# rust-analyzer for Motor OS development

2026-08-29. Investigation and staged plan for using the rust-analyzer snapshot
that is embedded in the Motor Rust source tree. The first stage runs
rust-analyzer on Linux while Cargo and rustc cross-compile for Motor OS. The
second stage runs rust-analyzer inside a Motor OS development VM.

An earlier investigation on 2026-08-13 proved that a patched rust-analyzer can
compile, link, and complete an LSP lifecycle natively on Motor OS. Temporary
source copies and dependency patches under `/tmp` were used for that prototype;
none of them are repository state.

## 0. Staging decision

Both stages are required:

| Stage | Server host | Analyzed target | Planning status |
|---|---|---|---|
| 1. Host | Linux | Motor OS | Detailed and ready for implementation |
| 2. Guest | Motor OS | Motor OS | Design constraints and prototype evidence |

Stage 1 comes first because it is useful immediately and exercises the same
rust-analyzer source, Motor rustc, Motor standard-library sources, target cfgs,
project descriptions, and LSP behavior that Stage 2 will need. It must leave
clean interfaces for Stage 2 rather than treating the Linux executable as the
only product.

Stage 2 is deliberately not a patch-by-patch implementation plan yet. The
native prototype identifies the important constraints, but Stage 1 will give us
the first maintained rust-analyzer build, repeatable semantic fixtures, and
project-loading evidence against the exact selected toolchain. Planning the
guest port in implementation detail after that evidence exists will be more
accurate and will avoid duplicating or prematurely freezing interfaces.

Reviewers should therefore treat the lower level of Stage 2 detail as an
intentional sequencing decision, not as missing work. Before Stage 2
implementation begins, this document must be updated with a reviewed patch
series based on the completed Stage 1 artifacts and measurements.

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
- keep generated artifacts in exact key-qualified locations;
- keep normal tests offline and deterministic;
- introduce no boot-time work;
- use editor-neutral LSP and `rust-project.json` contracts so the Linux test
  fixtures can be reused by a native editor and Lorry later;
- keep each implementation patch near 100-300 lines including tests; and
- introduce no compiler or Clippy warnings and format Rust changes with the
  repository-selected toolchain.

The initial effort will not:

- make the repository root one homogeneous Rust workspace or assign one target
  to Linux host tools, Motor userspace, the kernel, and the loader;
- port Cargo to Motor OS;
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

The generated bootstrap configuration already has `extended = true` and
installs rustc, rustdoc, Cargo, host and Motor std, Clippy, rustfmt, and
`rust-src`. Its `tools` list currently omits rust-analyzer.

The selected Rust bootstrap already has first-class steps for both host
components needed here:

- `rust-analyzer`, built as a host `ToolRustcPrivate` tool with the
  `in-rust-tree` feature; and
- `rust-analyzer-proc-macro-srv`, built when rust-analyzer is enabled and
  installed below the compiler sysroot's `libexec` directory.

Rust-analyzer searches that `libexec` directory for the proc-macro server. No
Rust fork change is expected for the Stage 1 build itself.

After the host prefix has been completed and linked through rustup, the
pipeline builds the assembly, including native LLVM, mlibc, and a Stage 2 rustc
whose host is `x86_64-unknown-motor`. That later native-compiler bootstrap is
why the two rust-analyzer builds must remain separate.

## 3. Stage 1: Linux host, Motor target

### 3.1 Deliverables and acceptance boundary

Stage 1 is complete when:

1. `src/build-motor-os.sh` builds or reuses a key-qualified Linux
   rust-analyzer and its matching proc-macro server in the host prefix.
2. Bare `rust-analyzer` from the Motor OS checkout resolves through rustup to
   that exact prefix.
3. A Linux editor can load a Cargo project for
   `x86_64-unknown-motor`, resolve a definition in `std::os::motor`, and run a
   target-correct check without using an ambient Rust installation.
4. A minimal custom JSON target carrying the kernel target's Motor and
   soft-float properties is loaded with Motor cfgs in an isolated fixture.
5. The same semantic fixture can be loaded from an inline
   `rust-project.json` object. This is the project-description seam reserved
   for the future native Lorry/editor integration.
6. The host smoke tests use no network and are included transitively in
   `src/tests/full-test.sh`.

Stage 1 does not claim that opening the repository root gives one accurate
crate graph for every component. The checkout contains Linux host programs,
ordinary Motor targets, and custom JSON kernel/loader targets. Users must open
or link projects by build context. A future repository-wide workspace
discovery command may combine those contexts, but silently assigning
`x86_64-unknown-motor` to every crate would be incorrect.

### 3.2 Enable rust-analyzer in the host bootstrap

Update both identity declarations of the bootstrap tool list:

```text
src/toolchain-bootstrap.sh
  tools = ["cargo", "clippy", "rust-analyzer", "rustdoc", "rustfmt", "src"]

src/toolchain-versions.sh
  MOTOR_BUILD_TOOLS="cargo,clippy,rust-analyzer,rustdoc,rustfmt,src"
```

Do not add a second `x.py` command and do not run rust-analyzer's
`cargo xtask install`. The existing `x.py install --stage 2` invocation must
produce all host components together. This preserves bootstrap's installer
layout, uses the in-tree features, builds the matching proc-macro server, and
keeps the result inside the immutable keyed prefix rather than
`$HOME/.cargo/bin`.

The changed tool list and rendered bootstrap configuration already participate
in `MOTOR_TOOLCHAIN_KEY`. The change must therefore select a new prefix. It
must not add files to or relax validation of the currently completed prefix.

The rust-analyzer workspace has its own committed `Cargo.lock` inside the exact
Rust source tree. Its contents are selected by the effective Rust commit or
authoring tree digest. Managed-source verification must remain clean after
bootstrap. A lockfile rewrite or other source mutation rejects the new prefix;
the build must not run `cargo update` or accept an unreviewed resolution.

### 3.3 Validate and record the installed components

Extend `src/toolchain-prefix.sh` so a prefix is incomplete unless it contains:

```text
bin/rust-analyzer
libexec/rust-analyzer-proc-macro-srv
```

Validation must:

- require both files to be regular executable files;
- run `rust-analyzer --version` and require the selected Rust release family;
- set `RUST_ANALYZER_INTERNALS_DO_NOT_USE=1` when running
  `libexec/rust-analyzer-proc-macro-srv --version`;
- retain the existing full `rustc -vV`, `cargo -Vv`, sysroot, and two-target
  compile probes;
- record both new version strings in `MOTOR-TOOLCHAIN-MANIFEST` as base64
  fields; and
- bump `MOTOR_GENERATED_MANIFEST_SCHEMA` because the two components become
  required manifest content.

The source transaction, exact toolchain key, and clean-source re-verification
are the authority tying rust-analyzer to the selected Rust revision. The short
commit spelling in `rust-analyzer --version` is diagnostic evidence, not a
replacement for that identity chain and must not be hard-coded to a fixed
abbreviation length.

Extend rustup-link validation to require:

```sh
rustup which rust-analyzer --toolchain "$MOTOR_RUSTUP_TOOLCHAIN"
```

and compare its canonical path with
`$TOOLCHAIN_PREFIX/bin/rust-analyzer`. The proc-macro server has no rustup
proxy; validate its canonical path directly below the same prefix.

Update the fake prefix and fake rustup implementations in:

- `src/tests/test-toolchain-prefix.sh`;
- `src/tests/test-toolchain-host.sh`; and
- any manifest-schema fixtures affected by the new required fields.

Add negative assertions that a missing rust-analyzer, missing proc-macro
server, wrong rustup resolution, or stale manifest is rejected. Update
`src/tests/test-toolchain-bootstrap.sh` to require the exact new tools array and
`src/tests/test-toolchain-versions.sh` to retain deterministic re-keying.

### 3.4 Provision and select the new immutable prefix

Run the managed build through the public entry point; do not invoke bootstrap
manually:

```sh
src/build-motor-os.sh --source-mode managed
```

After the new prefix validates and rustup links it, update
`rust-toolchain.toml` to the exact value returned by `toolchain_clean_name`.
Do not guess or truncate the key. `src/tests/test-toolchain-cutover.sh` must
continue to prove that the checked-in selector, computed clean tuple, key
stamp, rustc, Cargo, and rustup paths all agree.

Document rust-analyzer with the other host components in:

- `docs/build-motor-os.md`;
- `docs/build-rustc.md`;
- `docs/toolchain.md`; and
- the `src/build-motor-os.sh --help` component summary.

The documentation must distinguish the Linux executable from the later native
one. Installing Stage 1 must not change either VM image.

### 3.5 Editor-neutral Motor target configuration

The repository should document LSP initialization options instead of adding a
VS Code-, Vim-, or editor-specific settings file. For an ordinary trusted
Motor userspace Cargo project, the semantic configuration is:

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

`targetDir = true` gives rust-analyzer a separate Cargo artifact directory so
editor checks do not contend with ordinary command-line builds. The root
`rust-toolchain.toml` or an explicit `RUSTUP_TOOLCHAIN` must select the Motor
toolchain before the server starts. Editors that bundle their own server must
be pointed explicitly at the rustup proxy or the exact prefix binary; merely
opening the checkout does not force an editor to discard a bundled server.

Build scripts and procedural macros execute project code on the Linux host.
They are acceptable for the trusted Motor OS checkout and explicit trusted
projects, but the documentation must call out that trust boundary. The
network-free smoke fixture below contains no external dependencies or build
script.

For a custom JSON target, start a separate project context and set `cargo.target`
and `check.targets` to the absolute JSON file. Do not apply the kernel's
soft-float target to the entire `src/sys` workspace. The pinned rust-analyzer
already recognizes `.json` targets while obtaining Cargo metadata. The Stage 1
test must also prove that its rustc cfg and target-data queries work with the
current requirement for unstable JSON target specifications. If they do not,
stop and diagnose the pinned rust-analyzer integration; do not substitute
`x86_64-unknown-motor`, inject cfgs by hand, or ignore the failed query.

### 3.6 Reusable host LSP smoke test

Add a dependency-free fixture beneath `src/tests/` with:

- an ordinary Cargo library configured for `x86_64-unknown-motor`;
- a Motor-only source path that references
  `std::os::motor::rt_version` under `#![feature(motor_ext)]`;
- a `#[cfg(not(target_os = "motor"))]` failure sentinel;
- a small local procedural-macro crate for the host-only proc-macro check; and
- an isolated `#![no_std]` crate plus a copied/minimal custom JSON target with
  `os = "motor"` for target-query coverage.

Use a small standard-Rust host harness, not an editor extension or an external
JSON program. It should spawn the exact rust-analyzer, implement only the LSP
framing and response inspection needed by the test, and keep fixed bounds on
frame size, pending requests, stderr capture, and total execution time. It must
not retry a failed server.

For Cargo project discovery, the harness must:

1. start rust-analyzer with the exact rustup toolchain and fixture working
   directory;
2. send `initialize` with the Motor target options above, followed by
   `initialized`;
3. wait for the server to report that project loading is quiescent;
4. open the fixture source;
5. request the definition of `std::os::motor::rt_version` and require a URI
   below the selected sysroot's `library/std/src/os/motor` directory;
6. require no active non-Motor sentinel diagnostic;
7. prove that the local proc macro expands using the proc-macro server from the
   selected sysroot; and
8. perform the LSP `shutdown`/`exit` sequence and require a clean child exit.

Run a second project-load case for the custom JSON target and require
`target_os = "motor"` behavior without running or linking the target binary.

Run a third case using an inline `rust-project.json` object instead of Cargo
discovery. It should describe the same dependency-free Motor crate with:

- the selected `sysroot` and `sysroot_src` paths;
- an absolute normalized root module;
- edition, target, cfgs, environment, and source include/exclude roots; and
- admitted dependency indices and names (empty for this dependency-free
  fixture).

The inline case deliberately excludes proc macros and build-script output so
the same shape can later run in the guest. Require the same Motor std
definition result. Keep its project-data builder path-parameterized; do not
embed Linux home-directory or toolchain-key strings in a checked-in JSON file.

Add the smoke test to `src/tests/full-test.sh` directly or through a focused
host-toolchain test. It must run with prepared local sources and must not reach
Cargo registries, Git repositories, or any other network service.

### 3.7 Stage 1 patch sequence

Keep the implementation incremental:

1. **Bootstrap selection.** Add rust-analyzer to the exact tools declaration,
   update the bootstrap/key tests, and document the expected key change.
2. **Prefix contract.** Validate the server and proc-macro server, extend the
   manifest and rustup checks, and update fake-prefix tests.
3. **Real provision and selector cutover.** Build the managed prefix, inspect
   both binaries, update `rust-toolchain.toml`, and run the cutover tests.
4. **Host semantic smoke.** Add the Cargo, custom-target, and inline-project
   fixtures plus the bounded LSP harness.
5. **User documentation.** Document editor-neutral launch/configuration and
   the mixed-target repository boundary.

Do not combine an unproven native build or Red changes with these patches.

### 3.8 Stage 1 tests and gates

Before accepting Stage 1:

- run the focused bootstrap, versions, prefix, host, state, and cutover shell
  tests;
- run the new host LSP smoke entirely offline;
- run `src/build-motor-os.sh --source-mode managed` to prove the real in-tree
  rust-analyzer workspace builds through bootstrap;
- confirm both new installed files resolve inside the new prefix;
- run `src/tests/full-test.sh` in debug and release modes; and
- run the non-Lorry developer-image gate only in release mode with
  `src/tests/full-test-dev.sh --release`.

This stage does not change `src/sys`, the Motor Rust standard library, or
`moto-rt`, so the three-debug/three-release core repetition requirement does
not apply. If implementation discovers that one of those core components must
change, stop and obtain review before expanding the scope.

## 4. Stage 2: native Motor OS guest design

### 4.1 Design status and replanning point

Stage 2 will cross-build another rust-analyzer executable that runs inside the
development VM. It remains required, but implementation must wait for Stage 1
completion.

After Stage 1, update this section using:

- the exact installed rust-analyzer version and dependency graph;
- the maintained Cargo and inline-project semantic fixtures;
- observed sysroot and custom-target behavior;
- the reusable bounded LSP test harness;
- host startup, memory, thread-count, and first-analysis measurements; and
- any source changes that were actually needed for Stage 1.

At that point, produce a reviewed 100-300-line patch series for dependency
ports, native build/staging, project generation, and editor integration. The
design below preserves the constraints that Stage 1 must not foreclose; it is
not authorization to begin those patches now.

### 4.2 Native prototype evidence

The 2026-08-13 prototype used the in-tree rust-analyzer snapshot and the final
Stage 2 Motor compiler.

After temporary compatibility changes for `dirs`, rust-analyzer's child-pipe
reader, and `url`, this cross-check completed:

```sh
RUSTC="$RUST/build/$HOST/stage2/bin/rustc" \
  cargo check --locked --offline \
  --manifest-path "$RUST/src/tools/rust-analyzer/Cargo.toml" \
  --target x86_64-unknown-motor -p rust-analyzer
```

A pure-Rust-linked executable was approximately 28 MiB stripped and answered
`--version` and LSP `initialize`, but then failed because Salsa's `inventory`
registrations were absent. `inventory 0.3.24` did not emit Motor OS ELF
constructors, and pure-Rust `motor_start` did not walk `.init_array`.

After temporarily classifying Motor as an ELF `.init_array` platform and
linking through `motor-rust-cc`, the resulting static PIE was approximately
29 MiB stripped with a nonempty `.init_array`. In a 1 GiB, four-vCPU VM it:

1. ran `--version`;
2. answered LSP `initialize`;
3. loaded an inline project for a staged Rust file;
4. reported `health=ok, quiescent=true`;
5. answered `shutdown`; and
6. exited cleanly after `exit`.

This proves native process, thread, pipe, file-URL, Salsa database,
project-load, and JSON-RPC lifecycle feasibility. It did not prove complete
Motor project analysis, production dependency pinning, editor integration, or
acceptable resource use.

### 4.3 Native build and image boundary

The likely native build remains:

- use the same in-tree rust-analyzer source selected for the host component;
- use host Cargo from the installed keyed toolchain;
- compile with the final Stage 2 `x86_64-unknown-motor` rustc;
- link through the assembly's `motor-rust-cc` wrapper;
- use the rust-analyzer workspace lockfile with explicit, reviewed dependency
  acquisition and offline normal tests;
- keep Cargo output outside the image root;
- strip with the assembly's LLVM tools; and
- mechanically reject an executable that is not a static PIE, has a dynamic
  `NEEDED` entry, has an executable stack, lacks `.init_array`, or retains
  undefined symbols.

Do not invoke `x.py` after the final native compiler/sysroot build. Rust
bootstrap can recreate a Stage 2 sysroot at the start of a later invocation.
The native rust-analyzer should instead be built directly with Cargo after the
final Stage 2 compiler and both required standard libraries have been
validated.

Stage only into a dev-specific root such as:

```text
$MOTORH/assemblies/<assembly-key>/images/rust-analyzer/
  devtools/rust/bin/rust-analyzer
  devtools/rust/lib/rustlib/src/rust/library/...
```

Only `src/imager/motor-os-dev.yaml` should consume this root. The main image
must contain neither rust-analyzer nor the added rust-src overlay. The server
must start on demand from an editor, never during boot.

### 4.4 Portability areas to revalidate

The prototype found the following likely native work. Revalidate each item
against the exact source left by Stage 1 before designing patches:

- **Configuration directory:** Motor has no approved implicit user config
  path for rust-analyzer. The initial server should accept no user config and
  receive reviewed settings in LSP initialization options.
- **Child output:** rust-analyzer's concurrent stdout/stderr reader needs a
  Motor implementation using standard Rust threads and bounded messages. It
  must drain both pipes without polling, retrying, or buffering one pipe until
  the other closes.
- **File URLs:** the selected `url` crate must support absolute Motor UTF-8
  paths without pretending Motor is Unix.
- **Salsa registration:** the selected `inventory` crate must emit Motor ELF
  constructors, and the chosen startup path must execute them. The prototype's
  recommended path is mlibc startup through `motor-rust-cc`.
- **CPU selection:** use `std::thread::available_parallelism()` for Motor's
  logical CPU count and measure memory before choosing any cap.

The alternative to mlibc startup is a vetted Rust standard-library change that
walks `.init_array` from pure-Rust `motor_start`. That affects all qualifying
processes and startup latency, so it remains outside this design unless
separately approved. Choosing it would trigger the full repeated core test
gate.

### 4.5 Project and editor direction

The guest image currently has no Cargo. Rust-analyzer supports non-Cargo build
systems through `rust-project.json`, `linkedProjects`, and workspace discovery:

- <https://rust-analyzer.github.io/book/non_cargo_based_projects.html>
- <https://rust-analyzer.github.io/book/configuration>

The first native project bridge is expected to expose Lorry's resolved
compilation plan as deterministic rust-analyzer project data. It should reuse
the Stage 1 inline-project fixture and preserve, at minimum:

- sysroot and sysroot-source paths;
- crate roots, editions, targets, target kinds, and source boundaries;
- dependency indices and the names visible to rustc;
- selected features, cfgs, and compile-time environment;
- workspace membership; and
- build labels for later checks and runnables.

Paths must be absolute, normalized UTF-8 paths within the admitted workspace,
verified dependency repository, or sysroot. Unsupported build-script output
must be rejected explicitly rather than represented inaccurately.

The exact Lorry command, refresh protocol, proc-macro artifact policy, and
flycheck JSON envelope are intentionally deferred until Stage 1 proves the
consumer side. Porting Cargo is not the preferred first solution.

Red remains the likely first native client. Its eventual integration needs a
bounded LSP transport, concurrent stdout/stderr draining, one serialized
writer, request correlation, UTF-16 position conversion, document
synchronization, and a unified terminal/LSP event loop. Only the editor's main
thread may mutate buffers or terminal state. Server failure must remain
visible and must not trigger an automatic restart.

The initial native configuration should disable build scripts, procedural
macros, command execution, workspace edits, and server-side polling. Declarative
macros remain available. Procedural macros require loading compiler-produced
dylibraries and therefore need a separate dynamic-loading or static/IPC design.

### 4.6 Security and resource constraints

The Stage 2 implementation plan must retain these constraints:

- start the server only for an explicitly opened Rust workspace;
- execute programs with argument vectors, never through a shell;
- use absolute tool paths and an explicit minimal environment;
- bound protocol frames, pending requests, diagnostics, completion items,
  stderr retention, and event queues;
- reject project paths outside admitted roots;
- validate server-returned file URIs before opening them;
- leave `workspace/executeCommand` and `workspace/applyEdit` unsupported until
  separately designed; and
- measure image growth, startup latency, resident and virtual memory, thread
  count, and first completion latency in the normal 1 GiB VM.

Do not compress the server in a way that adds startup decompression, and do not
guess worker limits before measuring the completed Stage 1 and native builds.

### 4.7 Decisions deferred to the Stage 2 review

Stage 2 implementation requires explicit review of:

1. **Constructor path:** the recommended `inventory` plus mlibc startup path,
   or a separately vetted Rust startup change.
2. **Dependency source:** exact-revision Motor forks versus a reviewed vendor
   snapshot for native-only dependency changes.
3. **Project bridge:** the Lorry command/data boundary, refresh mechanism, and
   treatment of build-script-dependent graphs.
4. **Editor JSON:** approval of `serde`/`serde_json` for Red, or a reviewed
   standard-Rust JSON component with complete bounds and escaping behavior.
5. **User configuration:** no implicit path initially, and any later Motor
   filesystem convention.
6. **Procedural macros and checks:** the initial disabled behavior and the
   separate designs required to enable them safely.

These are not blockers for Stage 1. They are explicit replanning inputs for
Stage 2 and must not be decided implicitly by host-only implementation choices.

### 4.8 Stage 2 acceptance direction

The later detailed plan should culminate in:

- a reproducible assembly-keyed native rust-analyzer and rust-src overlay;
- offline cross-check and mechanical ELF validation;
- native `--version`, initialize, inline/linked project load, quiescent,
  shutdown, and clean-exit tests;
- a deterministic Lorry project graph proven equivalent on Linux and Motor for
  supported fixtures;
- a real diagnostic plus definition/hover/completion result in Red;
- correct UTF-16 handling for non-ASCII text;
- visible, bounded failure behavior; and
- recorded resource and dev-image-size measurements.

The Stage 1 semantic fixture and LSP harness should be extended for these guest
checks rather than replaced by an unrelated test protocol.
