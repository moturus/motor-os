# rust-analyzer for Motor OS development

2026-08-29. Investigation and staged plan for using the rust-analyzer snapshot
that is embedded in the Motor Rust source tree. The first stage runs
rust-analyzer on Linux while Cargo and rustc cross-compile for Motor OS. The
second stage runs rust-analyzer inside a Motor OS development VM.

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

| Stage | Server host | Analyzed targets | Planning status |
|---|---|---|---|
| 1. Host | Linux | Motor and Linux host | Detailed; ready to implement |
| 2. Guest | Motor OS | Motor only | Constraints and evidence |

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
- in Stage 1, also analyze the checkout's Linux host programs for
  `x86_64-unknown-linux-gnu` with the same keyed toolchain's host std;
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
- support custom JSON target specifications, including the kernel and loader
  targets, or any analyzed target other than `x86_64-unknown-motor` and, in
  Stage 1 only, `x86_64-unknown-linux-gnu`;
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

Rust-analyzer searches that `libexec` directory for the proc-macro server.
Stage 1 changes no file in the Rust tree: rust-analyzer is enabled through the
rendered bootstrap configuration, and the build-pipeline patch in section 3.9
also changes only rendered configuration and Motor OS scripts.

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
4. The same editor can load a Linux host Cargo project for
   `x86_64-unknown-linux-gnu`, resolve a definition in `std::os::linux`, and
   run a host check, again from the keyed toolchain rather than an ambient
   installation. Motor and Linux projects may be open in one session with
   different targets.
5. The Motor semantic fixture can be loaded from an inline
   `rust-project.json` object. This is the project-description seam reserved
   for the future native Lorry/editor integration.
6. The host smoke tests use no network and are included transitively in
   `src/tests/full-test.sh`.

Stage 1 does not claim that opening the repository root gives one accurate
crate graph for every component. The checkout contains Linux host programs,
ordinary Motor targets, and the custom JSON kernel/loader targets that are out
of scope here. Users must open or link Motor and Linux projects by build
context. A future repository-wide workspace discovery command may combine
those contexts, but silently assigning `x86_64-unknown-motor` to every crate
would be incorrect.

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
- set `RUST_ANALYZER_INTERNALS_DO_NOT_USE='this is unstable'`, the value
  rust-analyzer itself sends, when running
  `libexec/rust-analyzer-proc-macro-srv --version`; the pinned server only
  checks that the variable exists, but a later snapshot may check the value;
- retain the existing full `rustc -vV`, `cargo -Vv`, sysroot, and two-target
  compile probes;
- record both new version strings in `MOTOR-TOOLCHAIN-MANIFEST` as base64
  fields; and
- leave `MOTOR_GENERATED_MANIFEST_SCHEMA` unchanged: the toolchain key
  already changes, the prefix manifest is compared byte-for-byte against a
  fresh render that embeds that key, readers fetch fields by name, and the
  constant is shared with the assembly manifest and the assembly selector,
  where a bump would only add churn.

The source transaction, exact toolchain key, and clean-source re-verification
are the authority tying rust-analyzer to the selected Rust revision. The short
commit spelling in `rust-analyzer --version` is diagnostic evidence, not a
replacement for that identity chain and must not be hard-coded to a fixed
abbreviation length.

Both binaries print `<name> <CFG_RELEASE> (<abbrev> <date>)`, so the expected
outputs are `rust-analyzer 1.99.0-dev (...)` and
`rust-analyzer-proc-macro-srv 1.99.0-dev (...)`; the abbreviation comes from
`git log --format=%h` and is shorter than rustc's. Check the fixed prefix up
to the opening parenthesis and that the hash is a prefix of
`EFFECTIVE_MOTOR_RUST_REV`, nothing stricter. Both executables link
`librustc_driver` through a `$ORIGIN/../lib` runpath, so run them by absolute
path inside the prefix. Get these expectations right the first time: a
failure in `toolchain_validate_prefix` after `x.py install` marks the freshly
built prefix rejected, and rejected prefixes are never revalidated, so a wrong
expectation costs a complete rebuild.

Extend rustup-link validation to require:

```sh
rustup which rust-analyzer --toolchain "$MOTOR_RUSTUP_TOOLCHAIN"
```

and compare its canonical path with
`$TOOLCHAIN_PREFIX/bin/rust-analyzer`. The proc-macro server has no rustup
proxy; validate its canonical path directly below the same prefix.

Update the fake prefix and fake rustup implementations in:

- `src/tests/test-toolchain-prefix.sh`; and
- `src/tests/test-toolchain-host.sh`.

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

Sequencing, decided 2026-08-30: every toolchain re-key also re-keys the
assembly, and the checked-in selector is already unbuilt on the development
host, so land the bootstrap-selection/prefix-contract patch and the
build-pipeline patch of section 3.9 before running the next managed build.
One build then serves both; do not run a throwaway build of the current
selector first. Neither patch touches `x.py` or the Rust bootstrap sources.

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

For a Linux host program, leave `cargo.target` and `check.targets` unset: the
server then analyzes and checks `x86_64-unknown-linux-gnu` with the keyed
toolchain's host std and the same `rust-src`, under the same toolchain
selection rule. `cargo.target` is a workspace-scoped setting in the pinned
rust-analyzer, so a Motor workspace can carry it in a `rust-analyzer.toml` at
its root while a Linux workspace linked into the same session leaves it unset.

Build scripts and procedural macros execute project code on the Linux host.
They are acceptable for the trusted Motor OS checkout and explicit trusted
projects, but the documentation must call out that trust boundary. The
network-free smoke fixture below contains no external dependencies or build
script.

Custom JSON targets are out of scope. The kernel and loader crates
(`src/sys/kernel/kernel.json`, `src/boot/x64.kloader/kloader.json`) are not
supported by this plan, and no fixture, configuration, or documentation for
them is a deliverable of either stage. The reason was verified on 2026-08-30
with the installed prefix: the pinned Cargo rejects every `.json` target
invocation (`cargo metadata --filter-platform`, `cargo rustc --print cfg`,
`--print target-spec-json`) unless `-Zjson-target-spec` is passed, and bare
rustc rejects JSON targets without `-Zunstable-options`. The pinned
rust-analyzer adds `-Zjson-target-spec` to `cargo metadata` on its own and
forwards `-Z` flags from `cargo.extraArgs` to build-script runs, but its rustc
cfg and target-data queries take no extra arguments, so a JSON-target project
silently loads with an empty cfg set. Supporting these targets needs either a
Motor-fork rust-analyzer change or a project-description bridge that supplies
the cfgs, and belongs to a separate plan. Do not work around it with
`cargo.cfgs` or by substituting `x86_64-unknown-motor` for a kernel or loader
crate.

### 3.6 Reusable host LSP smoke test

Add a dependency-free fixture beneath `src/tests/` with:

- an ordinary Cargo library configured for `x86_64-unknown-motor`;
- a Motor-only source path that references
  `std::os::motor::rt_version` under `#![feature(motor_ext)]`;
- a `#[cfg(not(target_os = "motor"))]` failure sentinel;
- a small local procedural-macro crate for the host-only proc-macro check; and
- a separate Linux host library that references
  `std::os::linux::fs::MetadataExt` with a
  `#[cfg(not(target_os = "linux"))]` failure sentinel.

Use a small Rust host harness, not an editor extension. It is a Cargo package
beneath `src/tests/` that `src/tests/full-test.sh` builds and runs with the
keyed toolchain for the Linux host. `serde_json` is its only external
dependency; its use was explicitly approved on 2026-08-30 as a test-only
exception to the standard-Rust rule because a new JSON implementation or a
Python harness would be worse. It must not become a product or guest
dependency and must not carry its own JSON parser. Pin its direct version
exactly to the version in rust-analyzer's committed `Cargo.lock`, commit the
harness `Cargo.lock` with only package versions and checksums already selected
by that rust-analyzer lock, and build and run it with the keyed Cargo using
`--locked --offline`. The harness spawns the exact rust-analyzer with piped
stdin/stdout, drains stderr on its own thread into a bounded buffer, enforces
one deadline per case, and kills the server on timeout. It must not retry a
failed server. It implements only what the cases need:

- LSP framing in both directions and a dispatch loop that matches responses
  to pending requests, answers server-to-client requests
  (`window/workDoneProgress/create`, `client/registerCapability`) with `null`
  results, and records `textDocument/publishDiagnostics`, `$/progress`, and
  `experimental/serverStatus` notifications;
- client capabilities that declare `experimental.serverStatusNotification`,
  without which the server never reports quiescence, and that omit
  `workspace.configuration`;
- no `workspace/didChangeConfiguration` notification: it is the pinned
  server's only trigger for a `workspace/configuration` pull, so omitting it
  makes the initialization options the sole configuration source;
- `cargo.extraEnv = {"CARGO_NET_OFFLINE": "true"}` in every case's
  initialization options, so that a registry package missing from
  `CARGO_HOME` fails `cargo metadata` visibly instead of being downloaded.
  This reaches only the cargo processes spawned by the test's server; it is
  not part of the editor configuration in section 3.5 and does not affect
  `make` or a developer's own server; and
- fixed bounds on frame size, pending requests, retained diagnostics, and
  stderr retention.

Before inspecting diagnostics the harness waits for the quiescent report and
then for every expected flycheck `$/progress` token to reach `end`;
quiescence does not cover the check. Each single-workspace Cargo case expects
one begin/end pair. The mixed-workspace case below expects one for each
workspace and must not treat the first completed check as completion of the
second.

For Cargo project discovery, the harness must:

1. start rust-analyzer with the exact rustup toolchain and fixture working
   directory;
2. send `initialize` with the Motor target options above, followed by
   `initialized`;
3. wait for the server to report that project loading is quiescent;
4. open the fixture source;
5. request the definition of `std::os::motor::rt_version` and require a URI
   below the selected sysroot's `library/std/src/os/motor` directory;
6. request the definition of the `moto_rt::RT_VERSION` reference inside that
   `std::os::motor` source and require a URI below
   the selected sysroot's `library/vendor/moto-rt-<version>/`. The real
   Stage 1 prefix confirmed that bootstrap installs a vendored, reduced
   `rust-src`, consistent with `docs/toolchain.md`. The pinned server loads
   the sysroot through `cargo metadata` on `library/Cargo.toml` and, when
   that fails, silently keeps a `--no-deps` result or a stitched crate list;
   only the full load resolves `moto_rt`, so this step is what proves the
   sysroot loaded correctly and offline;
7. require no active non-Motor sentinel diagnostic;
8. prove that the local proc macro expands with `procMacro.server` unset, so
   the server discovered its own `libexec/rust-analyzer-proc-macro-srv`; the
   prefix validation in section 3.3 is what proves that file's identity; and
9. perform the LSP `shutdown`/`exit` sequence and require a clean child exit.

Run a second case for the Linux host fixture with `cargo.target` and
`check.targets` unset. Require the definition of
`std::os::linux::fs::MetadataExt` below the selected sysroot's
`library/std/src/os/linux` directory and no active non-Linux sentinel
diagnostic once the check has completed. The proc-macro and vendored-source
steps are not repeated; the Linux sysroot loads through the same path.

Run a third case using an inline `rust-project.json` object instead of Cargo
discovery. It should describe the same dependency-free Motor crate with:

- the selected `sysroot` and `sysroot_src` paths;
- an absolute normalized root module;
- edition, target, cfgs, environment, and source include/exclude roots; and
- admitted dependency indices and names (empty for this dependency-free
  fixture).

The inline case deliberately excludes proc macros and build-script output so
the same shape can later run in the guest. Set `cargo.target` to
`x86_64-unknown-motor` in its initialization options as well: real Stage 1
logs confirmed that the pinned server uses this workspace setting when it
loads even a project object's sysroot through Cargo; the crate's own `target`
field controls the described crate but does not select the sysroot metadata
platform. Require the same Motor std definition result. Keep its project-data
builder path-parameterized; do not embed Linux home-directory or toolchain-key
strings in a checked-in JSON file.

Run a fourth, multi-root case with the Motor and Linux Cargo fixtures as two
`workspaceFolders` in one rust-analyzer process. Do not set a global
`cargo.target` or `check.targets`. Put the Motor target and check target in a
`rust-analyzer.toml` at the Motor workspace root and leave both unset in the
Linux workspace. After both workspaces load and both checks complete, require
the Motor and Linux standard-library definition results and the absence of
both wrong-target sentinels. Only then perform one `shutdown`/`exit` sequence
and require a clean child exit. This case proves that workspace-scoped target
configuration works in one session rather than merely in two independent
server processes.

Add the smoke test to `src/tests/full-test.sh` directly or through a focused
host-toolchain test. It must not reach Cargo registries, Git repositories, or
any other network service. `--locked --offline` covers the harness build, and
the offline environment above turns any such need in a server child into a
visible failure. Its only external inputs are the keyed toolchain and the
registry cache under `CARGO_HOME`, which must already hold the
rust-analyzer `Cargo.lock` packages selected by the harness lock. The
installed `rust-src` vendors the library closure, so semantic sysroot loading
does not consult an ambient registry. The managed toolchain build on the same
host with the same `CARGO_HOME` (`src/build-motor-os.sh` uses
`${CARGO_HOME:-$HOME/.cargo}`, Cargo's own default) provides the harness
packages because it builds rust-analyzer.

### 3.7 Stage 1 patch sequence

Keep the implementation incremental:

1. **Bootstrap selection and prefix contract.** Add rust-analyzer to the
   exact tools declaration, validate the server and proc-macro server, extend
   the manifest and rustup checks, and update the bootstrap/key and
   fake-prefix tests. The tools-list change alone is a few lines and does not
   warrant its own patch.
2. **Build pipeline and identity.** The section 3.9 changes. Independent of
   patch 1 in content, but it must land before the same managed build.
3. **Real provision and selector cutover.** Build the managed prefix, inspect
   both binaries, update `rust-toolchain.toml`, and run the cutover tests.
   Runs only after patches 1 and 2 are in, so that one managed build serves
   all of them.
4. **LSP transport.** Add the harness package's bounded framing and dispatch
   logic, with in-memory tests for valid and malformed frames, frame and
   pending-request limits, response correlation, server requests, and the
   retained-notification bounds. It has no semantic fixtures yet.
5. **LSP process lifecycle.** Add child startup, concurrent bounded stderr
   draining, deadlines, timeout kill/reap, shutdown, and exit handling. Test
   it with a self-hosted fake-child mode of the test binary that can emit
   partial frames, fill stderr, exit cleanly, or hang. Split patches 4 and 5
   further if needed to keep each patch, including tests, near 100-300 lines.
6. **Host semantic smoke.** Add the Motor Cargo, Linux host, and
   inline-project fixtures and their four cases, including the mixed-target
   multi-root case, wired into
   `src/tests/full-test.sh`.
7. **User documentation.** Document editor-neutral launch/configuration and
   the mixed-target repository boundary.

Do not combine an unproven native build or Red changes with these patches.

### 3.8 Stage 1 tests and gates

Before accepting Stage 1:

- run the focused bootstrap, versions, llvm, prefix, host, state, assembly,
  and cutover shell tests;
- run the new host LSP smoke entirely offline, on the host that built the
  selected toolchain with the same `CARGO_HOME`;
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

### 3.9 Build-pipeline prerequisite: one host LLVM, non-incremental builds

Decided 2026-08-30 with the Stage 1 review. A clean managed rebuild takes
about 105 minutes on the development host, and roughly 71 of them compile the
same X86-only LLVM source four times: the standalone host clang (20.6 min),
rustc's host LLVM (20.9), the Motor-target LLVM inside the native rustc
bootstrap (12.3), and the guest clang driver (17.7). This patch removes the
second build and the incremental caches. It changes only
the Motor OS toolchain identity, bootstrap, prefix/assembly manifest, and LLVM
scripts, their tests, and documentation; no file under the Rust tree changes.

Rendered bootstrap configuration:

- `[rust] incremental = false`. The `library` profile sets it to true, so the
  value must be explicit. Clean builds get slightly faster and stop leaving
  multi-gigabyte incremental caches; incremental toolchain rebuilds are
  explicitly not a priority.
- `[target.x86_64-unknown-linux-gnu] llvm-config = "$llvm_bin/llvm-config"`.
  The pinned bootstrap then treats the host LLVM as prebuilt, links it
  statically by default, uses `llvm-config --cmakedir` with the
  `llvm-tblgen` beside it, and requires LLVM 21 or newer; the selected LLVM is
  23.1.0-rc1. The `$llvm_bin` location is already a placeholder in the
  configuration identity digest.

Standalone LLVM build:

- `LLVM_ENABLE_ASSERTIONS=OFF`. With the build shared, assertions would slow
  every host rustc codegen invocation by roughly five to ten percent against
  today's assertion-free rustc LLVM; upstream ships assertions only in
  nightly. Clang and everything it compiles also get faster. When someone
  needs an assertions-enabled toolchain to debug LLVM, authoring mode can
  build one under its own key.
- Build the existing tool list plus `llvm-libraries`, so that every static
  library `llvm-config --libs` may name actually exists. Rust bootstrap also
  requires all 14 of its `LLVM_TOOLS` while assembling intermediate sysroots,
  even though external LLVM makes the later component-install step skip them:
  `llvm-cov`, `llvm-nm`, `llvm-objcopy`, `llvm-objdump`, `llvm-profdata`,
  `llvm-readobj`, `llvm-size`, `llvm-strip`, `llvm-ar`, `llvm-as`, `llvm-dis`,
  `llvm-link`, `llc`, and `opt`. Keep this exact list in one checked-in array
  used by standalone build and validation.
- Replace the configuration digest schema with
  `motor-standalone-llvm-config-v2` carrying the assertion setting and the
  ninja target list, so an existing build directory cannot be reused without
  the added libraries. The new standalone key costs one additional
  twenty-minute LLVM build, paid once.

Identity decision, approved 2026-08-30:

- The normalized standalone LLVM configuration digest becomes an explicit
  `MOTOR_TOOLCHAIN_KEY` input because the external LLVM now determines the
  installed host rustc. Bump `MOTOR_TOOLCHAIN_KEY_SCHEMA` from v1 to v2 and
  add a named `standalone_llvm_config_digest` field to the required-field list
  and canonical serialization. The effective LLVM revision and tree state are
  already separate toolchain-key inputs, so do not hash the host build path or
  redundantly add the full standalone key.
- Derive the digest from the same single configuration authority that drives
  the CMake and Ninja commands, before deriving `MOTOR_TOOLCHAIN_KEY`. The
  clean-key path must compute it offline from checked-in data. Do not duplicate
  assertion, project, target, or Ninja-target lists between identity and
  execution.
- `MOTOR_ASSEMBLY_KEY` inherits this input through `MOTOR_TOOLCHAIN_KEY`; it
  does not need a second identity field. Record the digest in both the prefix
  and assembly manifests for diagnosis, and update `docs/toolchain.md`, whose
  current text incorrectly places the standalone configuration only at the
  assembly boundary. The shared generated-manifest schema remains unchanged
  under the compatibility rationale in section 3.3; this key-schema bump is a
  separate change.

Product consequences to record:

- The installed prefix loses the separate `llvm-tools` component because
  bootstrap skips that install step when the host LLVM is external. The 14
  tools above are nevertheless required for intermediate compiler assembly;
  leaving `rust.llvm-tools` at its default also preserves `rust-objcopy` in
  the rustc component.
- External `llvm-config` disables bootstrap's automatic self-contained LLD
  and bootstrap rejects `rust.lld = true` in this mode. A real image build
  proved that the MBR, bootloader, kernel loader, and kernel custom targets all
  name `rust-lld`. After `x.py install` and before validation, automatically
  copy the already-built standalone `lld` to the standard prefix path
  `lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld`. Require a regular
  executable byte-identical to standalone `lld`, record its digest in the
  prefix manifest, and include the staging recipe in bootstrap identity. Keep
  `gcc-ld` omitted because the repository does not use it. Do not patch Rust
  bootstrap or build a fourth LLVM.
- rustc's host LLVM takes the standalone configuration: clang and lld
  projects present, X86 only, tests off, assertions off.
- The Motor-target LLVM and the guest clang driver are unchanged:
  `llvm-config` must run on the build host, and a cross build's `llvm-config`
  is a Motor executable, so three LLVM builds are the floor.
- The native bootstrap's stage1 rework under the assembly configuration is a
  relink plus a std rebuild worth one to two minutes. The first real build
  exposed one additional cross-bootstrap constraint: upstream uses the
  runnable host `llvm-config` and substitutes host-triple paths with target
  paths, but the content-addressed standalone path contains no host triple.
  Generate an assembly-scoped Bash adapter that leaves `--bindir` pointing at
  runnable host tools and, only when Cargo's inherited `TARGET` is
  `x86_64-unknown-motor`, rewrites other standalone include/library paths to
  the built Motor LLVM tree. Host-target and target-less calls pass through
  unchanged. Keep the real `llvm-ar` and `llvm-ranlib` beside it as symlinks,
  use this bin directory only in the native bootstrap config, and record the
  adapter recipe in a v2 native-configuration digest. Do not patch Rust
  bootstrap or rebuild a fourth LLVM.

Tests and documentation:

- `src/tests/test-toolchain-bootstrap.sh` gains the host-target section and
  `llvm-config` key in its exact rendered-key list and asserts the exact
  external `llvm-config` path and `incremental = false`.
- `src/tests/test-toolchain-llvm.sh` moves to the v2 digest and keeps the reuse
  and re-key assertions. Its fake CMake and Ninja commands record their
  argument vectors so the test also requires `LLVM_ENABLE_ASSERTIONS=OFF` and
  the exact Ninja target list including `llvm-libraries` and all 14 bootstrap
  tools. Standalone validation requires every bootstrap tool and
  `llvm-config --link-static --libfiles` to exist, the command to succeed, and
  every named library to exist; the fake provides representative libraries,
  and a missing library is a negative test.
- `src/tests/test-toolchain-native.sh` requires the adapter in the native
  bootstrap config, unchanged host `--bindir`, pass-through host and
  target-less paths, Motor-only rewritten include/library paths, exact
  argument forwarding and failure status, and the adjacent host archive-tool
  links.
- The prefix and host tests require the staged `rust-lld`, reject a missing or
  changed copy, and require its digest in the prefix manifest. Standalone LLVM
  validation requires the source `lld` multicall binary as well as `ld.lld`.
- The versions/state tests prove that changing only the normalized standalone
  configuration digest changes both clean and dynamic toolchain keys without
  introducing host-path identity. The assembly test proves that this new
  toolchain key selects a new assembly key, and the cutover test continues to
  derive the checked-in selector entirely offline.
- `docs/toolchain.md` currently lists "the standalone LLVM build is not used
  as rustc's LLVM through `llvm-config`" among the design's exclusions and
  shows the identity-relevant bootstrap settings; both passages must be
  updated, and the component documentation must record the removed
  `llvm-tools`.
- `docs/build-motor-os.md` gains the clean-rebuild procedure: delete the
  keyed `toolchains`, `toolchain-state`, `assemblies`, and
  `build/toolchain/standalone-llvm` entries with any `.building` locks, plus
  `toolchain-src/rust/build`, then rerun the managed build. The standalone
  LLVM directory is a runtime input of every assembly whose sysroot wrappers
  point into it, so it is deleted only together with those assemblies.
  `toolchain-src/rust/build` is disposable after a successful build because
  assemblies copy the native rustc and LLVM images they need.

With this patch the expected clean rebuild is roughly 80 minutes. The
successful real-build validation on 2026-08-30 reused the sealed standalone
LLVM, so it is not a clean-build measurement: it completed in 49 minutes 14
seconds, including an 18-minute 11-second host `x.py install` with
rust-analyzer, a 7-minute 2-second native Rust bootstrap, and all three
release images. Earlier implementation discoveries required re-keying between
attempts, so there is not yet one successful end-to-end clean timing; retain
the roughly 80-minute estimate until the final clean gate measures it.

The same validation recorded both `rustc_llvm` paths from Cargo build-script
output. Linux-target builds linked from the sealed standalone LLVM `lib`
directory. The Motor-target stage-2 build invoked the assembly adapter and
linked from `build/x86_64-unknown-motor/llvm/lib`. The prefix's staged
`rust-lld` was byte-identical to standalone `lld` with SHA-256
`6dca91de3516a10e14c0c4dcfbb1ac36a20441990eeeeb90a6faf905b6d86d06`;
the MBR, bootloader, kernel loader, and kernel then linked successfully, and
the base, standard, and developer images were produced.

## 4. Stage 2: native Motor OS guest design

### 4.1 Design status and replanning point

Stage 2 will cross-build another rust-analyzer executable that runs inside the
development VM. It analyzes `x86_64-unknown-motor` only; there is no Linux
target in the guest. It remains required, but implementation must wait for
Stage 1 completion.

After Stage 1, update this section using:

- the exact installed rust-analyzer version, remembering that Stage 1's
  `in-rust-tree` build links `librustc_driver` dynamically while the native
  build must use the crates.io `ra-ap-rustc_*` closure of the same source, so
  the two dependency graphs differ;
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

- use the same in-tree rust-analyzer source selected for the host component,
  without the `in-rust-tree` feature;
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
validated. Stage 2 source changes, where needed, are to dependency crates and
to `src/tools/rust-analyzer`; the Rust bootstrap is never patched.

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
  path; the initial server takes reviewed settings from LSP initialization
  options only.
- **Child output:** rust-analyzer's concurrent stdout/stderr reader needs a
  Motor implementation on standard Rust threads with bounded messages that
  drains both pipes without polling, retrying, or holding one pipe until the
  other closes.
- **File URLs:** the selected `url` crate must support absolute Motor UTF-8
  paths without pretending Motor is Unix.
- **Salsa registration:** the selected `inventory` crate must emit Motor ELF
  constructors and the chosen startup path must execute them; the prototype's
  path is mlibc startup through `motor-rust-cc` (section 4.7, item 1).
- **CPU selection:** use `std::thread::available_parallelism()`; choose any
  worker cap only from the measurements in section 4.8.

### 4.5 Project bridge and editor direction

The guest image has no Cargo. Rust-analyzer supports non-Cargo build systems
through `rust-project.json`, `linkedProjects`, and workspace discovery:

- <https://rust-analyzer.github.io/book/non_cargo_based_projects.html>
- <https://rust-analyzer.github.io/book/configuration>

The first native project bridge is expected to expose Lorry's resolved
compilation plan as deterministic rust-analyzer project data. It reuses the
Stage 1 inline-project fixture and preserves, at minimum:

- sysroot and sysroot-source paths;
- crate roots, editions, targets, target kinds, and source boundaries;
- dependency indices and the names visible to rustc;
- selected features, cfgs, and compile-time environment;
- workspace membership; and
- build labels for later checks and runnables.

Paths are absolute, normalized UTF-8 paths within the admitted workspace,
verified dependency repository, or sysroot. Unsupported build-script output is
rejected explicitly rather than represented inaccurately, and crates built for
custom JSON targets stay out of scope. The exact Lorry command, refresh
protocol, proc-macro artifact policy, and flycheck JSON envelope wait until
Stage 1 proves the consumer side; porting Cargo is not the preferred first
solution.

Red remains the likely first native client. It needs a bounded LSP transport
with concurrent stdout/stderr draining, one serialized writer, request
correlation, UTF-16 position conversion, document synchronization, and a
unified terminal/LSP event loop in which only the editor's main thread mutates
buffers or terminal state.

### 4.6 Security and resource constraints

The Stage 2 implementation plan must retain these constraints:

- start the server only for an explicitly opened Rust workspace, with absolute
  tool paths, argument vectors rather than a shell, and an explicit minimal
  environment;
- initially disable build scripts, procedural macros, command execution,
  workspace edits, and server-side polling; declarative macros remain
  available;
- bound protocol frames, pending requests, diagnostics, completion items,
  stderr retention, and event queues;
- reject project paths outside admitted roots and validate server-returned
  file URIs before opening them;
- leave `workspace/executeCommand` and `workspace/applyEdit` unsupported until
  separately designed;
- keep server failure visible, with no automatic restart; and
- choose worker limits and any executable compression only from the
  measurements in section 4.8; startup decompression is not acceptable.

### 4.7 Decisions deferred to the Stage 2 review

Stage 2 implementation requires explicit review of:

1. **Constructor path:** the recommended `inventory` plus mlibc startup path,
   or a vetted Rust standard-library change that walks `.init_array` from
   pure-Rust `motor_start`. The latter affects every qualifying process and
   its startup latency, so it stays outside this design unless separately
   approved, and choosing it triggers the full repeated core test gate.
2. **Dependency source:** exact-revision Motor forks versus a reviewed vendor
   snapshot for native-only dependency changes.
3. **Project bridge:** the Lorry command/data boundary, refresh mechanism, and
   treatment of build-script-dependent graphs.
4. **Editor JSON:** approval of `serde`/`serde_json` for Red, or a reviewed
   standard-Rust JSON component with complete bounds and escaping behavior.
5. **User configuration:** no implicit path initially, and any later Motor
   filesystem convention.
6. **Procedural macros and checks:** procedural macros need compiler-produced
   dylibraries, so enabling them needs a separate dynamic-loading or
   static/IPC design; checks need the flycheck envelope from item 3.

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
- a real diagnostic plus definition/hover/completion result in Red, with
  correct UTF-16 handling for non-ASCII text;
- visible, bounded failure behavior; and
- recorded image growth, startup latency, resident and virtual memory, thread
  count, and first completion latency in the normal 1 GiB VM.

The Stage 1 semantic fixture and LSP harness should be extended for these guest
checks rather than replaced by an unrelated test protocol. The harness keeps
running on the Linux host and reaches the guest server through `ssh`, as
`src/tests/full-test.sh` reaches other guest programs; only the child command
changes.
