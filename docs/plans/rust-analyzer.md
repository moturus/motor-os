# Native rust-analyzer on Motor OS

2026-08-13. Investigation and design for building rust-analyzer as a native
Motor OS development tool and integrating it with native editors, initially
Red. This document is for review before implementation. No Motor OS source was
changed during the investigation.

The investigation used the rust-analyzer source embedded in the sibling Motor
Rust checkout (`rust/src/tools/rust-analyzer`) and the Stage 2 compiler produced
by `src/build-motor-os.sh`. Temporary source copies and dependency patches under
`/tmp` were used to prove compilation, linking, and native execution. None of
those experimental changes belong to the repository.

## 0. Decision summary

The port is feasible without changing `src/sys`, `moto-rt`, or the Motor Rust
standard library.

The recommended design is:

1. Build rust-analyzer directly with host Cargo and the final Stage 2 Motor
   rustc. Do not invoke `x.py` again after the final combined library/clippy
   build.
2. Link rust-analyzer through the existing `motor-rust-cc` wrapper. Patch the
   `inventory` crate to place Motor constructors in ELF `.init_array`; mlibc's
   existing startup runs them. This is necessary for Salsa's ingredient
   registration.
3. Keep rust-analyzer and Rust library sources out of the main image. Stage
   them in a new dev-only generated image root consumed only by
   `motor-os-dev.yaml`.
4. Add four required compatibility changes: rust-analyzer configuration paths,
   rust-analyzer's dual-pipe reader, `url` file paths, and `inventory` ELF
   constructors. Replace rust-analyzer's `num_cpus` calls on Motor as a fifth,
   performance-only change.
5. Do not port Cargo as a prerequisite. Extend Lorry to emit a
   `rust-project.json` crate graph and have Red pass it to rust-analyzer as a
   linked project. Add a Lorry flycheck/JSON-diagnostic interface later.
6. Disable procedural macros initially. The normal rust-analyzer proc-macro
   server loads dylibraries, while the Motor toolchain deliberately has no
   dynamic loading.
7. Give Red an asynchronous, bounded JSON-RPC transport and merge terminal and
   LSP events into one editor event loop. Deliver diagnostics first, followed
   by navigation and completion in separate patches.

Two choices require review before implementation:

- Approve the recommended mlibc-backed constructor path, or instead authorize
  a vetted Rust stdlib change that runs `.init_array` from pure-Rust
  `motor_start`.
- Approve `serde_json` for Red, or require a standard-Rust-only JSON solution.
  The repository's default policy does not allow adding it implicitly.

## 1. Goals

- Build a rust-analyzer executable that runs natively on
  `x86_64-unknown-motor`.
- Put the executable and the matching Rust standard-library sources in the dev
  image without increasing main-image size or boot work.
- Let a native editor start and stop rust-analyzer over standard LSP pipes.
- Give rust-analyzer an accurate Lorry workspace crate graph without requiring
  Cargo on the image.
- Support correct incremental document synchronization, UTF-16 LSP positions,
  diagnostics, hover, definition navigation, and completion.
- Keep all normal and test operation offline. No test may contact crates.io,
  GitHub, or another Internet service.
- Keep each implementation patch near 100-300 lines including its tests.
- Introduce no compiler or Clippy warnings and format Rust changes with
  `cargo fmt`.

## 2. Non-goals

The initial series does not:

- port Cargo to Motor OS;
- add dynamic linking or general ELF constructor support to the pure-Rust Motor
  process runtime;
- support procedural-macro dylibraries;
- implement every LSP capability rust-analyzer advertises;
- make Red a general plugin host;
- run rust-analyzer during boot;
- add a server-side polling filesystem watcher;
- conceal startup, protocol, or analysis failures with retries, longer
  timeouts, ignored failures, or automatic restarts.

## 3. Existing build and image pipeline

`src/build-motor-os.sh` defines:

```text
HOST=x86_64-unknown-linux-gnu
TARGET=x86_64-unknown-motor
LLVM_IMG=$MOTORH/assemblies/<assembly-key>/images/llvm
RUSTC_IMG=$MOTORH/assemblies/<assembly-key>/images/rustc
```

The relevant pipeline is:

1. Build host cross LLVM/Clang and the Motor mlibc/libc++ sysroot.
2. Build native Motor LLVM/Clang/lld as a static multicall executable.
3. Build a Stage 2 rustc with `--host x86_64-unknown-motor` and
   `--target x86_64-unknown-motor`.
4. In one final `x.py` invocation, build Clippy and the standard libraries for
   both Motor and Linux.
5. Stage stripped rustc plus Motor `.rlib`, `.rmeta`, and self-contained
   runtime files into `$MOTORH/assemblies/<assembly-key>/images/rustc`.

The single final `x.py` invocation is load-bearing. Rust bootstrap removes the
whole Stage 2 sysroot at the start of later sysroot builds. A separate
`x.py build rust-analyzer` after `build_stds()` could therefore erase the
compiler or libraries just produced. Rust-analyzer must be built directly with
Cargo after the final Stage 2 sysroot has been verified.

The generated Rust image currently contains rustc, target libraries, and a
small `hello.rs`; it contains neither Cargo nor the Rust library source tree.
Both `motor-os.yaml` and `motor-os-dev.yaml` consume the generated Rust root, so
dev-only files must not be added there.

`src/build-motor-os.sh` currently checks that the generated LLVM and Rust roots
exist and then invokes `make dev.img BUILD=release`. It is the natural entry
point for building or verifying a native rust-analyzer and staging a new
dev-only root.

## 4. Prototype evidence

The following was verified on 2026-08-13 against the checked-out Motor Rust
branch and its in-tree rust-analyzer snapshot.

### 4.1 Cross-check

Using the final Stage 2 rustc, the unmodified rust-analyzer dependency graph
first failed in `dirs 6.0.0`: Motor is neither `cfg(unix)` nor Redox, so
`dirs-sys` did not export functions that `dirs` called.

After temporary compatibility changes for `dirs`, rust-analyzer's process
reader, and `url`, this command shape completed successfully:

```sh
RUSTC="$RUST/build/$HOST/stage2/bin/rustc" \
  cargo check --locked --offline \
  --manifest-path "$RUST/src/tools/rust-analyzer/Cargo.toml" \
  --target x86_64-unknown-motor -p rust-analyzer
```

This establishes that no new `moto-rt` or Rust stdlib API is required merely
to compile the dependency graph.

### 4.2 Pure-Rust link and runtime failure

Linking through `motor-clang` produced a static PIE. The stripped executable
was approximately 28 MiB and ran `rust-analyzer --version` successfully in a
Motor VM.

An LSP `initialize` request also received a complete capability response, but
the server panicked after `initialized`:

```text
ingredient `salsa::input::JarImpl<base_db::AllCrates>` was not registered
```

The identical source revision and crate graph reached
`health=ok, quiescent=true` when built for Linux, proving this was
Motor-specific rather than a bad LSP fixture.

The cause is static registration. Rust-analyzer enables Salsa's `inventory`
feature. `inventory 0.3.24` does not include `target_os="motor"` in its ELF
constructor cfg, so the Motor binary had no `.init_array`. The Linux binary
had a populated `.init_array`. Even if `inventory` emitted that section, the
pure-Rust Motor `motor_start` path currently initializes `moto-rt` and calls
`main` without walking ELF constructors.

### 4.3 Constructor-enabled mlibc link

A temporary `inventory` patch classified Motor as an ELF `.init_array`
platform, and rust-analyzer was relinked with `motor-rust-cc`. That wrapper is
already used for native rustc and deliberately selects mlibc's `crt1.o`, whose
startup initializes the C runtime and executes `.init_array`.

The resulting binary was:

- an x86-64 static PIE with no dynamic library dependency;
- approximately 41 MiB before stripping and 29 MiB after stripping;
- equipped with a 1,360-byte `.init_array` in the tested revision.

In a disposable 1 GiB, four-vCPU Motor VM it:

1. ran `--version`;
2. answered LSP `initialize`;
3. loaded an inline `rust-project` crate graph for the staged `hello.rs`;
4. reported `health=ok, quiescent=true`;
5. answered `shutdown` with `result: null`; and
6. exited cleanly after the LSP `exit` notification.

The first run warned that it could not find `rustc` because the old SSH
environment did not expose the Rust toolchain. The development image now puts
the `/devtools/bin/rustc` launcher on `PATH`; an editor should still set
`RUSTC=/devtools/bin/rustc` explicitly so its compiler identity is closed.

This prototype proves native process, thread, pipe, URL/path, Salsa database,
project-load, and JSON-RPC lifecycle viability. It did not attempt a complete
Motor source-tree analysis, because the image lacks Rust library sources and a
Lorry-generated crate graph.

## 5. Required portability changes

### 5.1 rust-analyzer: configuration directory

Current rust-analyzer calls `dirs::config_dir()` in
`Config::user_config_dir_path`. `dirs` itself does not compile for Motor, and
pretending that Motor is Unix would be incorrect.

Make `dirs` a non-Motor dependency. On Motor, return `None` for the user config
directory during the first port. Red will supply reviewed settings through
LSP `initializationOptions`. A persistent per-user Motor configuration
location can be added later after its filesystem convention is explicitly
chosen.

Tests:

- Motor cross-check no longer builds `dirs` or `dirs-sys` for the target.
- Host configuration-path tests remain unchanged.
- A target-independent test verifies that no user config directory is a valid
  state.

### 5.2 rust-analyzer `stdx`: concurrent child-pipe draining

`crates/stdx/src/process.rs` defines its `read2` implementation only for Unix,
Windows, and wasm. Rust-analyzer uses it for Cargo/rustc subprocess output.
Reading one pipe completely before the other can deadlock if the unattended
pipe fills.

Add a Motor implementation using only `std`:

- one scoped reader thread per pipe;
- bounded messages containing stream identity, bytes, EOF, or error;
- one receiving thread that preserves the existing callback contract;
- incremental line delivery rather than buffering until child exit;
- deterministic propagation of the first I/O failure after both reader
  threads have been joined.

Do not add polling, a retry, or a timeout. The operation completes at EOF or
returns the underlying error.

Tests should cover interleaved output larger than a pipe buffer, partial lines,
one stream closing early, and an error path.

### 5.3 `url`: Motor file URLs

`url 2.5.8` gates `from_file_path`, `from_directory_path`, and `to_file_path`
behind a fixed list of operating systems. Rust-analyzer uses those functions
throughout its LSP path conversion, producing approximately 35 compile errors
when they are absent.

Patch `url` to include `target_os="motor"` and use the UTF-8 path branch. This
matches Motor's UTF-8 `OsStr` implementation and does not give Motor Unix path
or filesystem semantics.

Tests should round-trip absolute Motor-style paths, spaces, non-ASCII UTF-8,
directory trailing separators, and rejected relative paths.

### 5.4 `inventory`: ELF constructors on Motor

Patch `inventory` so Motor uses `.text.startup` for constructor functions and
`.init_array` for constructor pointers, as other ELF targets do. Pin the patch
through a reviewed Motor fork and exact Git revision, or vendor the exact
source. Do not modify an unpacked Cargo registry in the real build.

The first implementation will link rust-analyzer with `motor-rust-cc`, not the
pure-Rust linker path. The build gate must assert that the final ELF contains a
nonempty `INIT_ARRAY`, because omitting it produces a binary that appears to
start but cannot perform analysis.

An alternative pure-Rust design would add linker bounds and constructor
iteration to Motor's Rust startup. That affects the Rust stdlib port, all
pure-Rust processes with constructor sections, and process-start latency. It
is outside this plan unless separately reviewed and approved. If selected, it
becomes core work and receives the full repeated debug/release gate required
by AGENTS.md.

### 5.5 rust-analyzer: CPU count

`num_cpus 1.17.0` returns one on unknown targets. Motor's
`std::thread::available_parallelism()` already calls `moto_rt::num_cpus()` and
reported all four vCPUs in the test VM.

On Motor, use `available_parallelism()` for rust-analyzer's main-loop worker
count and cache priming. Fall back to one only if that standard API returns an
error. Physical-core topology is not available; treat Motor's available
logical CPU count as the scheduling limit rather than inventing a physical
count.

This is not a correctness blocker but should land before performance testing.

## 6. Reproducible build and dev-image staging

Add a `build_rust_analyzer` step to `src/build-motor-os.sh`, or a small script it
calls, with these properties:

- derive `MOTOR`, `MOTORH`, `RUST`, `SYSROOT`, `HOST`, and `TARGET` using the
  same layout as `build-motor-os.sh`;
- verify the final Stage 2 rustc and both target libraries before building;
- use the in-tree rust-analyzer snapshot from the same Rust revision as rustc;
- use host Cargo from the repository's pinned toolchain, with
  `RUSTC=$STAGE2/bin/rustc`;
- set `CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER` to
  `$SYSROOT/bin/motor-rust-cc`;
- pass `--locked --release --target x86_64-unknown-motor -p rust-analyzer`;
- keep Cargo's build target outside the image root;
- strip with the already-built LLVM strip tool;
- fail if the ELF is not a static PIE, has a dynamic `NEEDED` entry, has an
  executable stack, or lacks `.init_array`;
- never invoke `x.py`;
- recreate the generated output root so stale files cannot survive.

The rust-analyzer workspace has a lockfile but no vendored dependency tree.
The build must make dependency acquisition explicit and locked. Acceptable
designs are a reviewed vendor snapshot or a separate, explicit fetch step.
Normal tests and image tests must then run offline against the prepared cache;
they must not silently download dependencies.

Stage only into a new root, for example:

```text
$MOTORH/assemblies/<assembly-key>/images/rust-analyzer/
  devtools/rust/bin/rust-analyzer
  devtools/rust/lib/rustlib/src/rust/library/...
```

Add that root only to `src/imager/motor-os-dev.yaml`. Do not add it to
`motor-os.yaml`, and do not copy these files into the shared generated Rust
root.

The Rust library source tree in the inspected checkout was approximately
62 MiB. The rust-analyzer source workspace itself need not be staged.

The native spawn environment is:

```text
PATH=/system/bin:/user/bin:/devtools/bin
RUSTC=/devtools/bin/rustc
```

The rust-analyzer executable path is absolute:

```text
/devtools/rust/bin/rust-analyzer
```

## 7. Lorry workspace integration

Rust-analyzer normally invokes `cargo metadata`, Cargo build scripts, and
Cargo check. The Motor image does not contain Cargo. Lorry is the native
package builder, but its public commands are currently build, new, run, test,
vendor, help, and version; it is not a compatible `cargo metadata` substitute.

Rust-analyzer officially supports non-Cargo build systems through
`rust-project.json`, `linkedProjects`, and `workspace.discoverConfig`:

- <https://rust-analyzer.github.io/book/non_cargo_based_projects.html>
- <https://rust-analyzer.github.io/book/configuration>

### 7.1 First interface: `lorry rust-project`

Add a deterministic command that resolves the workspace using Lorry's
existing manifest, lockfile, target-selection, feature, and compilation-plan
logic, then emits rust-analyzer's project JSON.

The document must include:

- `sysroot`: `/devtools/rust`;
- `sysroot_src`:
  `/devtools/rust/lib/rustlib/src/rust/library`;
- every selected crate's root module and display name;
- edition and optional version;
- target triple and target kind where available;
- dependency edges using the crate name visible to rustc;
- cfg values and cfg groups;
- compile-time environment values needed for parsing/expansion;
- workspace-membership and source include/exclude roots;
- build labels sufficient for later runnable and flycheck mapping.

Output ordering must be stable. Paths must be absolute, normalized UTF-8 paths
within the admitted workspace, sysroot, or verified dependency repository.
Reject a crate root that escapes those locations instead of emitting an
untrusted path.

The first version may reject projects whose crate graph depends on unexecuted
build-script output. It must diagnose that limitation explicitly rather than
emit an inaccurate graph.

Red can initially request a temporary/static `rust-project.json` file and pass
its path in `linkedProjects`. A later patch can implement rust-analyzer's
workspace-discovery JSON-lines protocol so graph changes are refreshed without
an editor-specific file lifecycle.

### 7.2 Later interface: Lorry flycheck

Lorry already invokes rustc with:

```text
--error-format=json
--json=diagnostic-rendered-ansi,artifacts,future-incompat
```

Add a machine-readable check command suitable for rust-analyzer's
`check.overrideCommand`, preserving Cargo-compatible compiler-message JSON on
stdout and keeping human progress on stderr. The exact command name and JSON
envelope require a fixture test against rust-analyzer before becoming public
API.

Until this exists, disable check-on-save and use rust-analyzer's native
analysis diagnostics. Do not route Lorry's current human renderer back into
rust-analyzer.

### 7.3 Procedural macros and build scripts

Initialize the first native server with at least:

```json
{
  "cargo": { "buildScripts": { "enable": false } },
  "procMacro": { "enable": false },
  "files": { "watcher": "client" }
}
```

Declarative macros continue to work. Procedural macros remain disabled because
rust-analyzer's proc-macro server loads compiler-produced dylibraries. Full
support requires a separate design for Motor dynamic loading or an explicitly
static/IPC procedural-macro mechanism; it is not a local rust-analyzer patch.

## 8. Red integration

Red currently draws and then blocks in `crossterm::event::read()`. An LSP
reader thread cannot update diagnostics or complete a request while the main
thread waits for the next key unless both sources feed one event loop.

### 8.1 Process and event architecture

Add an editor-owned LSP client with:

- an absolute executable path and explicit PATH/RUSTC environment;
- piped stdin, stdout, and stderr;
- one serialized writer path for requests and notifications;
- a stdout reader that parses `Content-Length` framing;
- a stderr drain that forwards bounded recent errors to logging/status without
  blocking the child;
- request IDs and a bounded pending-request map;
- a dedicated terminal-input thread;
- one bounded main-thread channel carrying terminal, resize, LSP response,
  LSP notification, child-exit, and reader-error events.

Only the main editor thread mutates buffers or terminal state. LSP and input
threads own no `Editor` or `Buffer` references.

Shutdown order is:

1. stop sending document changes;
2. send `shutdown` and wait for its response through the normal event path;
3. send `exit`;
4. close the writer;
5. join reader threads and wait for the child;
6. if the child has already failed, report that original failure rather than
   replacing it with a shutdown error.

Do not automatically restart a failed server in the first implementation.

### 8.2 JSON decision

LSP messages require general JSON parsing and serialization. Red has no
general JSON dependency. Lorry has a repository-local JSON implementation,
but it was written for Lorry inputs and must be evaluated before being treated
as a complete LSP codec.

Review must choose one:

1. Approve `serde`/`serde_json` for Red. This is the least protocol code and
   uses rust-analyzer-compatible typed/untagged data naturally, but overrides
   the repository's standard-Rust-only default for this component.
2. Extract and extend a small internal JSON crate using standard Rust. It must
   implement all JSON string escaping, surrogate handling, number validation,
   nesting bounds, and duplicate/member behavior needed by LSP. This is more
   code and needs focused parser fuzz/property tests.

A hand-written parser embedded directly in the editor loop is not acceptable.

### 8.3 Protocol bounds and validation

- Accept only ASCII `Content-Length` headers with a fixed maximum header size.
- Set an explicit maximum message size and reject larger frames before
  allocation. The initial value should be chosen from measured rust-analyzer
  responses, with room for workspace diagnostics and completion, during the
  transport patch review.
- Treat truncated frames, invalid UTF-8 JSON, duplicate `Content-Length`, and
  impossible lengths as terminal protocol errors.
- Never execute `workspace/executeCommand` or a server-provided command without
  a separately reviewed allowlist and visible user action.
- Treat `workspace/applyEdit` as unsupported initially rather than applying
  unreviewed multi-file edits.
- Normalize and validate every server-returned file URI before opening it.
- Keep server stderr bounded in memory.

### 8.4 Document synchronization

For Rust buffers with an absolute filename:

- send `didOpen` with language ID `rust`, full text, and version 1;
- increment the version after every committed edit;
- initially send full-document `didChange` notifications for simplicity and
  correctness;
- debounce only redundant queued changes, not failures or responses;
- send `didSave` after a successful file write;
- send `didClose` when a buffer closes or the server shuts down.

Red stores lines as Rust `char` values and cursor columns as character indices.
LSP negotiated UTF-16 in the native prototype. Add explicit conversions from
line/character indices to UTF-16 code-unit positions and back. Tests must cover
ASCII, multibyte BMP characters, supplementary characters such as emoji,
combining characters, tabs, and positions at line end.

### 8.5 Filesystem watching

Keep rust-analyzer's default client watcher. Red already knows about its own
saves and can send buffer notifications immediately. Add
`workspace/didChangeWatchedFiles` for external workspace changes only after a
Motor-native change source is available and reviewed.

Do not select rust-analyzer's server watcher for the first port: the `notify`
crate falls back to polling on unknown targets, adding background filesystem
work and avoidable resource use.

### 8.6 User-visible feature order

1. Server status and diagnostics in the status bar plus simple per-line
   markers.
2. Hover text and go-to-definition.
3. Completion popup with insertion of plain text edits.
4. Signature help and references.
5. Rename, code actions, and workspace edits only after their multi-file edit
   and confirmation model is separately designed.

The first patch must not advertise or bind keys for capabilities it ignores.

## 9. Security, resource, and performance constraints

- Start rust-analyzer only when Red opens a Rust workspace or the user enables
  it, never during boot. This introduces no boot-time work.
- Pass arguments directly through `std::process::Command`; do not invoke Rush
  or interpolate a shell command.
- Use absolute tool paths and an explicit, minimal environment.
- Do not let project JSON reference arbitrary paths outside the workspace,
  dependency store, or sysroot.
- Bound protocol frames, pending requests, retained diagnostics, completion
  items, server stderr, and UI event queues.
- Drain both child output pipes concurrently.
- Disable proc macros, build scripts, server-side polling, and command
  execution initially.
- Rust-analyzer uses 16 MiB requested stacks for several named threads. Record
  resident memory, virtual memory, thread count, startup time, and first
  completion latency in the 1 GiB VM before choosing default worker limits.
- Use Motor's available logical CPU count, but cap only if measurements show a
  justified memory/latency tradeoff. Do not guess a smaller value in advance.
- Measure dev-image growth and retain the stripped binary; do not compress it
  in a way that adds startup-time decompression.

## 10. Patch series

Each numbered item is intended to be a reviewable 100-300 line patch including
tests. Dependency-fork changes are separate patches in their owning
repositories.

1. `url`: Motor UTF-8 file-URL support and round-trip tests.
2. `inventory`: Motor ELF `.init_array` support and a constructor execution
   fixture linked through the Motor mlibc wrapper.
3. rust-analyzer: make `dirs` non-Motor and define the no-user-config behavior.
4. rust-analyzer `stdx`: Motor concurrent streaming child-pipe reader.
5. rust-analyzer: Motor available-parallelism selection.
6. Motor OS build: direct, locked rust-analyzer build plus ELF validation and a
   clean generated dev root. No image change yet.
7. Motor OS image: stage stripped rust-analyzer and matching rust-src only in
   `motor-os-dev.yaml`; add `--version` and LSP lifecycle smoke tests.
8. Lorry: expose a stable internal crate-graph/project model from its resolved
   compilation plan.
9. Lorry: `rust-project` JSON serialization, CLI, fixtures, and path admission
   tests.
10. Red: reviewed JSON implementation/dependency and bounded LSP frame codec.
11. Red: child lifecycle, writer, stdout/stderr readers, and fake-server tests.
12. Red: unified terminal/LSP event loop without user-visible language
    features.
13. Red: UTF-16 conversion and full-document synchronization.
14. Red: diagnostics and server-status UI.
15. Red: hover and definition navigation.
16. Red: completion UI and plain-text completion edits.
17. Lorry/rust-analyzer: machine-readable flycheck command and
    `check.overrideCommand` integration.
18. Optional: workspace-discovery command replacing static project-file
    refresh.

Do not combine dependency ports, build staging, Lorry project modeling, and
editor protocol work into one large patch.

## 11. Tests and gates

### 11.1 Dependency and rust-analyzer gates

- Run relevant host unit tests in each modified dependency/workspace.
- Cross-check rust-analyzer for `x86_64-unknown-motor` with `--locked` and no
  network.
- Build the release executable with the final Stage 2 rustc.
- Inspect the ELF mechanically:
  - static PIE;
  - no `NEEDED` dynamic libraries;
  - nonempty `INIT_ARRAY`;
  - non-executable stack;
  - no undefined symbols after stripping.
- In Motor OS, test `--version`, initialize, inline/linked project load,
  `quiescent=true`, shutdown response, and clean exit.
- Analyze a fixture using the staged sysroot sources and assert at least one
  deterministic hover or completion response, not only startup.

### 11.2 Lorry gates

- Unit-test stable crate ordering and dependency indices.
- Compare fixture crate graphs with an approved host Cargo metadata oracle
  where semantics overlap.
- Test target cfg, renamed dependencies, features, path dependencies, registry
  dependencies, editions, libraries, binaries, tests, and rejected build-script
  cases.
- Verify identical project JSON on Linux and native Motor for the same admitted
  fixture.
- Include the native integration transitively in the dev full-test path.

### 11.3 Red gates

- Frame codec: fragmented headers and bodies, multiple frames in one read,
  malformed/duplicate lengths, oversized frames, invalid JSON, EOF, and
  unknown notifications.
- Fake LSP server: initialize/initialized, request correlation, diagnostics,
  server error, child exit, shutdown, and stderr saturation.
- UTF-16 property/fixture tests for non-ASCII content.
- Editor tests for didOpen/change/save/close versions and no LSP messages for
  non-Rust buffers.
- A native dev-image smoke test with real rust-analyzer, a Lorry project graph,
  a diagnostic, hover, and completion.

### 11.4 Repository gates

This design does not change `src/sys`, so component-specific tests plus the
dev full-test are the normal gate. New scripts must be included in
`src/tests/full-test.sh` or `src/tests/full-test-dev.sh` directly or
transitively, as appropriate.

Before each patch:

- run `cargo fmt` for the changed Rust workspace;
- run its focused tests and Clippy with no new warnings;
- build the affected dev image when staging changes;
- run all tests offline.

If implementation instead changes Motor Rust stdlib startup, stop and review
that change first. It then becomes core/toolchain work and requires three
consistent debug and three consistent release full-test builds/runs before a
patch is committed, following AGENTS.md.

## 12. Acceptance criteria

The initial native integration is complete when all of the following hold:

- `src/build-motor-os.sh` reproducibly builds or verifies a pinned rust-analyzer
  without another `x.py` invocation.
- The main image contains neither rust-analyzer nor rust-src; the dev image
  contains both at the documented paths.
- The native executable passes the ELF checks and the complete LSP lifecycle.
- A Lorry workspace can produce a deterministic, admitted crate graph without
  Cargo on Motor OS.
- Red can open a Rust file, keep its document synchronized, display a real
  rust-analyzer diagnostic, navigate to a definition, and show a completion.
- Non-ASCII cursor positions are correct according to negotiated UTF-16.
- Server failure is visible and leaves Red usable; it is not retried or
  ignored.
- Proc macros, build scripts, command execution, workspace edits, and polling
  watchers remain explicitly disabled unless later designs approve them.
- Component and dev full-test gates pass offline with no new warnings.
- Startup and resident-memory measurements are recorded for the 1 GiB,
  four-vCPU VM configuration used by normal development.

## 13. Review decisions still needed

1. **Constructor path.** Recommended: patch `inventory` and link
   rust-analyzer through `motor-rust-cc`. Alternative: vet and test pure-Rust
   `.init_array` startup in Motor Rust stdlib.
2. **Red JSON.** Approve `serde`/`serde_json`, or require extraction and
   extension of a standard-Rust internal JSON crate.
3. **Dependency source.** Choose exact-revision Motor forks versus a reviewed
   vendor snapshot for `url` and `inventory`.
4. **Motor user configuration.** Recommended first behavior: no implicit user
   config directory; use LSP initialization settings. Choose a persistent path
   only with a Motor filesystem convention.
5. **Project bridge.** Recommended: `lorry rust-project` first, discovery and
   flycheck later. Porting Cargo is explicitly not recommended as the initial
   dependency.

Implementation must not begin past the relevant boundary until these choices
are reviewed.
