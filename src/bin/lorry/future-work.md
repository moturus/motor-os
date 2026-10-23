# Lorry: potential future work

Everything here is potential future work. Nothing is scheduled. Each item
says what is missing or wrong, and where. Items marked "from dev" predate the
workspace work. `spec.md` documents the deliberate differences from Cargo;
this file lists the ones that could change.

## Reproduced bugs from the 2026-10-08 product review

These findings came from reviewing the current product and documentation,
with focused reproductions, rather than individual commits. P1 is the most
urgent fix; P2 findings are correctness issues that should also get focused
regressions in the product suite.

- **P1: Linux network filter accepts another syscall ABI.**
  `install_network_filter` in `src/sandbox.rs` compares native syscall
  numbers without checking the syscall architecture. On the review's
  x86-64 Linux host, a sandboxed script's native `socket(AF_INET, ...)`
  returned `EPERM`, while the i386 compatibility syscall through `int 0x80`
  returned a valid socket. The probe only created and closed sockets; it
  made no connections. This bypasses the filter that implements the spec's
  network isolation. Validate the architecture and reject unsupported ABIs
  before interpreting syscall numbers. Add a regression using an alternate
  ABI; an outer test sandbox must not supply the protection being tested.
- **P2: Build-script deadlines do not bound inherited pipe holders.**
  `capture` in `src/build_script.rs` stops monitoring its deadline when the
  direct child exits, then joins stdout/stderr readers without a deadline.
  The timeout branch also kills only the direct child before joining those
  readers. With `build-script-seconds = 1`, a script that spawned itself as
  a child, then exited, succeeded after 4.185 seconds because the child slept
  for four seconds with the pipes open. A descendant that never closes the
  pipes can hang Lorry indefinitely. Bound pipe draining as well as process
  execution, and terminate/reap the script's descendants. Use a finite child
  in the regression so a failure cannot hang the suite indefinitely.
- **P2: Strict completed-profile reuse skips build-script output contents.**
  `restore_fresh_profile` in `src/engine.rs` checks only that a recorded
  `OUT_DIR` exists. It bypasses the output digest check in `run_record::fresh`.
  In the reproduction, a build script wrote `generated.dat` in `OUT_DIR`,
  and the program read it at runtime. After changing its contents from
  `good` to `bad`, `lorry run --strict-validation` reported "validated fresh
  root profile" and the program read `bad`. The spec requires an unchanged
  `OUT_DIR` for script reuse. Carry script output fingerprints into completed
  profiles and share their validation with ordinary script reuse. Audit the
  other invariants bypassed by this shortcut as part of that fix.
- **P2: Native target runners are ignored without an explicit target.**
  `run_artifact` in `src/engine.rs` consults the runner only when
  `physical_target` is present. With
  `[target.x86_64-unknown-linux-gnu].runner` configured, the same project and
  pinned toolchain produced `RUNNER` followed by `PROGRAM` under Cargo, but
  only `PROGRAM` under Lorry. This is an undocumented Cargo incompatibility
  that can bypass required execution setup. Honor the runner for ordinary
  native target execution, while preserving the documented direct execution
  of host procedural-macro harnesses. Cover both native run and test.
- **P2: Metadata and tree use the wrong Cargo-evidence directory.**
  `src/metadata/mod.rs` and `src/tree.rs` pass
  `engine::artifact_root(manifest)` to `LockedContext::open`. That helper
  hardcodes `<workspace>/target/lorry`, ignoring the configured target
  directory. With a cached registry dependency, `CARGO_TARGET_DIR` pointing
  elsewhere, and an unrelated ordinary file named `target` in the project,
  Cargo metadata succeeded offline; Lorry metadata failed with "Not a
  directory" while inspecting `.cargo-evidence`. Tree has the same path
  construction. This also makes a writable external target directory
  insufficient for a read-only source checkout. Derive evidence paths from
  resolved configuration and add a registry-backed target-directory contract.

## Differences from Cargo

- **Resolver contexts.** Lorry resolves host and target feature contexts
  separately, so one package can add more than one group of dependencies.
  The extra groups normally select packages that are already chosen. If one
  of them causes backtracking, the lock can still differ from Cargo's. So can
  a `vendor` run that counts only the cached index entries of a crate, since
  Lorry fetches a crate's index only when no cached version matches.
- **Workspace membership.** A package below a workspace root that neither
  lists nor excludes it builds as a standalone package. Cargo refuses to
  build it. See `SourceWorkspace::load` in `src/manifest/source.rs`. The
  README's statement that membership follows Cargo needs this exception;
  recording it only here leaves the user-facing contract inaccurate.
- **Build-script link search paths.** Lorry accepts a `rustc-link-search`
  path, or a `-L` in `rustc-flags`, only if it exists inside the script's
  `OUT_DIR`. Cargo accepts any path. So crates that link a system library
  found by pkg-config, or kept in a fixed directory, fail. See
  `resolve_existing` in `src/build_script.rs`.
- **Build-script metadata keys.** Lorry accepts only ASCII letters, digits,
  `_`, and `-` in a metadata key. Cargo accepts more.
- **Build-script output.** Lorry prints a build script's stderr after a
  successful run, such as the compiler errors of a feature probe. Cargo shows
  it only when the script fails, or with `-vv`. See
  `render_build_script_output` in `src/executor.rs`.
- **GCC as a native tool.** A build script cannot use GCC: its driver starts
  `cc1`, which the build-script sandbox blocks. Clang works.
- **Config `rustflags` are always appended (from dev).** Cargo appends only
  arrays. A string value replaces the lower layer, and mixing a string with
  an array is an error. See `src/config.rs`.
- **`CARGO_TARGET_<T>_LINKER` and `_RUNNER` (from dev).** Cargo resolves a
  relative program path from these variables against the invocation
  directory, and splits a runner on whitespace only. Lorry keeps the path
  relative and splits like a shell.
- **Metadata `dep_kinds` order.** Lorry sorts platform selectors as strings.
  Cargo puts a target triple before any `cfg(...)`, and `cfg(unix)` before
  `cfg(target_os = ...)`.
- **Metadata lists dependencies that have no library.** Cargo leaves them out
  of `deps`, `dependencies`, `nodes`, and `packages`.
- **`tree` is small.** It shows no dev-dependencies. It has no `--depth`,
  `-e`, `-i`, `--prefix`, or `--charset`. See `src/tree.rs`.
- **`clean -p` accepts only workspace members.** Cargo also cleans a
  dependency, such as `cargo clean -p serde`.
- **Changing `-j` reruns build scripts.** `NUM_JOBS` is part of the
  build-script run key and the unit key. Cargo does not fingerprint it.
- **A name in the wrong case gets no hint.** A dependency spelled
  `mixedcase` for the crates.io package `MixedCase` fails, as in Cargo, but
  with only "no version of `mixedcase` matches". Cargo also suggests the
  right spelling. See `src/resolver/search.rs`.

## Commands

- **Per-command `--help`.** `lorry build --help` is an error; only
  `lorry help build` works. Cargo accepts both.
- **Help text drifts.** The help in `src/main.rs` is written by hand. The help
  for `build` lists five options, but the parser accepts many more. The help
  should come from the CLI schema, including per-command `--help`, so the
  parser and documentation share one list of supported options.
- **Options that do not apply are ignored.** `--max-packages`,
  `--use-cargo-registry`, and `--no-use-cargo-registry` are accepted by some
  commands that do not use them, such as `locate-project` and `help`. The
  spec says such options are usage errors. Enforce applicability centrally;
  this is a contract discrepancy, not just a missing convenience.
- **`--use-cargo-registry` placement.** It works only before the command
  name. `-q`, `-v`, and `--color` work in both places.
- **A first lock needs a review.** A path-only project with no Cargo.lock
  cannot build until `lorry vendor` writes one. That vendor run still shows
  a review, even with no outside packages, and fails without a terminal
  unless given `--accept-all`.
- **`cache clean`** could have a dry run and report the size it frees.

## Full native build

The goal is to build and Clippy-check, with Lorry on Motor OS, every
Motor-target crate that the root `Makefile` builds, except `src/boot`. That
includes the kernel and vdso, and the imager through `lorry run`. Curl and
the Linux `host-lorry` build stay on Cargo.

1. **Kernel custom target and build-std.** `src/sys/kernel/build.sh` uses
   `--target kernel.json -Zjson-target-spec -Zbuild-std=core,alloc
   -Zbuild-std-features=compiler-builtins-mem`. Lorry rejects `.json`
   targets. It would need to parse a bounded target file and use its digest
   in unit and admission identity. It would also need to build `core`,
   `alloc`, and `compiler_builtins` from the rust-src that matches rustc,
   and cache them under an identity that covers rustc, rust-src, the target
   file, and the features.
2. **The imager does not build for Motor.** This is a source problem. It
   uses moto-sdk's `async_fs::file_block_device`, which the SDK builds only
   for other targets. Its manifest takes Tokio from crates.io, not the Motor
   Tokio patch that `src/sys` uses.
3. **Admission state.** Only Lorry's own tree commits
   `.lorry/dependencies-v2.toml`. Every other root needs one networked
   `lorry vendor` and a review before offline native builds. The largest
   graphs, `russhd` and `httpd-axum`, have not been built natively; a dry
   run should check that they fit the download and extraction limits.
4. **Make still calls Cargo.** `DO_BUILD` and `DO_CLIPPY` run `cargo build`
   and `cargo clippy`. Switching them to Lorry needs a test of parallel
   `make -j`, where several Lorry processes share one target directory and
   the global cache.

A sensible order is 3, 2, 1, then 4. Two decisions are open: what portable
name admission should use for a custom target file, and which Motor block
device the imager should use.

## Performance

The last comparison with Cargo on Linux, at `aba5c563` (Helix at
`82f27ed3`), used Lorry repositories with admission. The default Cargo-cache
mode has not been measured. Both tools used the same rustc, the dev profile,
and 16 CPUs. The full report is in `cargo-performance.md` in git history.

| Step | sys-io: Cargo | sys-io: Lorry | Helix: Cargo | Helix: Lorry |
| --- | --- | --- | --- | --- |
| Cold build | 17.9 s | 18.8 s | 66.7 s | 70.4 s |
| No-op build | 0.06 s | 0.04 s | 0.12 s | 0.04 s |
| Edit a library | 1.3 s | 2.3 s | 8.1 s | 10.3 s |

Measure the default Cargo-cache workflow before choosing performance work.
Include cold, no-op, edited-source, and warm-global-cache builds with the
same toolchain and inputs. The figures above do not establish its current
costs. Duplicate source loading, repeated extraction, and admission after
edits are stronger initial candidates than the roughly 2 ms fallback cost.

- **Admission is rebuilt after every edit.** This is about half of the gap
  after an edit: 0.6 s for sys-io and 1.1 s for Helix. It is resolver work: the
  complete lock, then one resolution per reviewed host/target context.
- **Cold builds start late.** On a cold Helix build, admission and source
  checks took 2 s before the first rustc started.
- **A warm global cache saves less than it could.** With a warm cache and an
  empty target directory, Lorry still compiles every member and every binary:
  47 s of Helix's cold build.
- **Motor does not pipeline.** rt.vdso's `readdir` can end a listing early;
  see `docs/plans/future-work.md`. Once that is fixed, Motor builds can
  pipeline as Linux builds do.
- **A Cargo-cache miss runs the command twice.** The second run uses Lorry
  repositories. The repeated work costs about 2 ms. Running once would mean
  splitting build, metadata, and tree into a part that does not depend on the
  registry and a part that is retried.

## Simplifications

- **Freshness checks diverge.** Completed-profile, unit-cache, and script
  run-record reuse each validate their own evidence. The reproduced
  `OUT_DIR` bug shows the cost of that duplication. Share small evidence
  structures and validation functions so a fast path preserves the ordinary
  path's invariants; avoid adding another general cache abstraction.
- **Commands reconstruct configuration and dependency context.** Build,
  metadata, and tree should share resolved artifact/evidence paths and reuse
  already-loaded workspace and dependency data through `LockedContext`.
  The metadata target-directory bug is a concrete reason to consolidate
  this setup.
- **Admission loads Git sources twice.** `reconstruct` in
  `src/dependency/workspace/admission.rs` loads every locked Git source
  again, although the engine already did. Ordinary validation no longer
  rehashes them, but admission could take the engine's catalog.
- **Vendor extracts some archives more than once.** `Acquisition::evidence`
  in `src/vendor.rs` unpacks every archive-only object on each call, and
  `fetch --target` calls it once per proc-macro discovery round.
- **Large modules.** `src/engine.rs` (5.3k lines), `src/resolver.rs` (5.2k),
  `src/manifest.rs` (4.4k), and `src/admission_state.rs` (3.1k) could be
  split. About 2k lines of engine and 3.2k of resolver are tests, so total
  size overstates the production-code problem. Move test modules and extract
  cohesive freshness/execution code at real boundaries after correctness
  work, rather than starting a broad architectural rewrite.
- **Small duplicates.** `curl::Metadata` and `curl::GitMetadata` differ by one
  field. `requested` exists in both `src/git/direct.rs` and
  `src/git/refresh.rs`.

## Admission and review

- **Motor build-script isolation.** Motor's warning-only execution is an
  explicit documented limitation, separate from the Linux filter defect
  above. Decide the required native containment before expanding reliance
  on third-party build scripts. Admission review and execution isolation
  serve different purposes. Any needed OS support belongs in separately
  reviewed OS work.
- **Lock format 3 Git selectors.** A version 3 lock spells a branch selector
  decoded (`feature/x`), version 4 keeps it encoded (`feature%2Fx`). The same
  graph then gives two different review digests. This fails closed: the user
  must vendor again.

## Motor process roles

- **Each role's trust files are writable by every process of that role.**
  Lorry keeps its policy and workspace decisions in `/user/cfg` for
  Interactive and `/none/cfg` for None. Any process of the same role can
  change them, including a build script, since Motor runs build scripts
  without isolation. So a None-role build script can approve later None-role
  builds. This follows from the per-role layout; decide it together with
  Motor build-script isolation above.
- **Test bundles fix their extraction directory when built.**
  `TestConfig::extraction_root` in `src/config.rs` uses the building role's
  temporary directory, and the bundle digest includes it. A bundle built as
  Interactive, or cross-built on Linux, extracts under `/user/tmp`, which a
  None-role runner cannot use.
- **The System refusal has no end-to-end test.** `role::refuse_system` acts
  only on Motor, and no test runs Lorry as System: SSH sessions cannot be
  System, and the console test image has no Lorry.
- **The role comes from capability bits.** `src/role.rs` reads `CAP_SYS` and
  `CAP_INTERACTIVE` itself, because the published `moto-sys` 0.3.1 has no
  `ProcessRole`. Use `ProcessRole::from_caps` once a release has it.

## Tests

- `tests/test-native.sh` vendors from crates.io and GitHub on every run of
  `test-all.sh`. Supply pinned local source fixtures for regular offline
  validation and make online acquisition a separate integration step. Keep
  the Cargo and cross/native Lorry byte-identity checks in the offline gate.
- `artifact-lock-contract.sh` and `helpers/cancel-probe.rs` wait 0.1-0.2 s
  before checking that nothing happened, so they pass trivially when Lorry is
  slow. Replace elapsed-time assumptions with synchronization proving that
  the competing operation reached the relevant state.
- `stage2-differential.sh` keeps the old "stage 2" name.
- 25 test scripts embed Python (48 `python3` calls), mostly to read JSON and
  to build synthetic crates. Port them to shell or Rust.
  `mixed-case-name-contract.sh` builds a synthetic crate with `tar` and
  `sha256sum`.

## Recommended order after the product review

1. Fix the five reproduced defects, starting with the sandbox and process
   lifetime issues. Add focused regressions at those product boundaries.
2. Make native verification hermetic and replace fixed-sleep negative tests.
3. Resolve the intended Motor build-script isolation boundary.
4. Measure the default Cargo-cache workflow, then simplify repeated source,
   evidence, and admission work where the measurements justify it. Resolve
   the documented Motor `readdir` defect in separate OS work before enabling
   native pipelining.
5. For complete native builds, retain the admission -> imager -> kernel
   custom target/build-std -> Make order above. Qualify the full build set
   and concurrent shared-cache behavior before switching Make.

Help generation and documentation corrections can be small independent
patches. Broad module restructuring, tiny duplicates, the stage-2 rename,
and the whole-command fallback rewrite are lower priorities.

## Product review validation (2026-10-08)

- 495 unit tests and four integration tests passed. The ordinary unit run
  left ten fixture-dependent TLS tests ignored.
- All host contract stages preceding TLS in `tests/test-all.sh` passed,
  including Cargo differential/byte-identity checks, workspace behavior,
  admission, build scripts, procedural macros, concurrency, and editor
  integration.
- The initial TLS contract run failed because the outer execution sandbox
  denied localhost listener creation. Nine localhost TLS cases passed when
  run outside that sandbox. The external-DNS case was omitted to respect
  the network-test restriction; it was not validated by that run.
- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` passed
  with the repository-selected toolchain.
- This was not a complete `test-all.sh` pass. The online native self-build
  stage was not run, so native Motor execution remains unverified by this
  review. The five focused reproductions were temporary review fixtures;
  they still need permanent regressions in the product suite.
