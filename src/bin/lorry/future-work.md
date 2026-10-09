# Lorry: potential future work

Everything here is potential future work. Nothing is scheduled. Each item
says what is missing or wrong, and where. Items marked "from dev" predate the
workspace work. `spec.md` documents the deliberate differences from Cargo;
this file lists the ones that could change.

## Differences from Cargo

- **Resolver contexts.** Lorry resolves host and target feature contexts
  separately, so one package can add more than one group of dependencies.
  The extra groups normally select packages that are already chosen. If one
  of them causes backtracking, the lock can still differ from Cargo's. So can
  a `vendor` run that counts only the cached index entries of a crate, since
  Lorry fetches a crate's index only when no cached version matches.
- **Workspace membership.** A package below a workspace root that neither
  lists nor excludes it builds as a standalone package. Cargo refuses to
  build it. See `SourceWorkspace::load` in `src/manifest/source.rs`.
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

## Commands

- **Per-command `--help`.** `lorry build --help` is an error; only
  `lorry help build` works. Cargo accepts both.
- **Help text drifts.** The help in `src/main.rs` is written by hand. The help
  for `build` lists five options, but the parser accepts many more. The help
  could come from the parser.
- **Options that do not apply are ignored.** `--max-packages`,
  `--use-cargo-registry`, and `--no-use-cargo-registry` are accepted by some
  commands that do not use them, such as `locate-project` and `help`. The
  spec says such options are usage errors.
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
   uses `async_fs::file_block_device`, which `async-fs` builds only for
   other targets. Its manifest takes Tokio from crates.io, not the Motor
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

- **Admission loads Git sources twice.** `reconstruct` in
  `src/dependency/workspace/admission.rs` loads every locked Git source
  again, although the engine already did. Ordinary validation no longer
  rehashes them, but admission could take the engine's catalog.
- **Vendor extracts some archives more than once.** `Acquisition::evidence`
  in `src/vendor.rs` unpacks every archive-only object on each call, and
  `fetch --target` calls it once per proc-macro discovery round.
- **Large modules.** `src/engine.rs` (5.3k lines), `src/resolver.rs` (5.2k),
  `src/manifest.rs` (4.4k), and `src/admission_state.rs` (3.1k) could be
  split.
- **Small duplicates.** `curl::Metadata` and `curl::GitMetadata` differ by one
  field. `requested` exists in both `src/git/direct.rs` and
  `src/git/refresh.rs`.

## Admission and review

- **Lock format 3 Git selectors.** A version 3 lock spells a branch selector
  decoded (`feature/x`), version 4 keeps it encoded (`feature%2Fx`). The same
  graph then gives two different review digests. This fails closed: the user
  must vendor again.

## Tests

- `tests/test-native.sh` vendors from crates.io and GitHub on every run of
  `test-all.sh`. Regular tests should stay offline.
- `artifact-lock-contract.sh` and `helpers/cancel-probe.rs` wait 0.1-0.2 s
  before checking that nothing happened, so they pass trivially when Lorry is
  slow.
- `stage2-differential.sh` keeps the old "stage 2" name.
