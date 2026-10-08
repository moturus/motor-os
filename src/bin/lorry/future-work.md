# Lorry future work

Known gaps and simplifications, recorded on 2026-10-08 and not scheduled.
Each item says what is wrong and where. Items marked "from dev" predate the
workspace work.

## Simplifications

- **Delete the older single-package build path.** The shared workspace path
  can build everything. The narrow path still builds one package with no
  build script, no feature flags, and no binaries with `required-features`.
  It used to make unchanged builds faster. It no longer does, because both
  paths now reuse a completed-profile record before admission. Remove it and
  the `shared` predicate in `src/engine.rs`. `--use-cargo-registry`
  (`src/cargo_registry.rs`) uses the narrow prepare code, so move it first.
- **Admission verifies Git sources twice.** `reconstruct` in
  `src/dependency/workspace/admission.rs` loads and hashes every locked Git
  source again, although the engine already did. It cannot simply reuse the
  engine's catalog: a single-package build loads only the root's
  dependencies, while admission needs the whole workspace.
- **Vendor extracts some archives more than once.** `Acquisition::evidence`
  in `src/vendor.rs` unpacks every archive-only object on each call, and
  `fetch --target` calls it once per proc-macro discovery round.

## Differences from Cargo

- **Resolver contexts.** Lorry resolves host and target feature contexts
  separately, so one package can add more than one group of dependencies.
  The extra groups normally select packages that are already chosen. If one
  of them causes backtracking, the lock can still differ from Cargo's. So can
  a `vendor` run that counts only the cached index entries of a crate, since
  Lorry fetches a crate's index only when no cached version matches.
- **Config `rustflags` are always appended (from dev).** Cargo appends only
  arrays. A string value replaces the lower layer, and mixing a string with
  an array is an error. See `src/config.rs`.
- **`CARGO_TARGET_<T>_LINKER` and `_RUNNER` (from dev).** Cargo resolves a
  relative program path from these variables against the invocation
  directory and splits a runner on whitespace only. Lorry keeps the path
  relative and splits like a shell.
- **Options that do not apply are ignored.** `--max-packages` and
  `--use-cargo-registry` are accepted by commands that do not use them,
  such as `clean`, `locate-project`, and `help`. The spec says such options
  are usage errors.
- **Metadata `dep_kinds` order.** Lorry sorts platform selectors as strings.
  Cargo puts a target triple before any `cfg(...)`, and `cfg(unix)` before
  `cfg(target_os = ...)`.
- **Metadata lists dependencies that have no library.** Cargo leaves them out
  of `deps`, `dependencies`, `nodes`, and `packages`.
- **`clean -p` accepts only workspace members.** Cargo also cleans a
  dependency, such as `cargo clean -p serde`.
- **Changing `-j` reruns build scripts.** `NUM_JOBS` is part of the
  build-script run key and the unit key. Cargo does not fingerprint it.

## Admission and review

- **`--use-cargo-registry` skips admission for Git packages.** Without
  `.lorry/dependencies-v2.toml`, Git packages compile under policy alone in
  this mode. The spec says compilation with Git dependencies needs a reviewed
  context. Either gate Git packages in both modes or document the exception.
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
