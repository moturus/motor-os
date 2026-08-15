# Lorry Stage-1 Cargo oracles

`cargo-1.97.json` and `cargo-1.99.json` freeze the oldest and newest supported
Cargo families' dependency-free Stage-1 unit shapes: normal binary and binary
test harness units, in dev and release profiles, for native Linux and explicit
`x86_64-unknown-motor` compilation.

All three supported Cargo versions use the same Linux rustc for native cases
and the same Motor development rustc for cross cases. Regeneration captures
every family in temporary storage and rejects any metadata, extra-filename, or
executable-byte difference between adjacent families. Only the boundary
families are retained in Git; Cargo 1.98 remains covered by that equivalence
check and by the live Stage-2 resolution oracle in every Lorry gate. Paths are
normalized, and every build uses a new isolated `HOME`, `CARGO_HOME`, and target
directory. The package is the checked-in dependency-free fixture at
`src/tests/lorry-fixtures/stage1-package`; it contains no current Red source.

Regenerate from the repository root with the locally installed toolchains:

```sh
src/tests/capture-lorry-stage1-oracles.py \
  --cargo-1.97 "$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo" \
  --cargo-1.98 "$HOME/.rustup/toolchains/nightly-2026-06-19-x86_64-unknown-linux-gnu/bin/cargo" \
  --cargo-1.99 "$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/cargo" \
  --native-rustc "$HOME/.rustup/toolchains/nightly-2026-06-19-x86_64-unknown-linux-gnu/bin/rustc" \
  --motor-rustc "$HOME/.rustup/toolchains/dev-x86_64-unknown-motor/bin/rustc" \
  --output-dir src/tests/lorry-fixtures/stage1-oracles
```

The script removes an obsolete intermediate capture from the output directory.
After regeneration, review both retained JSON diffs and run the fast and
exhaustive Lorry gates.

## Cargo compatibility bump workflow

The large Stage-1 oracle set is always bounded to two checked-in families: the
oldest and newest families that Lorry supports. Adding a family does not
implicitly retire product support for an older family. The small Stage-2
resolution oracle continues to execute every supported Cargo family.

For a `cargo-compat-version` bump:

1. Add the family to Lorry's compatibility enum, inference, configuration,
   diagnostics, specification, installation defaults, and focused tests.
2. Extend `capture-lorry-stage1-oracles.py` to capture the new Cargo binary in
   version order. Keep the adjacent-family comparisons and retain only the
   first and last captures.
3. Run the command above with one binary for every supported family and the
   same native and Motor rustc binaries. Any identity or artifact difference
   is a compatibility change that must be resolved before the bump proceeds.
4. Extend `verify-stage2-resolution-oracle.sh` to run the frozen resolver
   fixture with the new Cargo binary. All supported families must still
   produce the one checked-in lockfile byte-for-byte.
5. Review the two retained Stage-1 captures, the Stage-2 lockfile result, and
   the product/configuration changes. Run
   `src/bin/lorry/tests/test-fast.sh`, then
   `src/bin/lorry/tests/test-exhaustive.sh` because a compatibility bump
   changes the compiler-identity and harness boundary.

Removing a supported family is a separate compatibility decision. When that
happens, remove it consistently from code, configuration, documentation,
capture inputs, and the live Stage-2 resolver check; the boundary-capture rule
then selects the new oldest family automatically.
