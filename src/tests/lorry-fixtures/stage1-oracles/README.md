# Lorry Stage-1 Cargo oracles

`cargo-1.97.json`, `cargo-1.98.json`, and `cargo-1.99.json` freeze every
dependency-free Stage-1 unit shape: normal binary and binary test harness units,
in dev and release profiles, for native Linux and explicit
`x86_64-unknown-motor` compilation.

All three Cargo versions use the same Linux rustc for native cases and the same
Motor development rustc for cross cases. The capture rejects any metadata,
extra-filename, or executable-byte difference between the Cargo families.
Paths are normalized, and every build uses a new isolated `HOME`, `CARGO_HOME`,
and target directory. The package is the checked-in dependency-free fixture at
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
