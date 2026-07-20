# Stage-1 Cargo oracles

`cargo-1.97.json` and `cargo-1.98.json` freeze every dependency-free Stage-1
unit shape: normal binary and binary test harness units, in dev and release
profiles, for native Linux and explicit `x86_64-unknown-motor` compilation.

Both Cargo versions are run with the same Linux rustc for native cases and the
same Motor development rustc for cross cases. The capture rejects any metadata,
extra-filename, or executable-byte difference between the two Cargo families.
Paths are normalized, and every build uses a new isolated `HOME`, `CARGO_HOME`,
and target directory.

Regenerate with the locally installed 1.97, 1.98, and Motor toolchains:

```sh
./tests/capture_stage1_oracles.py \
  --cargo-1.97 "$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo" \
  --cargo-1.98 "$HOME/.rustup/toolchains/nightly-2026-06-19-x86_64-unknown-linux-gnu/bin/cargo" \
  --native-rustc "$HOME/.rustup/toolchains/nightly-2026-06-19-x86_64-unknown-linux-gnu/bin/rustc" \
  --motor-rustc "$HOME/.rustup/toolchains/dev-x86_64-unknown-motor/bin/rustc" \
  --package ../red \
  --output-dir tests/oracles
```
