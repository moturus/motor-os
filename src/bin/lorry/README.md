# Lorry Stage 1

Lorry is a dependency-free Rust package builder for the deliberately small
Stage-1 package shape:

- one package in `Cargo.toml` in the current directory;
- one implicit `src/main.rs` binary;
- an empty `[dependencies]` table;
- a present, current, root-only Cargo.lock version 4;
- Cargo's default dev profile and the supported release keys `panic`, `lto`,
  `strip`, and `codegen-units`.

The Stage-1 commands are:

```text
lorry [+toolchain] [GLOBAL] build [--release|-r] [--target TRIPLE]
lorry [+toolchain] [GLOBAL] run   [--release|-r] [--target TRIPLE] [-- ARGS...]
lorry [+toolchain] [GLOBAL] test  [--release|-r] [--target TRIPLE] [-- ARGS...]
```

The global `--use-cargo-registry` option is an explicit offline compatibility
mode. It resolves crates.io packages from Cargo's populated registry cache and
compiles them at Cargo's unchanged source paths, which is the mode used for
Cargo/Lorry release-byte comparisons. Cached archives and extracted sources
are verified before use; the option never fetches or repairs Cargo's cache.
Without it, Lorry uses its configured repositories.

Run and test return the executed program's status. Build and operational
failures return 101, command-line usage errors return 1, and help/version
return 0. Build output is isolated below `target/lorry`; Lorry never reads
Cargo artifacts and deliberately rebuilds every Stage-1 unit.

Stage 1 can be bootstrapped without Cargo:

```sh
rustc --edition=2024 src/main.rs -o /tmp/lorry
```

Run the fast unit suite and the complete Linux Stage-1 acceptance gate with:

```sh
cargo test --locked
./tests/stage1-linux.sh
```

The native Motor gate is:

```sh
./test-native.sh --full
```

`test-native.sh --reuse-running-vm` runs the short smoke gate inside the VM
owned by `src/tests/full-test.sh`.

Stage 2 supports locked registry and local-path dependency graphs, one root
library and binary, and direct `tests/*.rs` integration targets. Ordinary
`test`, `--test NAME`, and `--no-run` build Cargo-compatible separate
harnesses; `--bundle` and `vendor` remain later Stage-2 sub-stages. Workspaces,
custom JSON targets, compiler wrappers, and output relocation are rejected
with actionable errors. Documentation tests are reported as omitted because
native Motor does not ship rustdoc.
