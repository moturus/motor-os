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

Stage 1 rejects workspaces, dependencies, explicit targets in the manifest,
custom profiles, custom JSON targets, compiler wrappers, output relocation,
and Stage-2-only vendoring/integration-test/bundle options with actionable
errors. Documentation tests are reported as omitted because native Motor does
not ship rustdoc.
