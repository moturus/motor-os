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

The native Motor OS gate is:

```sh
./test-native.sh --full
```

`test-native.sh --reuse-running-vm` runs the short smoke gate inside the VM
owned by `src/tests/full-test.sh`.

Stage 2 supports locked registry and local-path dependency graphs, one root
library and binary, and direct `tests/*.rs` integration targets. Ordinary
`test`, `--test NAME`, and `--no-run` build Cargo-compatible separate
harnesses. Explicit `test --bundle` packages the selected harnesses and any
required package binary into one verified, self-extracting target executable;
`--no-run` prints its deterministic path. Bundle arguments are forwarded to
every harness and failures are aggregated. The extraction cache location is
configured by the absolute `[test].extraction-root` path. Unix builds enforce
private file modes; platforms without Unix permission modes retain the
symlink, canonical-file-set, and content-integrity checks. `vendor` remains a
later Stage-2 sub-stage. Workspaces, custom JSON targets, compiler wrappers,
and output relocation are rejected with actionable errors. Documentation
tests are reported as omitted because native Motor OS does not ship rustdoc.

Stage 2 reuses verified library metadata and rlibs from the versioned
content-addressed cache below `target/lorry/.cache`. Every hit re-hashes its
canonical payload, while incomplete entries are ignored and corrupt entries
are quarantined. Build scripts still compile and run on every Lorry invocation,
and final programs and test harnesses always relink.
