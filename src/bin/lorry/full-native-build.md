# Full native build: remaining gaps

Status: updated on 2026-10-08. This is a findings document, not a normative
Lorry design. Accepted behavior belongs in `spec.md`, and implementation
rationale belongs in `design.md`.

## Goal

Run Lorry on Motor OS and have it build and Clippy-check every Motor-target
crate that the repository-root `Makefile` builds, except the crates below
`src/boot`. This includes the kernel and vdso, every ordinary `DO_BUILD` and
`DO_CLIPPY` package, Lorry itself, and the imager, which runs through
`lorry run`.

Out of scope:

- `src/boot/x64.mbr`, `src/boot/x64.boot`, and `src/boot/x64.kloader`;
- the Linux-host `host-lorry` build, and curl, which Linux-hosted Cargo
  cross-builds as Lorry's network transport on Motor;
- replacing Make, `strip`, or VM scripts with Lorry features.

The VM supplies the prebuilt boot binaries, the native LLVM toolchain
(`/devtools/llvm`, with `/devtools/bin/cc` and `/devtools/bin/c++`), and a
native rustc with matching rust-src and `clippy-driver`.

## Done since the first audit

- Member build scripts run, with `rustc-link-arg` and the other supported
  directives, under named grants.
- Lock formats 1 to 3 are read, and Cargo profile environment overrides
  and CLI feature flags work.
- The developer image allows 384 packages, which covers the largest graph
  (`russhd`, about 200 packages).
- `lorry clippy` exists, and the image stages a native `clippy-driver` next
  to rustc.
- Git patches and direct Git dependencies are fetched with gix on Linux and
  Motor.
- `dns-resolver` no longer has a build script, so its native-tool gap is
  gone.

## Remaining gaps

1. **Kernel custom target and build-std.** `src/sys/kernel/build.sh` builds
   with `--target kernel.json -Zjson-target-spec -Zbuild-std=core,alloc
   -Zbuild-std-features=compiler-builtins-mem`. Lorry rejects `.json`
   targets. A narrow implementation needs to:
   - parse a bounded target JSON file, query rustc's cfg for it, and use a
     stable target name plus the file digest in unit and admission identity;
   - pass rustc the JSON-target opt-in without accepting other unstable
     Cargo flags;
   - build `core`, `alloc`, and `compiler_builtins` with the requested
     features from the rust-src that matches rustc;
   - keep host build scripts and procedural macros on the host;
   - cache the target libraries under an identity that covers rustc,
     rust-src, the target JSON, the build-std set, and the features.
2. **The imager does not build for Motor.** This is a source problem, not a
   Lorry one:
   - it imports `async_fs::file_block_device`, which `async-fs` builds only
     when the target is not Motor;
   - its manifest takes Tokio from crates.io, not the Motor Tokio patch that
     `src/sys` uses.
3. **Admission state.** Only Lorry's own tree commits
   `.lorry/dependencies-v2.toml`. Each other root needs one networked
   `lorry vendor` and a review before offline native builds. A dry run should
   check that the largest graphs fit the download and extraction limits.
4. **Make still calls Cargo.** `DO_BUILD` and `DO_CLIPPY` in the root
   `Makefile` run `cargo build` and `cargo clippy`. Switching the in-scope
   recipes to Lorry also needs a test of parallel `make -j`, where several
   Lorry processes share `src/sys/target/lorry` and the global cache.

## Order

1. Prepare admission state for the ordinary packages and build them natively.
2. Fix the imager's Motor block device and Tokio source, then build and run
   it natively against the prebuilt payloads.
3. Add the custom target and build-std, and build the kernel natively.
4. Switch the in-scope Make recipes to Lorry and test parallel publication.

Lorry-only steps use focused contracts and `tests/test-all.sh`. A step that
changes Make, image contents, or another system component uses the gate of
that component.

## Decisions needed

- What portable name should admission use for a custom JSON target?
- Which Motor-capable file-backed block device should the imager use?
