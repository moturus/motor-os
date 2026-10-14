# Native Helix builds on Motor OS

Status: implemented and lightly tested; full developer-image gate awaits push.

## Outcome

The Motor Helix branch must build and run inside the developer image with:

```sh
lorry vendor --accept-all
lorry build --release
```

Exclude the Git backend and its optional dependency on Motor, preserving Git
support elsewhere. Make two local commits with one-line messages: Motor OS/Lorry
and the separate Helix repository. The user will publish Helix.

## Diagnosis

- The guest compiler correctly reports `x86_64-unknown-motor`.
- The reproduced failure occurs while linking `helix-term/build.rs`. Its
  `helix-loader` build dependency links the static grammars, including a C++
  scanner. The command includes `-lc++`, but rustc's default link disables the
  system runtime libraries. `__gxx_personality_v0` remains undefined.
- Replaying that exact compiler invocation in a temporary output directory
  succeeds with `-C link-self-contained=no -C default-linker-libraries=yes`.
  These are the documented Motor flags for opting into the C runtime.
- `engine.rs` supplies a logical Motor target even when no target was selected.
  `unit.rs` also uses that logical target to exclude Rust flags from host units.
  Consequently native build scripts and their dependencies miss configured
  flags. The failed host command also omits Helix's existing `tokio_unstable` flag.
- The image producer currently builds Helix through `motor-rust-cc`, which
  unconditionally adds the startup object and runtime libraries. That masks
  Helix's missing runtime configuration during cross-compilation.

Original evidence: `/tmp/helix-native-link-original.log` and
`/tmp/helix-link-probe.log` on the host. The native build now passes with both
patches applied, including the originally failing build-script link.

## Proposed patches

1. **Lorry native Rust flags and regression coverage.** Separate actual target
   selection from the logical target used for Motor artifact identity. Without
   a CLI/configured target, apply the effective Rust flags to native host units
   as Cargo does. Preserve explicit-target flag isolation and Motor's logical
   target identity. Cover compiler arguments, build-script flag environment,
   cache identity, and a native build script depending on C++ code. Keep tests
   below `src/bin/lorry/tests` and invoke them through the Lorry suite.
2. **Helix runtime configuration and the producer.** This explicitly modifies
   the separate repository `/home/posk/motor-dev/helix`, outside Motor OS:
   add the two runtime flags under a Motor target selector in its
   `.cargo/config.toml`, preserving existing flags, and document native builds.
   Gate the optional `gix` dependency and Git code on non-Motor targets so the
   default build needs no feature flags. Apply the same changes to `/user/helix`
   in the running VM.
   In Motor OS's `src/build-motor-os.sh`, switch Helix from `motor-rust-cc`
   to `motor-clang`, which honors the runtime flags without duplicating the
   startup object. Do not modify the toolchain, Rust std, or moto-rt.

Native host flags affect host-unit identities. They must remain compiler/cache
inputs; do not hide those differences to force an identity check to pass.
Preserve the required Cargo/cross/native release comparisons for equivalent
inputs, and investigate any changed comparison before adjusting a fixture.

## Validation

- Run focused Lorry flag regressions and validate the native C++ link through
  Helix. The user explicitly requested light testing before the two commits.
- Format Rust changes with the repository-selected toolchain.
- Rebuild Helix natively, offline, through the fixed Lorry. Check `hx --version`
  and grammar health, including grammars using C++ scanners. Confirm a warm
  build succeeds and exercise an actual edit/save in the native binary.
- After the user pushes Helix, run `src/tests/full-test-dev.sh --release`.
  Per the user's instructions, defer the full suite until then; no 3+3 core OS
  gate is required because `src/sys` is unchanged.
- Diagnose further failures and fix clear issues within this build path.
  Stop for review if the scope grows or a non-obvious choice is required.

The user approved this plan with Motor-specific Git gating and the staged
validation/commit workflow above. The full developer-image suite remains
pending the user's Helix push.

## Focused results

- Passed native flag/identity/environment, compiler, and freshness regressions;
  Cargo Rust flag and member C++ contracts; formatting and warning-free Clippy.
- Cargo's Motor dependency tree excludes Git; its Linux tree retains Git.
- Plain native `lorry build --release` passes from clean artifacts and warm
  without recompilation. `hx --version`, C++ grammar health, all eleven grammar
  parser fixtures, and an interactive SSH edit/save pass.
- An attempted SFTP executable overwrite changed Lorry's timestamp but not its
  bytes, invalidating its metadata-based cache. The extra generation exhausted
  the 4 GiB guest disk during follow-up checks. Clearing generated caches and
  installing by rename resolved that setup failure; the final clean build,
  warm build, and grammar tests passed with the unchanged final executable.
