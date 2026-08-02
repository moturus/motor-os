# Lorry Stage 2

Lorry is a small, strict Rust build, test, run, and dependency-vendoring tool.
It implements the audited Stage-2 Cargo subset summarized below; unsupported
semantics are rejected instead of being ignored.

The directly bootstrappable historical Stage-1 package shape was:

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

The historical dependency-free Stage-1 source supported a direct one-file
`rustc` bootstrap. The current Stage-2 source has reviewed registry
dependencies, so acceptance tests use an offline Cargo build as the initial
oracle executable. Native Motor test phases remain Cargo-free and use only the
staged Lorry executable.

Run the fast unit suite and the complete Linux Stage-1 acceptance gate with:

```sh
cargo test --locked
./tests/stage1-linux.sh
```

The repository integration entry point owns all Lorry host and native gates:

```sh
src/tests/lorry-integration-test.sh
```

`src/tests/full-test.sh` invokes its host and native phases transitively. The
gate also proves that pristine Rush and Red sources receive the Git-patch
diagnostic, are materialized by Linux `lorry vendor`, and then compile with
Lorry on Linux and Motor OS.

The public crates.io acquisition lane is intentionally opt-in:

```sh
LORRY_TEST_PUBLIC_CRATES_IO=1 ./tests/public-crates-io.sh
```

The dedicated patched-`cc` and patched-`ring` Motor provisioning lane is also
opt-in. It requires KVM and reserves localhost TCP port 10023 for its QEMU user
network. Its frozen minimal-image template is independent of the production
`src/imager/motor-os.yaml`; before acquisition, the lane diagnoses any missing
guest path whose expected filesystem role has changed:

```sh
LORRY_TEST_MOTOR_CRATES_IO=1 ./tests/motor-crates-io.sh
```

The deterministic Linux Lorry-to-Motor-curl contract gate is:

```sh
./tests/curl-contract-linux.sh
```

The native Motor OS gate is:

```sh
./test-native.sh --full
```

`test-native.sh --reuse-running-vm` runs the short smoke gate inside the VM
owned by `src/tests/full-test.sh`. Its Linux-to-Motor artifacts use the exact
Rust sysroot copied into that VM image so cross/native byte comparisons cannot
silently mix different installed standard libraries.

## Audited Stage-2 capability matrix

| Area | Supported in Stage 2 |
| --- | --- |
| Platforms | Native Linux and Motor OS; Linux and `x86_64-unknown-motor` targets; Cargo 1.97 and 1.98 compatibility families |
| Commands | `build`, `run`, `test`, and `vendor`; debug/release; installed target triples; test selection, no-run, and bundles |
| Package shape | One root package with at most one library and one binary; implicit or explicit targets; top-level `tests/*.rs`; editions 2015–2024; resolvers 1–3 |
| Dependencies | Locked crates.io and local-path graphs; renamed, optional, default-feature, forwarded-feature, and target-conditioned dependencies; exact required local `[patch.crates-io]` entries; Linux vendoring of root Git patches into local paths |
| Build scripts | Dependency build scripts and dependency-free root build scripts; explicitly admitted compiler and archiver roles |
| Repositories | Verified local/user/system immutable stores; transactional `vendor`; retained archive/source forms; seeded patched-`cc` and patched-`ring` objects |
| Outputs | Cargo-compatible compilation; content-addressed library cache; separate test harnesses; verified self-extracting test bundles |
| Security | Linux build scripts enforce network, filesystem, environment, and child-tool isolation; Motor prints an explicit warning and runs unsandboxed until the Stage-3 sandbox is implemented |

| Rejected or deferred | Required rewrite or status |
| --- | --- |
| Workspaces, upward discovery, `--manifest-path` | Run Lorry from a supported single-package root; workspace support is deferred |
| Multiple binaries, `--bin`, explicit `[[test]]`, examples, benches | Reduce the package to the supported targets; broader target declarations are deferred |
| Custom crate types, procedural macros, `harness`, `required-features`, `autobins`, `autotests`, `default-run` | Remove the unsupported build semantics; procedural macros and broader target metadata are deferred |
| Root build-dependencies or dev-dependencies | Keep root build scripts dependency-free and express test support through normal supported dependencies |
| Direct Git dependencies, alternative registries, artifact dependencies | Use crates.io/path dependencies; direct Git and general registry acquisition are deferred |
| Unmaterialized root Git patch during build/run/test | Run `lorry vendor` on Linux, review the pinned Git/source identities, then copy the vendored project and repository to Motor OS |
| CLI feature selection, custom profiles or JSON targets, multiple default targets | Use the locked default feature graph, dev/release profiles, and an installed single target |
| Cargo wrappers, `CARGO_TARGET_DIR`, `build.target-dir`, output relocation | Remove the setting; Lorry owns its compiler invocation and `target/lorry` output tree |
| General native-tool discovery or arbitrary build-script processes | Declare only policy-approved compiler/archiver roles; broader native tooling is deferred |
| Documentation tests | Reported as omitted because native Motor OS does not ship `rustdoc` |

Ordinary `test`, `--test NAME`, and `--no-run` build Cargo-compatible separate
harnesses. Explicit `test --bundle` packages the selected harnesses and any
required package binary into one verified, self-extracting target executable;
`--no-run` prints its deterministic path. Bundle arguments are forwarded to
every harness and failures are aggregated. The extraction cache location is
configured by the absolute `[test].extraction-root` path. Unix builds enforce
private file modes; platforms without Unix permission modes retain the
symlink, canonical-file-set, and content-integrity checks.

Stage 2 reuses verified library metadata and rlibs from the versioned
content-addressed cache below `target/lorry/.cache`. Every hit re-hashes its
canonical payload, while incomplete entries are ignored and corrupt entries
are quarantined. Build scripts still compile and run on every Lorry invocation,
and final programs and test harnesses always relink.

## Git-patch vendoring bridge

Build, run, and test remain offline and reject a root `[patch.crates-io]` Git
entry with an instruction to run `lorry vendor`. On Linux, that command uses
the installed `git` executable to fetch an anonymous canonical HTTPS URL. It
honors one optional `branch`, `tag`, or `rev`; preserves a matching full commit
already recorded in Cargo.lock; checks out the resolved commit privately; and
applies Lorry's normal source-tree limits. Before approval it reports the URL,
requested revision, resolved commit, Git tree, Lorry source SHA-256, file count,
and byte count.

Approval publishes `.lorry/vendor/<patch>/source`, records the evidence in the
adjacent `git.toml`, and rewrites only that manifest entry to an equivalent
local path patch. The normal vendoring phase then resolves Cargo.lock and
publishes the selected crates.io objects. If that later phase fails, the
reviewed Git materialization remains as a valid local path and rerunning
`lorry vendor` resumes ordinary registry vendoring.

The Linux Git child receives no ambient Git configuration, credentials, proxy
settings, or interactive prompt. Its combined output is limited to 8 MiB and
each command has a 300-second deadline. URLs containing credentials, query
strings, fragments, unsafe revisions, submodules represented as non-files, and
trees exceeding policy limits fail closed. Direct Git dependencies are not
part of this bridge.

Motor OS has no Stage-2 Git client. `lorry vendor` continues to handle
crates.io-only projects there, but returns an explicit not-supported error if
Git materialization is required. Run the command on Linux, then transfer both
the rewritten project tree and the Lorry repository containing its registry
objects. The integration gate follows exactly this workflow for Rush and Red;
Motor never contacts the forge or crates.io. Stage 3's planned `git-light`
binary will replace this compatibility bridge.
