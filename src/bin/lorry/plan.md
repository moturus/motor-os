# Lorry Implementation Plan

Status: **Stage 2 in progress — core build, cache, bundle, registry
vendoring, and Linux curl build paths are implemented; Motor sandboxing and
final curl closure remain**

`spec.md` is the authority for lasting product and technical requirements.
This document is the authoritative implementation resume point.
`work-in-progress.md` holds detailed evidence, measurements, investigations,
and superseded decisions that are useful while work remains but safe to
discard afterward.

## Document maintenance

Each new committed patch must update both `plan.md` and
`work-in-progress.md` appropriately to reflect the current state:

- update this file with concise completed work, the next actionable step, and
  any change to remaining acceptance work;
- update `work-in-progress.md` with the detailed implementation notes, test
  evidence, measurements, blockers, and temporary reasoning needed to resume
  or audit that patch.

Before committing, follow the repository-wide build, formatting, warning, and
three-pass debug/release `src/tests/full-test.sh` requirements in `AGENTS.md`.

## Completed work

### Stage 1

- Implemented the dependency-free bootstrap and the `build`, `run`, and
  `test` commands.
- Closed Linux-native, Linux-to-Motor, and native-Motor `red`, self-build, and
  Cargo 1.97/1.98 identity gates.
- Made the native `--full` harness preserve Lorry's repository-relative
  `moto-rt` path and compare native-Motor Lorry with a Linux-hosted Lorry
  cross-build. Cargo's cross-build is retained only as the bootstrap.
- Closed Motor prerequisites exposed by the full native Lorry workload:
  sys-io propagates storage-full errors, generated data partitions are 2 GiB,
  and scheduler watchdog/system-time intervals use calibrated durations
  instead of assuming a one-gigahertz TSC.

### Stage-2 foundations and build path

- Implemented the supported bounded Cargo.toml/config/lock/index/archive
  parsers, resolver 1/2/3 behavior, target/features/policy selection, required
  path-patch validation, and layered content-addressed repositories.
- Implemented dependency, host build-dependency, build-script, root library/
  binary, unit-test, and discovered integration-test unit graphs.
- Implemented Cargo-compatible identity, Linux build-script isolation,
  approved directive handling, root and dependency execution, and the `rush`
  acceptance surface, including `--test` and `--no-run`.
- Proved through the production dependency executor that a configured native
  tool receives neither its `CC_<target>` environment entry nor execute
  permission when the package policy does not grant that role. The same
  fixture proves the explicitly admitted rustc remains executable.
- Implemented the Stage-2 cache, test bundle, and core Lorry self-build path
  from the reviewed system seed.
- Implemented the reusable Rust source-remapping execution path. Planned units
  can carry distinct physical, absolute logical, and workspace-relative
  presentation roots; rustc receives the latter and dep-info validation maps
  it back to the verified physical tree.
- Bound normal repository crates.io sources to
  `.lorry/registry/sha256/<locked-checksum>/source` and required patches to
  their declared logical paths. Ordinary path dependencies use
  `.lorry/path/sha256/<source-tree-sha256>/source`. These presented paths feed
  both Cargo-compatible unit identity and rustc path remapping; conflicting
  mappings are rejected and `--use-cargo-registry` stays unmapped.
- Passed each source mapping only to an approved C compiler through
  `-ffile-prefix-map`; archivers and other native tools remain unchanged, and
  roots that cannot be represented safely are rejected.
- Normalized native Motor host-only compiler unit identity to the paired Linux
  Cargo host while retaining the real compiler, execution target, cache, and
  audit inputs.
- Preserved executable-bit distinctions through SFTP and guest `cp -r`
  staging. The release-VM `--full` gate proved two byte-identical native Lorry
  generations, byte-identical downstream `red`, both 66-test runs, and
  second-generation argument-preserving execution.

### Bootstrap and vendoring

- Implemented and validated the external 45-object production seeder and the
  minimal patched-`ring` seed. The buildable `ring` object is the exact
  crates.io 0.17.14 archive plus two reviewed Git blobs.
- Implemented a separate 16-package Cargo-oracle closure for inactive lockfile
  entries. These packages are checksum-verified and safely extracted only
  into an explicitly requested disposable oracle view; they do not enter the
  production repository, fingerprint, policy, or Motor image seed.
- Motor prerequisites for SFTP/recursive staging, whole-file locking, and
  atomic no-replace publication are complete.
- Implemented project locking, private transaction staging, bounded sparse
  record/archive downloads through direct curl, checksum/safe extraction,
  policy and approval, immutable no-replace publication, and lockfile-last
  commit.
- Added registry-transaction fixtures proving that abrupt interruption exposes
  no staged object, an already-staged competitor safely reuses an identical
  winner, and every object remains private when prepublication validation of
  any staged object fails.
- Implemented independent redirect trust with initially empty persistent
  allow/deny lists and operation-only or persistent decisions.
- Added an opt-in public crates.io lane for the real curl graph. It creates the
  reviewed ring-only system seed, publishes the expected 14 registry objects
  without changing Cargo.lock, and proves a warm pass reuses every selected
  archive.

### Curl and native tools

- Implemented target-specific compiler/archiver roles. Linux defaults to
  Clang and `ar`.
- Built the reviewed patched `ring` and `src/bin/curl` graph with Lorry on
  Linux.
- Implemented the independent Motor curl utility's required HTTPS/CLI subset
  and deterministic local TLS coverage. Lorry uses the same direct curl
  command/stream contract on Linux and Motor.
- Added a deterministic Lorry-level fixture that drives the production
  request path through upstream Linux curl and a verified local TLS server.
  It covers successful and redirect response metadata, certificate rejection,
  malformed and truncated HTTP, and Lorry's body limit. The complete Lorry
  unit suite now runs transitively from the repository full-test entry point.
- Added a deterministic Linux acceptance lane that creates an isolated copy
  of the reviewed full seed, builds Motor curl with Lorry without network
  access or lockfile changes, and reruns the production request fixture
  through that exact executable.
- Made the TLS-server half of that fixture target-native. Curl's Lorry-built
  Rust integration-test executable can serve each scenario as an explicit
  one-shot child, and the Linux acceptance lane proves Lorry can coordinate
  that server without Python.
- Closed the corresponding native-Motor lane. The smoke gate installs an
  isolated reviewed host seed, cross-builds the Lorry test harness, Motor curl,
  and its Rust TLS server with Lorry, stages them and the reviewed CA through
  SFTP, and requires all five production TLS/error cases to pass in the VM.
  Three debug and three release full-test runs passed under the unchanged
  repository deadline, including recursive-copy staging and all native gates.
- Completed the granted Clang resource closure needed by that cross-build:
  only its canonical sibling `lib` resource tree and configured absolute
  `--sysroot` are added read-only, and an ungranted compiler exposes neither.
- Added chunked and connection-close response framing to the same selected-curl
  TLS boundary on upstream Linux, Lorry-built Linux, and native Motor curl.
- Added total-transfer and low-speed stall timeout cases to that boundary;
  both implementations must exit with curl status 28.
- Checked the public lane's safe skip path into the default full-test entry
  point; setting `LORRY_TEST_PUBLIC_CRATES_IO=1` explicitly enables its public
  seed and acquisition traffic.

## Remaining Stage-2 work

Complete these steps in order. Do not broaden a trust boundary, weaken a
sandbox, add retries/timeouts, or hide a failing fixture to advance the plan.

### 1. Close registry acquisition fixtures

- Complete the remaining hostname, stream, and exit-code cases required by
  `curl-interaction.md` on both implementations.

This is the immediate resume point.

### 2. Enforce the Motor build-script sandbox

Replace the explicit Motor warning stub with real isolation. Run the same
observable network, filesystem, environment, and child-process denial
fixtures used for the Linux contract.

External Gate 11 remains mandatory. Stage 2 cannot close and native Motor
build scripts cannot be described as sandboxed until this gate passes.

### 3. Complete the curl bootstrap cycle

- Build patched `ring` and curl for Linux-to-Motor and native Motor.
- Run Motor entropy and verified-HTTPS fixtures.
- On Linux and Motor, use the Lorry-built curl to populate a second fresh
  writable repository starting from the minimal system `ring` seed.
- Rebuild curl using only that repository plus the required system `ring`.
- Compare clean Cargo/Lorry Linux outputs and Linux-cross/native-Motor release
  outputs under the specification's identity rules.

### 4. Run final Stage-2 closure

- Run pristine debug and release suites, Cargo 1.97/1.98 identity fixtures,
  `red`, `rush`, Lorry self-build, and curl self-build matrices.
- Run cold, warm, invalidated, and corrupt-cache coverage.
- Run fresh, warm, interrupted, declined, corrupt, and concurrent vendoring
  coverage.
- Run Linux-native, Linux-to-Motor, native-Motor, smoke, and `--full`
  acceptance lanes, including the repository-wide three-pass test rule.
- Audit every pinned input, checksum, feature, license, patch, native tool,
  manifest, config, seed, and oracle fixture.
- Document each rejected Cargo capability with its actionable diagnostic and
  publish the Stage-2 support matrix.

Stage 2 is complete only when all four remaining steps and Gate 11 are green.

## After Stage 2

Reopen Stage-3 design only after Stage-2 closure. Workspaces, `httpd-axum`,
`russhd`, procedural macros, general Git acquisition, CLI feature selection,
and other deferred capabilities require separate reviewed plans before code
changes.
