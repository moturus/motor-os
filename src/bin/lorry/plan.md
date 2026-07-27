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
- Implemented the Stage-2 cache, test bundle, and core Lorry self-build path
  from the reviewed system seed.

### Bootstrap and vendoring

- Implemented and validated the external 45-object production seeder and the
  minimal patched-`ring` seed. The buildable `ring` object is the exact
  crates.io 0.17.14 archive plus two reviewed Git blobs.
- Classified the 16 inactive lockfile packages needed by Cargo oracles as a
  separate manifest set. They are excluded from the production repository,
  fingerprint, policy, and Motor image seed.
- Motor prerequisites for SFTP/recursive staging, whole-file locking, and
  atomic no-replace publication are complete.
- Implemented project locking, private transaction staging, bounded sparse
  record/archive downloads through direct curl, checksum/safe extraction,
  policy and approval, immutable no-replace publication, and lockfile-last
  commit.
- Implemented independent redirect trust with initially empty persistent
  allow/deny lists and operation-only or persistent decisions.
- Verified fresh public crates.io acquisition from the minimal seed and a warm
  no-fetch reuse pass.

### Curl and native tools

- Implemented target-specific compiler/archiver roles. Linux defaults to
  Clang and `ar`.
- Built the reviewed patched `ring` and `src/bin/curl` graph with Lorry on
  Linux.
- Implemented the independent Motor curl utility's required HTTPS/CLI subset
  and deterministic local TLS coverage. Lorry uses the same direct curl
  command/stream contract on Linux and Motor.

## Remaining Stage-2 work

Complete these steps in order. Do not broaden a trust boundary, weaken a
sandbox, add retries/timeouts, or hide a failing fixture to advance the plan.

### 1. Complete the Linux curl identity oracle

Safely extract the separate checksum-pinned lock-only packages into an
explicitly requested disposable Cargo oracle view. Do not install them in a
Lorry repository or include them in production fingerprints, generated
policy, or Motor images. Then finish the Clang/`ar` Cargo-versus-Lorry Linux
release comparison.

This is the immediate resume point.

### 2. Close registry acquisition fixtures

- Finish Lorry-level deterministic TLS and error fixtures for the exact
  `curl-interaction.md` contract.
- Add interruption, competing publication, and all-or-none registry
  transaction fixtures.
- Turn the successful public crates.io acquisition into the planned opt-in
  acceptance lane.
- Prove that build scripts cannot execute undeclared native child tools.

### 3. Enforce the Motor build-script sandbox

Replace the explicit Motor warning stub with real isolation. Run the same
observable network, filesystem, environment, and child-process denial
fixtures used for the Linux contract.

External Gate 11 remains mandatory. Stage 2 cannot close and native Motor
build scripts cannot be described as sandboxed until this gate passes.

### 4. Complete the curl bootstrap cycle

- Build patched `ring` and curl for Linux-to-Motor and native Motor.
- Run Motor entropy and verified-HTTPS fixtures.
- On Linux and Motor, use the Lorry-built curl to populate a second fresh
  writable repository starting from the minimal system `ring` seed.
- Rebuild curl using only that repository plus the required system `ring`.
- Compare clean Cargo/Lorry Linux outputs and Linux-cross/native-Motor release
  outputs under the specification's identity rules.

### 5. Run final Stage-2 closure

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

Stage 2 is complete only when all five remaining steps and Gate 11 are green.

## After Stage 2

Reopen Stage-3 design only after Stage-2 closure. Workspaces, `httpd-axum`,
`russhd`, procedural macros, general Git acquisition, CLI feature selection,
and other deferred capabilities require separate reviewed plans before code
changes.
