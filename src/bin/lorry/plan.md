# Lorry Implementation Plan

Status: **Stage 2 in progress — core build, cache, bundle, registry
vendoring, and the Linux/Motor curl bootstrap cycles are implemented; only
final Stage-2 closure remains**

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
- Corrected sys-io's TCP-connect error propagation so an early reset is
  reported as not-connected while expiry of the requested deadline remains a
  timeout. This lets the native curl boundary distinguish required statuses 7
  and 28.
- Made shared IPC endpoints close when their owning process drops its last
  handle, independently of temporary kernel references. A native child-stdout
  fixture proves that dropping the parent reader wakes a blocked child writer
  with an error.

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

- Implemented and validated the external 44-object production seeder and the
  minimal patched-source seed. The buildable `cc 1.4.0` and `ring 0.17.14`
  objects are exact crates.io archives plus their reviewed Git blobs.
- Git cache objects are constructed, synced, and atomically published on the
  cache filesystem, independently of the seed destination's filesystem.
- Implemented a separate 16-package Cargo-oracle closure for inactive lockfile
  entries. These packages are checksum-verified and safely extracted only
  into an explicitly requested disposable oracle view; they do not enter the
  production repository, fingerprint, policy, or Motor image seed.
- Implemented the dedicated Motor minimal-seed image builder. It materializes
  a complete disposable imager scaffold, removes the copied full repository,
  installs and verifies the pinned `cc`-and-`ring` seed offline, and stages the
  ordinary VM scripts without changing shared generated roots or images.
- Motor prerequisites for SFTP/recursive staging, whole-file locking, and
  atomic no-replace publication are complete. Rustc's separate compiler lock
  abstraction now selects the Motor standard-library file-lock backend; a
  rebuilt release toolchain completed native Red dev/release builds and its
  72-test suite in the Stage-1 smoke gate.
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
  reviewed patched-source system seed, publishes the expected 13 registry
  objects without changing Cargo.lock, and proves a warm pass reuses every
  selected archive.

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
- Added deterministic certificate-hostname mismatch coverage to the same
  upstream Linux, Lorry-built Linux, and native Motor boundary.
- Closed the remaining selected-curl exit-code contract on upstream Linux,
  Lorry-built Linux, and native Motor: malformed URL 3, name resolution 6,
  connection failure 7, local write failure 23, timeout 28, TLS failure 35,
  and certificate verification 60. Motor curl writes transfer output through
  `moto_rt` so a closed pipe remains observable despite the current Rust
  standard-output compatibility hook.
- Proved exact body/control stream separation through that three-lane
  boundary: response bytes remain on stdout and the final nonce trailer remains
  on stderr.
- Checked the public lane's safe skip path into the default full-test entry
  point; setting `LORRY_TEST_PUBLIC_CRATES_IO=1` explicitly enables its public
  seed and acquisition traffic.
- Closed the Linux fresh-repository bootstrap cycle. The opt-in public lane
  builds curl from an upstream-curl-populated writable repository, uses that
  exact Lorry-built curl to populate a second repository from a separately
  installed patched-source seed, rebuilds from a clean source tree, and requires
  byte-identical release executables.
- Added direct Motor entropy and verified-HTTPS integration fixtures to the
  native gate. The cross-built curl test executable calls the registered
  Motor OS random source twice and completes a locally verified TLS transfer
  before Lorry's ten-case production request boundary runs through curl.
- Closed the Motor fresh-repository bootstrap cycle in a disposable
  minimal-seed image. Native Lorry acquires the exact reviewed 13-package
  registry graph, rebuilds curl using only that user repository plus system
  `cc` and `ring`, and produces the clean cross-build bytes. The entropy,
  verified-HTTPS, and ten-case request-boundary fixtures pass, and the
  recursively downloaded system repository retains its pinned minimal
  fingerprint.

## Remaining Stage-2 work

Complete these steps in order. Do not broaden a trust boundary, weaken a
sandbox, add retries/timeouts, or hide a failing fixture to advance the plan.

### Motor build-script sandbox — deferred to Stage 3

Stage 2 retains the explicit warning and permits native Motor build scripts to
run without isolation. They must not be described as sandboxed. Enforced
Motor network, filesystem, environment, and child-process isolation is now a
Stage-3 prerequisite; Linux continues to enforce and test the complete
sandbox contract.

### 2. Complete the curl bootstrap cycle — complete

- On Motor, use the Lorry-built curl to populate a second fresh writable
  repository starting from the minimal system `cc` and `ring` seed, then
  rebuild curl using only that repository plus the required system patches.
- Compare clean Cargo/Lorry Linux outputs and Linux-cross/native-Motor release
  outputs under the specification's identity rules.

#### Motor proof: resolved approach (reviewed 2026-07-29)

The earlier "proposal for review" text was reviewed against the actual seed
installer, imager, configuration, and test-lane code and replaced by this
plan. The verified evidence behind each requirement below is recorded in
`work-in-progress.md` ("Motor fresh-repository proof review").

Why a dedicated image is required: on Motor, `repositories.system` is owned
exclusively by the locked `/sys/tools/rust/cfg/lorry.toml` layer. No
command-line option, environment variable, user configuration, or project
configuration can override it today, and none may be added. The ordinary
image's system repository carries the full seed, whose objects would shadow
a fresh acquisition through the local → user → system lookup order. The
Motor proof therefore runs in a dedicated disposable image whose locked
system repository contains only the reviewed patched `cc` and `ring`.

All three bounded patches are complete. They keep the ordinary
debug/release images, the generated roots under `img_files/generated`, and
the shared full-seed VM untouched; must add no repository-override
mechanism. The Motor sandbox warning remains unchanged for its Stage-3 work.

##### Patch A: minimal-seed image builder — complete

`bootstrap/build_minimal_seed_image.py` creates an absent absolute scaffold
from hard links or copies, rejects links and missing imager inputs, deletes
the copied full vendor tree, and redirects every minimal offline installer
output into the scaffold. The builder passes its frozen
`bootstrap/minimal-seed-image.yaml` to the unchanged imager; it never reads
the production `src/imager/motor-os.yaml`, so unrelated image-program changes
cannot change this acceptance fixture. Before invoking the imager it requires
the pinned
`32f6225b7a324eba5c1d69e1db894634e231b95eabc116c19944073a30c8eefe`
fingerprint, no `objects/crates-io` entry, and the complete generated layout.
It then stages the ordinary VM scripts and sets `test.key` to mode `0400`.
The stale hand-maintained
`bootstrap/motor-system-lorry.toml` was removed; generated configuration
continues to come solely from `system-lorry.toml.in`.

##### Patch B: dedicated VM lane and guest configuration — complete

- Add an opt-in acceptance lane (suggested gate:
  `LORRY_TEST_MOTOR_CRATES_IO=1`) whose default non-networked skip path is
  wired transitively into `src/tests/full-test.sh` beside the Linux public
  lane.
- The lane boots the dedicated image through its own staged `run-qemu.sh`
  with the opt-in `MOTO_QEMU_USER_NET=1` mode. Normal VM runs remain on
  `moto-tap`; the acceptance lane instead binds its SSH forwarding only to
  localhost port 10023 and does not depend on mutable host firewall rules.
- Check live-lane prerequisites up front with an actionable message: KVM
  and exclusive use of localhost port 10023. No existing lane performs
  guest-to-internet traffic; this is the first, and it is the riskiest new
  capability in this work.
- Stage over SFTP, as the smoke gate does: the cross-built Lorry, the
  Lorry-built Motor curl (byte-identical to a native build under the
  closed identity gates), the reviewed CA bundle, and a clean curl plus
  `moto-rt` source tree.
- Write `/user/cfg/lorry.toml` over SFTP — the first provisioning of the
  Motor user layer — declaring exactly `repositories.user` (an absolute
  writable path under `/user`, non-nesting with the system repository) and
  `network.curl` (the staged Lorry-built curl), plus `network.ca-bundle`
  only if the lane's CA differs from the image default.
  `repositories.system` stays absent from user and project configuration;
  the system layer's lock already rejects any mention of it.
- Before acquisition, list the system repository in-guest and require
  exactly the seeded-git `cc` and `ring` objects and no `objects/crates-io`
  directory. The host-side fingerprint check in Patch A remains the
  authoritative identity verification.

The lane, pinned CA input, provisioning, exact patched-source repository check,
and production-contract request to public `index.crates.io` are implemented.
The public request succeeds through the lane's isolated QEMU user network.

##### Patch C: acquisition, rebuild, and live closure evidence complete

The first native `lorry vendor --accept-all` is implemented. The lane proves
the exact 13 registry identities derived from the reviewed curl Cargo.lock,
not merely their count, and requires unchanged lockfile bytes and empty
transaction staging. Lorry retains an open repository-header descriptor so
Linux can keep directory-local syncs while Motor uses its filesystem-wide
flush at the same pre- and post-rename durability barriers.

The generated Motor bootstrap configuration temporarily selects the existing
`/bin/cc` pass-through with no prefix arguments. This lets `cc` identify the
Clang family through its normal preprocessing probe; `cc` 1.4.0 currently
drops `CC` arguments from that probe and therefore cannot identify the
underlying LLVM multicall configured as `llvm clang`. Stage-3 sandbox design
must either model the immutable `/bin/cc` interpreter, underlying LLVM
executable, and resource directory or restore the exact
multicall-plus-prefix representation with a corrected `cc`.

The exact patched-`cc` 1.4.0 production graph passed the debug live lane.
Motor acquired its 13 registry packages, rebuilt release curl through
`/bin/cc` within the unchanged deadline, and produced bytes identical to the
clean Linux-to-Motor Lorry build. The production seed derives this object from
crates.io checksum `5add81bb...` plus `src/tempfile.rs` at reviewed
`moturus/cc-rs` commit `02932efc...`. Required-patch resolution, policy
revalidation, and cache keys hash complete immutable trees, including `cc`'s
legitimate `src/target` module; ordinary workspace paths retain their build
output exclusions.

The lane now rebuilds release curl natively using only the fresh user
repository plus system `cc` and `ring`, downloads it, and requires byte
identity with the clean Linux-to-Motor Lorry build. The existing entropy and
verified-HTTPS fixtures each pass one case, and the ten-case Lorry request
boundary passes through that freshly built curl. Finally, the lane re-lists
the system repository, recursively downloads it, rejects any crates.io
namespace, and verifies the pinned minimal-seed fingerprint host-side.

A live debug run passed this complete path on 2026-07-30. Three consecutive
repository-wide debug full-test runs and three release runs then passed the
default opt-in skip path and all ordinary acceptance gates.

### 3. Run final Stage-2 closure

The first post-merge release smoke run passed with the rebuilt toolchain and
the current `cc` seed provenance. It covered native Red and Rush dev/release
builds, Red's 72 tests, the standalone run fixture, entropy, verified HTTPS,
and the ten-case curl boundary. All 220 focused host tests, all 26 bootstrap
fixtures, and the consolidated offline host integration lane also pass. The
accumulated uncommitted changes are ready for review before rerunning the
complete closure matrices below.

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

Stage 2 is complete when the final closure above is green. The explicit Motor
sandbox warning and its deferred Stage-3 gate remain open by design.

## After Stage 2

After Stage-2 closure, first design and enforce the Motor build-script sandbox
while retaining the current warning until enforcement is complete. Workspaces,
`httpd-axum`, `russhd`, procedural macros, general Git acquisition, CLI feature
selection, and other deferred capabilities require separate reviewed plans
before code changes.
