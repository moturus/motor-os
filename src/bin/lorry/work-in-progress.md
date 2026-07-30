# Lorry Work in Progress

Status: **Working notes and historical evidence for Stage 2**

This file retains the detailed research, decisions, measurements, closure
evidence, and superseded checkpoints from the original combined design and
implementation plan. It is intentionally non-authoritative: durable product
requirements belong in `spec.md`, and the current implementation state and
next steps belong in `plan.md`. If this file conflicts with either document,
those documents win.

The details here may help diagnose or resume unfinished work, but they are
safe to discard after the work they describe is complete and all lasting
requirements have been incorporated into `spec.md`.

## Document maintenance

Each new committed patch must update both `plan.md` and
`work-in-progress.md` appropriately to reflect the current state. Keep
`plan.md` concise and current; put test output, investigation notes,
temporary blockers, measurements, and other disposable detail here.

## Dedicated minimal-seed image builder (2026-07-29)

Patch A of the reviewed Motor fresh-repository proof is implemented in
`bootstrap/build_minimal_seed_image.py`. The host script requires a fresh
absolute scaffold path and an already-built debug or release imager. It
materializes the selected binary directory and all three production static
roots with hard links, falling back to copies only when the filesystem cannot
link. It rejects missing binaries, links, and special files before imaging;
a fixture also keeps its binary list synchronized with every `input_files`
entry in `motor-os.yaml`.

The copied `sys/tools/rust/lorry/vendor` tree is deleted before the existing
installer runs in minimal offline mode. Every installer destination, including
the otherwise mandatory host repository/configuration outputs, is beneath the
scaffold; only the shared reviewed download cache is read. Before imaging the
builder requires the exact minimal fingerprint
`806048f5035adac8409ae7a52eaab26dfa6ce930768da883d33cdb7dc207e1a7`,
the complete imager layout, the generated Motor configuration, and no
`objects/crates-io` path. It invokes the existing imager unchanged, copies the
ordinary VM scripts, and applies the Makefile's `0400` mode to `test.key`.

A production debug smoke run created a 2,155,634,176-byte image from the
offline cache. Its repository had the pinned minimal fingerprint and no
crates.io namespace. The ordinary generated repository remained at the full
production fingerprint
`0f12be3e526e48aee5aa6fb761cadc43ffa1a8f5498e19384c113d7d5f5a0bcd`
with its crates.io objects present. The 2.9 GiB disposable scaffold was then
removed; the ordinary debug/release images and generated roots were not
changed.

Five new focused fixtures and the complete 23-test bootstrap suite pass.
Python byte-compilation and `git diff --check` pass. The stale unreferenced
`bootstrap/motor-system-lorry.toml`, whose old ring tree digest disagreed with
the active seed manifest, is removed. Generated Motor configuration continues
to come solely from `system-lorry.toml.in`. Patch B, the opt-in dedicated VM
lane and guest user configuration, is the next curl-closure increment.

The exact patch passed `src/tests/full-test.sh` three consecutive times in
debug mode and `src/tests/full-test.sh --release` three consecutive times.
Every pass included all 214 Lorry tests, the 20-test Lorry-built Linux curl
contract, the public lane's default non-networked skip, all 23 bootstrap
fixtures, all 66 native `red` tests, and the ten native Lorry request-boundary
tests through Motor curl. Debug native phases were 147.410--148.406 seconds;
release native phases were 31.788--32.314 seconds. The only displayed
non-package diagnostic was OpenSSH's existing post-quantum key-exchange
notice.

## Motor fresh-repository proof review (2026-07-29)

The step-2 "proposal for review" previously recorded in `plan.md` was
reviewed against the actual seed installer, imager, configuration, and
test-lane code, then replaced by the resolved three-patch approach now in
`plan.md`. The strategy — a dedicated ring-only image, no override
mechanisms, a dedicated VM — was confirmed correct and is the only approach
consistent with the locked Motor configuration model. The mechanics as
originally written were not implementable; this section records the verified
facts behind each correction so the implementer does not rediscover them.

### Why a dedicated image (verified)

- `repositories.system` is accepted only from the `LinuxBase` or
  `MotorSystem` configuration layers (`src/config.rs`,
  `merge_repositories`); a user or project file that sets it is a hard
  error, and the generated Motor system configuration additionally locks it
  through `[system-constraints]`. The CLI has no configuration options and
  `reject_environment` leaves no production environment override. On Motor
  the no-override property is therefore already structurally true and needs
  no code change; the plan's constraint only forbids adding a bypass.
- On Linux, by design, the single `$HOME/.config/lorry/lorry.toml` base
  layer owns `repositories.system`, which is exactly how
  `tests/public-crates-io.sh` relocates the system repository with a
  disposable `HOME`. The no-override invariant is Motor-only.
- The ordinary image's system repository currently contains all 45 seeded
  crates.io objects; through the local → user → system lookup order they
  would shadow any fresh-acquisition proof run on the normal image.

### Seed installer facts

- `bootstrap/install_stage2_seed.py` supports `--mode minimal --offline`
  and retargetable `--image-repository`/`--motor-config`, but has no
  image-only mode: `main()` always seeds `--build-repository`, installs a
  host repository, writes or validates a host configuration, and requires
  host/image fingerprint equality. Lanes must redirect every host
  destination to throwaways (the existing pattern in
  `tests/public-crates-io.sh` and `test-native.sh`).
- `install_repository_copy` merges into an existing destination, and
  minimal-mode verification iterates an empty registry selection, so
  leftover crates.io objects in a stale destination are invisible to every
  check. Deleting the copied vendor tree before seeding is required for
  correctness, not hygiene.
- `render_system_config` ignores the mode: the minimal and full generated
  Motor configurations are byte-identical (both carry all registry policy
  rules and the locked-key list). The original proposal's "remove the
  generated Lorry configuration" step was cosmetic.
- The generated Motor system configuration declares no `repositories.user`,
  so no native `lorry vendor` has ever been runnable on Motor. The new lane
  is the first native vendoring run.
- Housekeeping: `bootstrap/motor-system-lorry.toml` is referenced by
  nothing (the installer renders from `system-lorry.toml.in`) and pins a
  ring `source-tree-sha256` that disagrees with `stage2-seed.toml`. It
  misled this review once; delete or regenerate it in the next
  bootstrap-touching patch.

### Imager facts

- The imager accepts exactly `imager <motorh> <debug|release> <yaml>` and
  derives everything from `<motorh>`: binaries from `build/bin/<mode>`,
  `static_dirs` resolved relative to that root, and output hardwired to
  `<motorh>/vm_images/<mode>/motor-os.img`. Invoking it "against a copied
  rustc root", as the original proposal said, was not implementable; the
  resolved approach builds a full MOTORH-shaped scaffold instead, which
  needs no imager change and cannot clobber the ordinary images.
- `add_static_dir` classifies entries with a non-following `file_type()`,
  so symlinked files or subdirectories inside a static root are silently
  dropped; scaffolds must use copies or hard links. A missing static root
  is only logged, so the lane must assert the scaffold layout itself.
- The Makefile `img` target, not the imager, creates `vm_images/<mode>`,
  stages `src/vm_scripts/*` (including `run-qemu.sh` and `test.key`), and
  fixes the key permissions; the scaffold flow must replicate this.
- `img_files/generated/rustc` is about 255 MiB and
  `img_files/generated/llvm` about 139 MiB, so plain copies are cheap.
  `reflink` appears nowhere in the tree and the development checkout is on
  ext4, which has no reflink support; hard links or copies are the
  mechanism, and the original "reflink may optimize" note is moot.

### Guest and lane facts

- `/user/cfg/lorry.toml` is read as the `MotorUser` layer and may own
  `repositories.user`; `network.curl` and `network.ca-bundle` are accepted
  from any layer and are not in the generated locked list. Nothing in the
  tree creates this file today (`img_files/motor-os/user/cfg/` holds only
  `red.toml` and `rush.toml`), so provisioning it is a new capability, not
  an existing one.
- No existing lane performs guest-to-internet traffic. `run-qemu.sh`
  hardcodes the `moto-tap` interface, the guest MAC, and `192.168.4.2`;
  tests reach the guest over SSH at that address. Live crates.io access
  from the guest requires host NAT/forwarding, and a second concurrent VM
  would need new tap/MAC/IP plumbing — the resolved approach runs the
  dedicated VM serially instead and pre-checks reachability with a skip.
- Repository fingerprinting is host-side Python; the guest lanes use only
  `cp`/`mkdir`/`rm`/`echo` and SFTP, and the image has no `find` or
  hashing utility in use. In-guest repository checks are therefore cheap
  listings, with authoritative verification done host-side before imaging
  and, after acquisition, on the downloaded ring-only system repository.
- The Linux lane's "14 registry objects" is a Linux-measured value. The
  vendor target union includes the host triple, so the Linux lane resolves
  {linux-gnu, linux-musl, motor} while a native run resolves
  {linux-musl, motor}. Curl's only target-conditional dependency is the
  `moto-rt` path dependency, so the identity sets are expected to match,
  but the lane must assert the exact identities derived from the reviewed
  Cargo.lock rather than assume the count.
- The staged Lorry-built Motor curl (cross-built on Linux) performs the
  acquisition. The closed identity gates make it byte-identical to a
  native-built curl, so the bootstrap-cycle claim is unaffected by where
  it was compiled.

### Superseded proposal text

The original proposal paragraphs are superseded by the resolved approach in
`plan.md`. Summary of corrections: the imager cannot consume a bare
rustc-root copy and its output location is fixed by its root argument; the
seed installer cannot run image-only; removing the generated configuration
was a no-op while removing the old vendor tree is load-bearing; the Motor
user layer, guest internet access, guest-side repository verification, and
the first native vendor run are new capabilities rather than existing ones;
and the no-override constraint was already structurally enforced on Motor
while deliberately never holding on Linux.

## Linux curl bootstrap cycle (2026-07-29)

The opt-in public crates.io lane now completes the Linux half of the required
fresh-repository bootstrap cycle. It first uses upstream curl to populate 14
selected registry objects alongside a separately installed minimal system
`ring` seed, verifies warm archive reuse, and builds release Motor curl with
Lorry. It then installs another minimal seed and empty writable repository,
configures the first Lorry-built curl as Lorry's exact transport, and repeats
fresh public vendoring from a clean curl source tree.

The second transaction published the same 14 content-addressed identities,
left its system seed free of registry objects and private transaction staging
empty, and preserved the reviewed Cargo.lock. Lorry rebuilt curl using only
that second writable repository plus its required system `ring`; the two
clean-source release executables were byte-identical.

`bash -n`, `git diff --check`, and the default non-networked skip path pass.
The live `LORRY_TEST_PUBLIC_CRATES_IO=1` lane also passes against the pinned
ring source and public crates.io. Both curl builds emitted only the tolerated
warnings from the external patched `ring` package; core Motor OS code emitted
no new warning.

The complete host-side Lorry/curl matrix passed three consecutive times in
both debug and release modes. Each pass ran all 214 Lorry tests, all 20 tests
through a freshly Lorry-built Linux curl, and the public lane's default skip
path. `make -j16 BUILD=release` also passes.

After KVM access became available, `src/tests/full-test.sh` and
`src/tests/full-test.sh --release` each passed three consecutive times. Every
run included the host checks above, the Motor VM suite, all 18 Stage 2 seed
fixture tests, 66 native `red` tests, and 10 Lorry request-boundary tests
through the Lorry-built Motor curl. The only warnings were the already
tolerated lifetime diagnostics from the external patched `ring` package.

The next bounded increment makes the Motor entropy/HTTPS acceptance evidence
direct. Curl's target-native integration executable accepts an explicit
fixture directory, calls the registered `getrandom` source twice, rejects an
unchanged or repeated 64-byte result, and completes a verified local TLS
transfer. The native smoke gate runs both exact tests before its existing
ten-case Lorry request-boundary suite. This does not change or claim the
external Motor build-script sandbox gate.

The final state passed three consecutive `src/tests/full-test.sh` runs and
three consecutive `src/tests/full-test.sh --release` runs. Every pass included
all 214 Lorry tests, 20 Linux selected-curl contract tests, the Motor VM suite,
18 seed fixture tests, 66 native `red` tests, both exact entropy/HTTPS tests,
and the ten native Lorry request-boundary tests.

## Native self-build workload investigation (2026-07-27)

The full Motor-native gate copied `src/bin/lorry` to a standalone directory,
so its `../../sys/lib/moto-rt` manifest dependency resolved outside the staged
tree and failed with `NotFound`. The harness now stages a minimal tree
containing both `src/bin/lorry` and `src/sys/lib/moto-rt`, and clones that
tree for each native self-build generation. This preserves the reviewed
manifest path without rewriting package inputs.

The first debug `--full` validation passed repository and path resolution and
began the first native Lorry build, then the guest kernel declared CPU 3 dead
and panicked from `src/sys/kernel/src/sched/scheduler.rs:288`. SSH consequently
failed with status 255. Evidence is retained under
`target/lorry/native-tests/stage1-20260727T175610Z-71169`; the QEMU log shows
the watchdog panic at guest time 529 seconds while rustc was producing
`serde_core` build-script metadata.

The first complete native generation then exposed an oracle-boundary error:
Cargo's Linux-to-Motor output contains Cargo-registry absolute source paths,
while the native Lorry build presents repository sources through a different
physical repository. The native identity requirement compares Linux-hosted
Lorry cross output with native-Motor Lorry output, so the harness keeps the
Cargo cross build only as the bootstrap and produces the expected artifact
with hosted Lorry. It also uses the system configuration through its normal
host layer instead of copying it into a project-owned configuration layer.

The large compile first filled the former 512 MiB data partition. Sys-io now
maps `std::io::ErrorKind::StorageFull` to `moto_rt::Error::StorageFull`
(`bf058e27`), and generated data partitions are now 2 GiB (`1393cf0e`). The
next full run had no storage error but reproduced the scheduler watchdog on
CPU 1 at guest time 516 seconds; evidence is under
`target/lorry/native-tests/stage1-20260727T215139Z-128178`.

The watchdog called its threshold ten seconds but compared raw TSC values
against a fixed 10,000,000,000 ticks. On the 2.3 GHz validation host that is
about 4.3 seconds. The scheduler fix expresses both that threshold and its
one-second system-time interval as calibrated `Duration` values.

With that fix, the first native Lorry generation completed without a
watchdog or storage failure. The run reached the corrected identity oracle and
showed the next remapping requirement: hosted Lorry embeds
`/home/posk/.config/lorry/system/vendor/...` registry source paths, while
native Lorry embeds `/sys/tools/rust/lorry/vendor/...`. Evidence is under
`target/lorry/native-tests/stage1-20260727T223005Z-136169`. Ordinary immutable
registry sources therefore need the same host-independent source presentation
principle as required patches, with a distinct stable logical namespace.

The scheduler patch passed `src/tests/full-test.sh` three consecutive times
with the debug image and `src/tests/full-test.sh --release` three consecutive
times with the release image. Every run included the native Lorry smoke gate.
The earlier full native run also exercised the debug watchdog through an
entire first-generation Lorry release build.

The first remapped full-gate comparison still differed only for `moto-rt`.
The hosted source-tree digest was
`e535...`, while the SFTP-staged tree was `403d...`; inspection showed that
every uploaded source file had become executable. Russhd now applies requested
SFTP permissions (`25d94d5c`). A direct guest fixture then isolated a second
mutation: `cp -r` changed a source mode of 666 to 777. Sysbox now preserves
source permissions for files and recursive directories (`87dd2abb`).

With those transport fixes, ordinary path dependencies are presented as
`.lorry/path/sha256/<source-tree-sha256>/source`, in addition to the registry
and required-patch namespaces. Unit identity and rustc use the same presented
root. Approved C compilers alone receive the corresponding
`-ffile-prefix-map`; native Motor host units use the paired Linux host only
inside Cargo identity.

The debug-VM full gate then passed generation 1 identity but exhausted the
unchanged 1800-second shared phase deadline during a healthy generation 2
compile. QEMU evidence showed generation 1 progressing from guest time 135s
to 1121s and generation 2 progressing from 1128s until the deadline, with no
watchdog recurrence or stall. The unchanged release-VM gate completed in
416434ms. Evidence is retained under
`target/lorry/native-tests/stage1-20260728T150331Z-346239`; both Lorry
generations have SHA-256
`716050f19ef973d576114142faf5d657dce094025ad44405b813ee6a07e34477`,
and native plus second-generation `red` have
`269ad30160d734df3adf83e7f19ef9931c92e01ca347e7a216815f6a04a6a29d`.
Both 66-test runs and the second-generation argument-forwarding run passed.
All 200 focused Lorry tests pass. The completed remapping patch also passed
`src/tests/full-test.sh` three consecutive times in debug mode and
`src/tests/full-test.sh --release` three consecutive times; every run included
the Motor-native Lorry smoke gate and the permission-preserving staging
fixture, with no watchdog recurrence.

## Registry transaction fixture closure (2026-07-28)

The repository transaction now has focused coverage for each remaining
publication state without changing the production transaction design:

- An independently staged transaction publishes first; the stale competitor
  then verifies and reuses the immutable winner, proving the destination need
  not have existed when the competitor was staged.
- A child process is killed after it has checksum-verified and extracted a
  registry object. The interrupted process leaves only its private
  `.staging` directory and exposes no content-addressed object.
- A two-object transaction has its second staged index record modified before
  publication. The complete validation pass fails and drops staging before
  either object is moved into the visible repository.

All 203 focused Lorry tests pass with these cases. The remaining registry
fixture work is the Lorry-level deterministic TLS/error contract, the opt-in
public crates.io lane, and undeclared native-child-tool denial. The exact
patch also passed `src/tests/full-test.sh` three consecutive times in debug
mode and `src/tests/full-test.sh --release` three consecutive times. Every run
included permission-preserving SFTP/`cp -r`, Stage-2 seed verification, the
Motor-native Lorry smoke gate, and all 66 native `red` tests; no kernel
watchdog recurred.

## Lorry-to-curl TLS fixture (2026-07-28)

Lorry's production `request()` path now has a deterministic local TLS fixture.
The fixture reuses curl's checked-in test CA, server certificate, and key, and
uses a Python standard-library server so it does not add a TLS implementation
to Lorry's frozen dependency graph. Upstream Linux curl is invoked with the
exact production argument vector and cleared environment.

The focused cases prove verified status-200 body and trailer handling, 302
metadata, untrusted-certificate failure, malformed HTTP failure, declared-body
truncation failure, and Lorry-side body-limit termination. The negative cases
are separate tests so a preconnection setup defect identifies the exact
scenario; this exposed and corrected an initially shallow test-CA path instead
of concealing the waiting server.

All 208 Lorry tests pass. `src/tests/full-test.sh` now runs that complete suite
directly in the selected debug or release profile, so these loopback TLS cases
and all future Lorry unit fixtures are transitively part of the repository
gate. Remaining curl-contract work is to run this boundary against the
Lorry-built Linux and native Motor curl and add the remaining framing,
stall/timeout, hostname, stream, and exit-code cases.

The exact patch passed `src/tests/full-test.sh` three consecutive times in
debug mode and `src/tests/full-test.sh --release` three consecutive times.
Every run included the 208-test Lorry suite, permission-preserving
SFTP/`cp -r`, Stage-2 seed verification, the Motor-native Lorry smoke gate,
and all 66 native `red` tests. The kernel watchdog did not recur.

## Public crates.io acceptance lane (2026-07-28)

`tests/public-crates-io.sh` now packages the previously manual fresh
acquisition as an explicit `LORRY_TEST_PUBLIC_CRATES_IO=1` lane. It builds
Lorry offline, creates the reviewed ring-only system seed in disposable
locations, stages the real curl and `moto-rt` source shape, and runs
`lorry vendor --accept-all` with isolated HOME and Cargo state.

The fresh run acquired and published the expected 14 selected curl registry
objects, retained an unchanged reviewed Cargo.lock, left transaction staging
empty, and kept the system seed free of registry objects. The warm run uses a
logging curl wrapper and rejects any `static.crates.io` archive request or
change to the object set. Sparse metadata requests for inactive lockfile nodes
remain permitted because those records are not published as selected
repository objects.

The default repository full-test invokes the lane's non-networked skip path.
Public seed and acquisition traffic occur only for the exact opt-in value
above. The live opt-in lane passes against public crates.io and the pinned
ring source.

The exact patch then passed three consecutive debug and three consecutive
release `src/tests/full-test.sh` runs. Every run included the 208-test Lorry
suite, the safe public-lane skip, permission-preserving SFTP/`cp -r`, Stage-2
seed verification, the Motor-native Lorry smoke gate, and all 66 native `red`
tests. The kernel watchdog did not recur.

## Undeclared native child-tool proof (2026-07-28)

The production dependency-executor fixture now configures `/bin/true` as the
host target's C compiler while leaving the dependency's native-tool grant
empty. Its real compiled build script verifies that `CC_<target>` is absent
and an exact `/bin/true` child launch is denied by Landlock. The same script
successfully launches the explicitly admitted rustc, so the case distinguishes
selective executable admission from a sandbox that simply denies every child.

The focused production-path test passes. The exact patch then passed three
consecutive debug and three consecutive release `src/tests/full-test.sh`
runs. Every run included all 208 Lorry tests, the safe public-lane skip,
permission-preserving SFTP/`cp -r`, Stage-2 seed verification, the
Motor-native Lorry smoke gate, and all 66 native `red` tests. The kernel
watchdog did not recur.

## Lorry-built Linux curl contract (2026-07-28)

`tests/curl-contract-linux.sh` creates disposable host/image repositories from
the complete reviewed seed in offline mode, stages clean curl and `moto-rt`
sources without the development-tree `.lorry` link, and builds release Motor
curl with a freshly built Lorry. It requires Cargo.lock to remain unchanged
and the result to identify as Motor curl.

The built executable's directory is then placed first in the test process's
selection path and the complete `curl::tests` module is rerun. This drives the
production Lorry command, concurrent streams, nonce trailer parser, response
metadata, certificate rejection, malformed/truncated response handling, and
body limits through the Lorry-built executable. The ordinary unit-suite pass
continues to provide the upstream-curl baseline.

Both focused debug and release forms pass. The exact patch then passed three
consecutive debug and three consecutive release `src/tests/full-test.sh`
runs. Every run included all 208 baseline Lorry tests, the 15-test
Lorry-built-curl lane, the safe public-lane skip, permission-preserving
SFTP/`cp -r`, Stage-2 seed verification, the Motor-native Lorry smoke gate,
and all 66 native `red` tests. The kernel watchdog did not recur.

## Target-native TLS server fixture (2026-07-28)

Curl's existing Rustls integration harness now has an inert-by-default
`tls_server_child` test. An explicit scenario environment variable turns that
test into a one-request server for the same success, redirect, malformed, and
truncated responses used by Lorry. It reports its dynamic loopback port with a
stable marker; Lorry scans a bounded number of libtest output lines for that
marker and keeps the output pipe open until the child exits.

The Lorry fixture accepts an explicitly selected TLS-server executable and
otherwise keeps its Python standard-library fallback for ordinary host unit
tests. The isolated Linux acceptance lane now stages curl's reviewed test
sources and repository CA path, builds curl's test targets with Lorry, and
uses the resulting Rust server executable for all five production TLS
boundary tests. This provides the server side needed for a wholly in-guest
Motor fixture without regenerating certificates or adding dependencies to
Lorry.

Both focused debug and release acceptance forms pass all 15 selected Lorry
curl tests. The next patch must cross-build and stage the Lorry test harness,
Motor curl, this curl integration harness, and the test CA, and provide
explicit test-only curl/CA selection inside the VM.

The exact patch passed `src/tests/full-test.sh` three consecutive times in
debug mode and `src/tests/full-test.sh --release` three consecutive times.
Every run included all 208 baseline Lorry tests, the 15-test Lorry-built-curl
lane using the Rust TLS child, permission-preserving SFTP/`cp -r`, Stage-2
seed verification, the Motor-native Lorry smoke gate, and all 66 native `red`
tests. The kernel watchdog did not recur.

## Native Motor curl boundary (2026-07-28)

The native smoke gate now Cargo-cross-builds the Lorry unit harness and uses a
hosted Lorry to cross-build Motor curl plus curl's Rustls integration harness.
It installs the reviewed build seed into an isolated host repository first;
the raw build repository is installer input and is not consumed directly. It
then stages those three executables and the reviewed test CA through SFTP.
Explicit test-only variables select the staged curl, trusted/untrusted CA
paths, and TLS-server harness without changing production curl discovery.

The first real cross-target ring build exposed that the build-script sandbox
admitted Clang itself but not its builtin-header tree or configured Motor C
sysroot. The native-tool projection now adds the compiler distribution's
canonical sibling `lib` directory and each exact absolute `--sysroot` flag as
read-only sandbox inputs, only when `c-compiler` is granted. A focused unit
case proves the same configured compiler exposes no sysroot when ungranted.
The VM harness therefore uses the real Motor Clang, C sysroot, and archiver
rather than substituting Linux headers.

The focused Linux contract passes all 15 curl tests. The standalone debug VM
gate passes exactly five selected Lorry TLS/error tests through the
Lorry-built Motor curl and target-native Rustls server, all 66 native `red`
tests, SFTP staging, and the argument-preserving simple run. The exact-five
assertion rejects libtest's otherwise-successful zero-match result.

The Motor Lorry test driver is intentionally a debug-profile libtest
executable: clean compilation takes about 13 seconds instead of the roughly
60-second release/LTO build, while the Lorry-built Motor curl and TLS server
under test remain release artifacts. The Linux and native lanes also share
Cargo's normal fingerprinted host release-Lorry target, avoiding a duplicate
clean host build. These changes keep the complete gate under its unchanged
600-second deadline without retries or timeout changes.

The exact patch passed `src/tests/full-test.sh` three consecutive times in
debug mode and `src/tests/full-test.sh --release` three consecutive times.
Every run included all 209 Lorry tests, the 15-test Lorry-built Linux curl
lane, permission-preserving SFTP/`cp -r`, Stage-2 seed verification, all 66
native `red` tests, exactly five native curl boundary tests, and the remaining
MIO/Tokio suites. The native phase measured approximately 141 seconds in the
debug runs and 27 seconds in the release runs. No kernel watchdog recurred.

## Selected-curl response framing (2026-07-28)

The target-native Rust TLS child and Python host fallback now provide chunked
and connection-close response scenarios. A selected-curl Lorry test requires
both to produce their exact body and observed size, so the ordinary unit lane,
Lorry-built Linux lane, and native Motor lane all exercise the two remaining
required framing modes through Lorry's production request boundary. The native
gate now requires exactly six selected tests.

The first upstream-curl close-delimited run rejected the Python fixture's raw
TLS EOF. The host fallback now completes an orderly TLS shutdown after sending
the response, matching the Rust fixture's existing `close_notify`; upstream
curl and Motor curl then both accept the connection-close framing.

The exact patch passed `src/tests/full-test.sh` three consecutive times in
debug mode and `src/tests/full-test.sh --release` three consecutive times.
Every run included all 210 Lorry tests, all 16 Lorry-built Linux curl tests,
permission-preserving SFTP/`cp -r`, Stage-2 seed verification, all 66 native
`red` tests, exactly six native curl boundary tests, and the remaining
MIO/Tokio suites. Debug native phases were approximately 142 seconds and
release native phases approximately 27 seconds. The kernel watchdog did not
recur.

## Selected-curl timeout behavior (2026-07-28)

The TLS fixtures now have a deterministic two-second post-request stall. The
new selected-curl test derives Lorry's exact production argument vector and
changes only the fixture durations: one case sets a one-second total transfer
limit and the other a one-second low-speed interval. Both reuse production
process capture, trailer parsing, and nonzero-status reporting and require curl
status 28. The same test runs through upstream Linux curl, Lorry-built Linux
curl, and native Motor curl; the native gate now requires exactly seven
selected tests.

The exact patch passed `src/tests/full-test.sh` three consecutive times in
debug mode and `src/tests/full-test.sh --release` three consecutive times.
Every run included all 211 Lorry tests, all 17 Lorry-built Linux curl tests,
permission-preserving SFTP/`cp -r`, all 18 Stage-2 seed tests, all 66 native
`red` tests, exactly seven native curl boundary tests, and the remaining
MIO/Tokio suites. Debug native phases were 145.390--146.588 seconds and release
native phases were 31.437--31.733 seconds. The kernel watchdog did not recur.

## Selected-curl hostname verification (2026-07-28)

The hostname fixture uses a separate reviewed test CA and server identity. The
server certificate is signed by that CA but names only `127.0.0.2`; the server
and request remain on `127.0.0.1`. Both target-native and Python fallback
servers therefore require curl status 60 for a real certificate-name mismatch
without external DNS, public network traffic, wildcard binding, or a test-only
curl option. The selected test runs through upstream Linux curl, Lorry-built
Linux curl, and native Motor curl; the native gate now requires exactly eight
selected tests.

An initial native attempt tried to reach another loopback address through an
ephemeral wildcard listener. Motor deliberately rejects `0.0.0.0:0`, so the
TLS-server children exited at bind and the SSH command returned 255. The VM
remained healthy, cleanup SSH succeeded, and no watchdog recurred. Evidence is
retained under
`target/lorry/native-tests/stage1-20260729T002728Z-761230`.

The exact hostname-verification patch passed `src/tests/full-test.sh` three
times in debug mode and three times with `--release`. Every run included all
212 Lorry tests, all 18 Lorry-built Linux curl tests, permission-preserving
SFTP/`cp -r`, all 18 Stage-2 seed tests, all 66 native `red` tests, exactly
eight native curl boundary tests, and the remaining MIO/Tokio suites. Debug
native phases were 146.826--147.324 seconds and release native phases were
31.544--32.036 seconds. The kernel watchdog did not recur.

## Selected-curl stream separation (2026-07-28)

A selected-curl conformance case now invokes the exact production argument
vector without Lorry's capture layer and inspects both raw child streams. It
requires stdout to equal the five response-body bytes and stderr to equal only
the complete nonce-delimited control trailer, including the observed status,
effective URL, empty redirect, and size. The same test runs through upstream
Linux curl, Lorry-built Linux curl, and native Motor curl; the native gate now
requires exactly nine selected tests.

The isolated Linux acceptance lane now also supplies the hostname CA from its
copied curl source tree instead of relying on the equivalent repository path.
The exact stream-separation patch passed `src/tests/full-test.sh` three times
in debug mode and three times with `--release`. Every run included all 213
Lorry tests, all 19 Lorry-built Linux curl tests, permission-preserving
SFTP/`cp -r`, all 18 Stage-2 seed tests, all 66 native `red` tests, exactly
nine native curl boundary tests, and the remaining MIO/Tokio suites. Debug
native phases were 146.777--147.467 seconds and release native phases were
31.547--31.762 seconds. The kernel watchdog did not recur.

## TCP connect failure propagation (2026-07-29)

The selected-curl exit-code fixture exposed that sys-io returned
`E_TIMED_OUT` whenever a connecting smoltcp socket entered `Closed`, including
an immediate reset from an unused loopback port. Sys-io now compares the
request's existing absolute connect deadline with the current monotonic time:
deadline expiry remains `E_TIMED_OUT`, while an earlier close is
`E_NOT_CONNECTED`.

A native systest connects to the controlled VM's unused loopback port 1 with a
two-second deadline and requires `NotConnected`. Before the fix the same
operation returned `TimedOut`; this distinction lets Motor curl preserve
status 7 for connection failure without weakening its separate status-28
timeout behavior.

The isolated patch passed `src/tests/full-test.sh` three consecutive times in
debug mode and `src/tests/full-test.sh --release` three consecutive times.
Every run included the new native reset classification, the existing TCP
timeout cases, all 213 Lorry tests, the 19-test Lorry-built Linux curl lane,
permission-preserving SFTP/`cp -r`, all 66 native `red` tests, exactly nine
native curl tests, and the MIO/Tokio suites. Debug native phases were
146.283--147.102 seconds and release native phases were 31.432--31.818
seconds. The kernel watchdog did not recur.

## Legacy combined design and implementation record

The remainder of this file is preserved from the former monolithic
`plan.md`. Statements below that call themselves authoritative describe the
state at the time they were written; the current `plan.md` is now the
authoritative resume point.

## Current Stage-2 checkpoint (2026-07-26)

Before this document was split, this was the authoritative resume point. It is
now retained as detailed history and may describe work that has since been
completed; use `plan.md` for the current resume point.

Already implemented:

- Stage 1 is complete: dependency-free bootstrap, `build`, `run`, and `test`;
  Linux, cross-Motor, and native-Motor self-build and Cargo identity gates.
- Stage 2 parses and resolves the supported Cargo subset, validates lockfiles
  and explicit path patches, applies target/features/policy, verifies layered
  content-addressed repositories, and builds dependency, build-script, root,
  and integration-test units.
- Linux build-script isolation, the build cache, `rush` acceptance surface,
  `--test`, `--no-run`, and the self-extracting test bundle are implemented.
  The core Stage-2 Lorry self-build path works from the reviewed system seed.
- Vendoring holds a project lock, downloads bounded sparse records and crate
  archives through the configured curl executable, verifies and privately
  stages them, presents inspection evidence, applies per-package approval or
  `--accept-all`, and publishes immutable repository objects before committing
  `Cargo.lock` last. Publication is atomic and no-replace on Linux and Motor.
- Redirect trust uses initially empty persistent allow/deny lists. An unknown
  HTTPS site is prompted independently of package approval and may be allowed
  or denied for the current operation or persistently.
- A fresh public crates.io run has populated a repository from the minimal
  patched-`ring` seed, and a second warm run reused every selected archive.
  Native compiler/archiver roles are target-specific; Linux defaults to Clang
  and `ar`, and Lorry has built the reviewed patched `ring` and `src/bin/curl`
  graph on Linux.
- The independent Motor curl utility implements Lorry's required HTTPS/CLI
  subset and has deterministic local TLS coverage. Lorry invokes it through
  the same direct curl command/stream contract used with upstream Linux curl.

Remaining before Stage 2 can close:

1. Resolve the offline Cargo-oracle input gap for the curl lockfile. The
   production 45-object seed intentionally contains the selected graph, while
   Cargo also requires inactive target packages named by `Cargo.lock` (the
   first missing package observed was `wasi`). Prefer an oracle-only complete
   lockfile view unless a different trust-boundary change is reviewed; then
   finish the same-tool Clang/`ar` Cargo-versus-Lorry Linux identity check.
2. Finish item 7's Lorry-level deterministic TLS/error fixtures and registry
   interruption, concurrent-publication, and all-or-none transaction fixtures.
   Turn the already successful public crates.io acquisition into its planned
   opt-in acceptance lane and prove undeclared native child tools are denied.
3. Replace the explicit Motor build-script sandbox warning stub with enforced
   isolation and pass the network, filesystem, environment, and child-process
   denial fixtures. External Gate 11 remains mandatory.
4. Complete curl closure: build patched `ring` and curl for cross-Motor and
   native Motor, run Motor entropy and verified-HTTPS fixtures, use the
   Lorry-built curl on both platforms to populate a second fresh repository,
   and rebuild curl using only that repository plus the system `ring`.
5. Run the final pristine debug/release, Cargo 1.97/1.98 identity,
   cold/warm/corrupt-cache, fresh-vendor, cross/native, and `--full` matrices
   (including the three-pass repository test rule), audit all pinned inputs and
   native tools, document every rejected Cargo capability, and publish the
   Stage-2 support matrix.

Resume with item 1. It is the immediate blocker for the clean Linux curl
identity comparison; do not broaden the production trust seed merely to make
Cargo's oracle accept inactive lockfile entries without explicit review.

This is a living document. Statements under **Agreed requirements** come from
the project brief or later discussion. The round-by-round decision record
preserves the reasoning and notes when a later round supersedes an earlier
choice.

The active design boundary is stages 1 and 2 (`red` and `rush`). Detailed
stage-3 and later decisions are frozen until stage 2 is implemented and
accepted. Previously agreed broad future goals remain context, but no
stage-3-specific mechanism is implementation-ready merely because it is
mentioned here.

## Motivation

Lorry will be a smaller and stricter alternative to Cargo for projects that do
not need Cargo's full feature set.

It addresses two related problems:

1. Cargo itself is difficult to port to Motor OS because it has broad scope and
   a large dependency graph. Motor OS now has a native `rustc`, so it needs a
   native Rust build and packaging tool.
2. Cargo and crates.io make it easy for projects to accumulate large,
   insufficiently reviewed transitive dependency graphs. Lorry should make
   dependencies deliberate and visible.

## Agreed requirements

- Lorry is implemented by the `src/bin/lorry` crate.
- Lorry itself must run natively on Linux and Motor OS.
- Development will be iterative on Linux, with periodic native Motor OS tests
  to catch portability regressions.
- Lorry is intentionally a subset of Cargo, not a complete reimplementation.
- Cargo parity is not an objective. A capability is added only for a concrete
  supported-project need with an acceptable complexity and security cost;
  otherwise Lorry rejects it explicitly. Small CLI syntax can still conceal
  graph, acquisition, policy, or caching complexity and is judged by the full
  behavior it implies.
- Many simple, pure-Rust projects with simple `Cargo.toml` manifests should
  build with `lorry build`.
- For supported projects, equivalent Cargo and Lorry builds should produce
  byte-identical final binaries.
- Byte identity is defined for builds using the same source tree, manifest,
  lock state, compiler/toolchain, target, profile, and host environment:
  - On a Linux host, native Cargo and Lorry builds must produce identical
    binaries.
  - On a Linux host cross-compiling for Motor OS, Cargo and Lorry must produce
    identical binaries when both builds are supported.
  - A native Motor OS Lorry build must produce the same binary as a Linux-hosted
    Lorry cross-build when the same manifest supports both environments.
  - Required Motor patches are explicit Cargo-compatible path declarations:
    `Cargo.toml` must contain the configured path patch and `Cargo.lock` must
    contain the corresponding path-package entry. Lorry refuses an unpatched
    graph rather than silently substituting one, so Cargo and Lorry compare
    against the same manifest and lock identities.
- Byte identity is an acceptance requirement for release binaries. Debug builds
  must use Cargo-equivalent compilation semantics, but are not promised to be
  byte-identical across native and cross-host environments because paths and
  host-specific debug information may differ.
- Initial byte-identity compatibility covers Cargo algorithm families 1.97 and
  1.98. Lorry infers the family from a conventionally paired Linux toolchain
  and accepts an explicit `cargo-compat-version` from layered `lorry.toml` for
  custom/unpaired toolchains. Motor's system configuration pins the family
  used by its corresponding Linux cross toolchain. An unsupported family is a
  hard error rather than a silent downgrade of the identity promise.
- Native Motor target units use the logical identity of an explicit
  `x86_64-unknown-motor` target even when the command omits `--target`.
  Host-only build helpers still execute natively. This normalization makes
  target-unit identity comparable with Linux-to-Motor cross-builds.
- Native/cross-host byte identity applies to deterministic packages whose
  target outputs do not embed host-dependent observations or differing
  absolute paths. Packages that embed values such as host paths, timestamps,
  randomness, `OUT_DIR`, or arbitrary build-script observations are outside
  that cross-host promise. Lorry should diagnose known hazards where
  practical, but is not expected to prove arbitrary code deterministic.
- Lorry must be able to build for Linux and for Motor OS.
- Lorry will download supported dependencies from crates.io.
- Centrally maintained `lorry.toml` rules identify crates that must be
  explicitly repointed to approved Motor-compatible sources. Lorry validates
  the matching `Cargo.toml` and `Cargo.lock` entries and gives an exact
  correction when they are missing or wrong; it does not silently rewrite the
  manifest during a build.
- Planning precedes implementation. Important behavioral or architectural
  choices must be agreed explicitly rather than inferred.
- Lorry implementation must not begin until Motor OS supplies SFTP upload
  support plus working recursive guest copy and removal operations (`cp -r`
  and `rm -r`). These are external Motor OS prerequisites, implemented and
  validated outside this Lorry effort. The native harness will use them for
  staging pristine inputs and cleaning isolated work trees rather than baking
  changing test payloads into each VM image.
- Lorry must not invoke or depend on the Cargo executable for resolution,
  lockfile creation, fetching, building, or any other operational step. Cargo
  may be invoked only by compatibility tests that compare Cargo's results with
  Lorry's.
- Lorry's intended audience includes both Motor OS developers building
  natively and general Rust/Linux users who need stronger dependency and
  supply-chain controls than Cargo provides.
- The core `lorry` package may use narrowly scoped, pure-Rust dependencies
  already present in an unpatched form in `src/sys/Cargo.toml` or a
  `src/bin/*/Cargo.toml` graph. Existing Motor use is portability/review
  evidence, not a policy exemption. Lorry has no gameable numerical crate cap:
  every direct dependency and graph change records its purpose, exact
  source/version, license, selected features, and complete transitive-graph
  justification. A crate that is patched anywhere in those Motor graphs is
  not admitted under this shortcut and needs its own explicit design review.
- The stage-1 revision of core Lorry has no third-party dependencies and must
  build itself with stage-1 Lorry. The stage-2 revision may use only dependency
  and manifest capabilities supported by stage 2 and must build itself with
  stage-2 Lorry from its Cargo.lock and local dependency repository, both on
  Linux and natively on Motor.
- Self-buildability is a per-milestone invariant, not a claim that the frozen
  stage-1 executable must build the later stage-2 source revision.
- Stage-1 Lorry's CLI parser is hand-written for its deliberately small command
  surface. Stage 2 replaces it with Clap's builder API using an existing
  unpatched Motor-tested crate graph; derive/proc-macro features stay disabled.
- HTTPS acquisition uses a curl-compatible command directly, with no
  Lorry-specific helper, adapter executable, or private protocol. Linux uses
  upstream curl 7.63.0 or newer. Motor OS supplies the independent
  `src/bin/curl` package, installed as `/bin/curl`, which implements the
  required curl CLI subset using blocking HTTP/1.1 over `std::net` and Rustls.
  The exact invocation and stream contract is in `curl-interaction.md`.
- Before Stage 2 closes, Stage-2 Lorry must build `src/bin/curl` on Linux and
  native Motor, and Lorry must use the resulting executable directly to
  populate a fresh dependency repository used for a second curl build.
- Stage-2 Motor curl pins `ring` 0.17.14 as its Rustls cryptography
  provider. Cargo.toml explicitly path-patches to its stable logical Lorry
  artifact path, and Cargo.lock contains the corresponding path-package node.
  Lorry resolves the source through its repository layers. The system seed is
  derived from that exact crates.io archive with only the
  two Motor target-classification changes recorded in Round 27; its Git
  URL/commit remain verified seed provenance rather than a Cargo source. The
  curl package also enables `getrandom` 0.2.17's `custom` feature and registers a
  Motor-only callback to `moto_rt_fill_random_bytes`; it does not patch
  `getrandom`. AWS-LC remains a viable post-Stage-2 provider candidate, but
  generic Cargo `links` metadata forwarding is not added to Stage 2 merely to
  support it.
- New Lorry and Motor curl code uses `MIT OR Apache-2.0`. Dependencies of both
  packages pass the same configurable admission machinery as other
  dependencies; first-party use does not create a policy exemption.
- Initial user-facing commands include `lorry build`, `lorry run`, and
  `lorry test`. Each supports the default development profile and `--release`.
- Stage 2 supports `lorry test --test <name>` as a low-complexity integration
  target filter. Without it, all enabled root unit and discovered integration
  test targets run.
- Stage 2 adds `lorry test --bundle`, an explicit Lorry extension that packages
  the selected test harness executables and required program binaries into one
  target-native self-extracting executable. It builds and runs the bundle by
  default; `--no-run` builds it and prints its deterministic path. Ordinary
  `lorry test --no-run` builds separate Cargo-compatible harnesses without
  executing them.
- A test bundle verifies its embedded payload table and extracts through
  race-resistant operations into a directory beneath a configurable absolute
  extraction root. It invokes payloads without a shell, forwards harness
  arguments after `--`, and aggregates failures. All platforms reject links,
  unexpected files, and content tampering; Unix builds additionally enforce
  private directory, manifest, and executable modes. Platforms without Unix
  permission modes omit only that mode-specific hardening.
- Bundle mode is not covered by Cargo byte identity. It preserves separate Rust
  crate/harness semantics internally, but tests that require Cargo's original
  absolute artifact paths or a system with no writable extraction location may
  be rejected in bundle mode.
- A stage-1/2 root package may have at most one library and one binary target,
  each implicit or explicitly configured. `[lib]` and the single `[[bin]]`
  accept `name`, `path`, and `test`, with Cargo defaults when omitted.
- `lorry test` includes enabled root library and binary unit-test harnesses plus
  automatically discovered `tests/*.rs` integration crates. Stages 1 and 2
  reject multiple binaries, `--bin`, explicit `[[test]]`, custom crate types,
  `harness`, `required-features`, `autobins`, `autotests`, and `default-run`.
- For Cargo behavior that falls within Lorry's documented subset, replacing
  the `cargo` executable with `lorry` in the command line should preserve
  behavior. This includes:
  - Cargo/rustup-style leading toolchain selectors on Linux, such as
    `lorry +dev-x86_64-unknown-motor build --target
    x86_64-unknown-motor`.
  - Cargo-compatible `run` argument forwarding, including arguments after
    `--`.
  - Cargo-compatible cross-test behavior; Lorry does not invent a distinct
    build-only interpretation for `test --target`.
- Linux-hosted builds select and invoke Rust tooling the way Cargo does. Native
  Motor OS builds use `/sys/tools/rust/bin/rustc`; exact override and discovery
  precedence is:
  - On Linux, a leading `+toolchain` is resolved by asking `rustup` for that
    toolchain's `rustc`; Lorry does not invoke Cargo. Without a selector,
    `RUSTC` takes precedence over `rustc` found through `PATH`.
  - On Motor, `/sys/tools/rust/bin/rustc` is the default. `RUSTC` and an
    absolute configured override are supported unless a system policy locks
    the compiler path.
  - A requested `+toolchain` for which rustup is unavailable or cannot locate
    rustc fails with a direct, actionable diagnostic.
- Lorry honors `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` with Cargo-compatible
  precedence. Effective flags are compilation-identity and cache inputs.
- Lorry reads only a documented compilation-related subset of Cargo
  configuration: default build target, target-specific linker, rustflags, and
  runner. Cargo registry, credential, alias, network, and unstable settings do
  not become Lorry configuration. A setting outside the supported subset that
  can affect an in-scope build is rejected rather than ignored.
- For that subset, Lorry follows Cargo's `.cargo/config.toml` discovery and
  merge behavior, including supported `CARGO_TARGET_<TRIPLE>_*` environment
  forms.
- A cross-target `lorry run` or `lorry test` uses the configured target runner.
  Without a runner, Lorry attempts direct execution and reports the resulting
  failure as Cargo would. Both Cargo-compatible string and argument-array
  runner forms are supported without invoking a shell.
- `RUSTC_WRAPPER` and `RUSTC_WORKSPACE_WRAPPER` are unsupported through stage
  3. If either is set, Lorry fails with an actionable diagnostic rather than
  ignoring it or weakening the identity guarantee.
- Through stages 1 and 2, `--target` and Cargo's `build.target` accept installed
  target triple names, not custom JSON target specifications. `build.target`
  must be a single string; Cargo's multi-target array form is rejected. Stage
  3 makes no commitment yet.
- Stages 1 and 2 accept Rust editions 2015, 2018, 2021, and 2024. For a
  single-package root they implement resolver versions 1, 2, and 3, including
  Cargo's edition-based defaults and an explicit root
  `resolver = "1" | "2" | "3"`.
- Lorry parses and enforces `package.rust-version`. Resolver 3 uses the root
  Rust-version/compiler context and dependency index `rust_version` metadata
  with Cargo-compatible incompatibility handling.
- The supported target configuration accepts both exact target-triple tables
  and `cfg(...)` selectors. Selector evaluation uses rustc's reported cfg set,
  shared with target-specific dependency evaluation.
- Lorry will use `target/lorry/` as its default artifact root, with familiar
  `debug`, `release`, and target-triple subdirectories beneath it. It must not
  consume Cargo artifacts from `target/debug`, `target/release`, or
  `target/<triple>`:
  - Separate artifacts make Cargo-versus-Lorry byte comparisons genuine.
  - Lorry can use a deliberately smaller fingerprint/cache format without
    accidentally accepting Cargo's opaque fingerprints.
  - Keeping the directory under `target/` works with standard Cargo
    `.gitignore` rules and keeps all build output together.
- A later explicit output-directory option may override this default.
- An omitted native target uses `target/lorry/debug` or
  `target/lorry/release`. An explicitly selected target uses
  `target/lorry/<triple>/debug` or `release`. Native Motor's logical explicit
  target identity does not force the target triple into the user-facing path
  when the user omitted `--target`.
- Lorry initially operates on `Cargo.toml` in the current package directory.
  `--manifest-path` and upward manifest discovery are explicitly deferred.
- Cargo workspaces are not supported in stages 1 and 2. Even current-member
  workspace support changes root discovery, shared lock/output locations,
  resolver and feature scope, metadata hashing, root patches/profiles, and
  inherited dependency/package/lint configuration. A deliberately restricted
  current-member workspace mode may be considered after stage 2, but its
  design is not decided now.
- Any manifest or configuration key that Lorry reads but does not support is a
  hard error. Diagnostics must name the unsupported key and source location,
  explain the limitation in plain language, and suggest a supported rewrite or
  explicitly identify the feature as deferred when possible. Lorry must never
  silently ignore a setting that could change build output or dependency
  selection.
- `lorry build`, `lorry run`, and `lorry test` never access the network or
  automatically acquire a missing dependency. A missing dependency fails with
  a diagnostic that identifies the package/version/source and recommends the
  appropriate `lorry vendor` command.
- Every build requires a present, current `Cargo.lock`, including
  zero-dependency builds. Build/run/test treat it as read-only and never
  perform resolution or rewrite it.
- `lorry vendor` is the separate, explicitly networked dependency-acquisition
  command. It downloads dependencies into the configured repository-local
  artifact store when present, otherwise the configured user store. The system
  store is always read-only to Lorry.
- `lorry vendor` acquires its project-scoped exclusive lock through the stable
  `std::fs::File::lock` API on every platform and holds the owning `File` until
  the complete vendoring transaction has finished. Lorry does not emulate this
  with lock directories, polling, platform-specific side channels, or another
  best-effort fallback.
- Repository-local, user, and system artifact-store locations are separately
  configured by their corresponding `lorry.toml` layers. The initial format
  accepts absolute paths only. Relative paths, interpolation, and implicit
  paths are rejected.
- By default, `lorry vendor` presents the dependencies it proposes to acquire
  one package at a time and requires explicit user confirmation for each new
  package. All downloads/extractions are staged transactionally: if any
  package is declined or any operation fails, none of the newly proposed
  packages are committed to the dependency repository.
- `lorry vendor --accept-all` is the non-interactive form. It accepts every
  package in the proposed tree that passes all configured policy and integrity
  checks. The flag does not bypass rejection, checksum failure, or policy.
- `[vendor].targets` in `lorry.toml` lists the target triples whose combined
  dependency graph must be acquired. Its defaults are
  `x86_64-unknown-linux-musl` and `x86_64-unknown-motor`.
- The current rustc host triple is implicitly added to the vendoring target
  set by default. On the present GNU Linux host, the effective defaults are
  GNU Linux, musl Linux, and Motor. Configuration may explicitly disable host
  inclusion.
- Vendoring acquires the union of non-path dependencies selected for those
  targets, not every target-conditioned entry present in `Cargo.lock`.
- Stage 2 applies a configurable pre-approved policy filter before a dependency
  can be vendored. Rounds 17 and 18 resolve its base criteria, trust model,
  defaults, and rule behavior. Round 28 resolves its native-tool configuration
  and authorization fields.
- `lorry vendor` must run natively on Motor OS as well as Linux. It invokes the
  platform's curl-compatible command directly and cannot depend on Cargo.
  Lorry owns URL and redirect validation, resolution, policy, approval,
  integrity checking, size limits, staging, and repository commit. Curl owns
  only the requested HTTPS transfer. General Git acquisition and any
  selectively enabled `gix` functionality are post-Stage-2.
- A root manifest's local path dependencies remain local path dependencies and
  are built from the declared paths, matching Cargo. They are not copied into
  the dependency repository merely because they participate in the graph.
- Every non-path package acquired into the dependency repository must have its
  complete non-path transitive closure in the repository. A build never falls
  back from the configured repository to Cargo's cache or the network.
- A dependency-free or path-only build does not require a configured dependency
  repository. The repository setting becomes mandatory only when the selected
  acquisition/build graph contains a non-path package. `lorry vendor` may
  create or repair a dependency-free/path-only Cargo.lock without a repository
  and without network access.
- Alternative registries are initially unsupported and rejected; crates.io is
  the only registry source in the initial subset.
- `Cargo.lock` remains the only dependency lockfile in stages 1 and 2. A
  configured required-patch rule never acts as a hidden graph overlay.
- Required-patch rules are configuration data in the normal layered
  `lorry.toml` hierarchy, not compiled into the executable. Official
  installations seed them in system/base configuration so Linux and Motor
  validate the same explicit Cargo source identity.
- Every required-patch rule identifies the crates.io package/version it guards,
  when the rule applies, the required logical artifact path, and the seeded
  source's exact Git provenance/full commit and independent source-tree digest.
- Dependency admission policy separately authorizes the replacement. There is
  no hard-coded bypass for `ring` or any other named crate.
- A selected dependency matching a required-patch rule must be resolved through
  a semantically matching root `[patch.crates-io]` path entry and Cargo.lock
  path-package node. A missing/wrong entry is a hard error with an exact TOML
  correction and `lorry vendor` advice; build/run/test never edit either file.
- Git dependencies are a supported source type, subject to configurable
  policy. A restrictive policy may reject all git sources or admit only
  selected hosts/repositories/commits; a permissive policy may allow arbitrary
  sources within Lorry's supported Git protocols. This remains a general
  post-Stage-2 direction. Stage 2 rejects Cargo Git sources entirely; Git is
  used only by external host tools as provenance/acquisition for a system-
  seeded source tree that Cargo and Lorry consume through a path override.
- Root packages in stages 1 and 2 support normal dependencies only. They
  include
  target-conditioned crates.io/path dependencies, string and table forms,
  renaming, optional dependencies, default-feature control, feature
  forwarding, required version requirements for crates.io dependencies, and
  path dependencies with or without an explicit version requirement. When a
  path dependency supplies `version`, the selected local package must satisfy
  it.
- Root build-dependencies and dev-dependencies are rejected in stages 1 and 2.
  Dev-dependencies declared by dependency packages are ignored as Cargo
  ignores them. Stage 1 rejects every selected build-dependency. Stage 2
  supports transitive build-dependencies required by approved dependency
  build scripts, compiling their unit graph for the host.
- Stage 1 compiles and executes dependency-free Rust build scripts. Stage 2
  additionally supports approved dependency build scripts with transitive
  build-dependencies, native `links` packages, and the narrowly controlled
  native toolchain needed by the selected Motor curl cryptography provider;
  no crate is special-cased. Root default features and features requested on
  dependencies are supported. CLI `--features`, `--all-features`, and
  `--no-default-features` are deferred because they change the offline
  vendoring graph, policy decisions, compilation identities, and cache keys,
  not merely argument parsing.
- Stage 2 accepts exact local path replacements in root
  `[patch.crates-io]`. The replacement remains a local path package, must
  satisfy the replaced version selection, and is subject to path-package and
  build-script policy. A path matching an effective required-patch rule must
  resolve to the exact verified object through the Lorry artifact layers.
  Manifest Git and registry patch sources remain unsupported.
- Stages 1 and 2 reject direct Git, alternative-registry,
  workspace-inherited, and artifact dependencies. A host-seeded object's Git
  provenance does not admit any Cargo Git dependency form.
- Dependency-repository storage uses two configurable booleans:
  - `keep-artifacts = true` retains verified acquisition artifacts.
  - `keep-sources = true` retains extracted source trees.
  Both default to true, and configuration with both false is rejected. With
  artifacts only, builds extract into an ephemeral Lorry build cache; with
  sources only, Lorry retains a source-tree integrity manifest after discarding
  the acquisition artifact.
- Lorry combines three Motor OS configuration layers, with later layers
  overriding earlier layers:
  1. System: `/sys/tools/rust/cfg/lorry.toml`.
  2. User: `/user/cfg/lorry.toml`.
  3. Repository-local: `lorry.toml` at the repository root.
  Linux has two layers:
  1. User/base: `$HOME/.config/lorry/lorry.toml`.
  2. Repository-local: the same nearest-ancestor `lorry.toml` rule.
  Linux never reads or writes `/etc` and does not redirect this control root
  through `XDG_CONFIG_HOME`. A missing or non-absolute `HOME` is an actionable
  error when the base layer or host system seed is required.
- Starting at the current package directory, Lorry walks ancestors and uses the
  nearest `lorry.toml` as the repository-local layer. It does not require Git,
  a `.git` directory, or Cargo workspace discovery for this lookup.
- Configuration tables merge recursively. A later scalar or array replaces the
  earlier value in full; arrays never append implicitly. Diagnostics for
  effective configuration should retain source-layer provenance.
- System configuration can mark security constraints as non-overridable. A
  user or repository layer that attempts to weaken one fails with a diagnostic
  naming both the attempted override and the system rule.
- Motor's system CA certificates live under `/sys/cfg/ssl/`. Lorry passes
  `/sys/cfg/ssl/ca-certificates.crt` to curl by default.
  `[network].ca-bundle` may specify an absolute override path.
- Lorry is installed under `/sys/tools/rust/bin/` and Motor curl is installed
  as the general utility `/bin/curl`. `[network].curl` may provide an absolute
  override. On Linux, Lorry resolves `curl` through `PATH`; on Motor it defaults
  to `/bin/curl`.

## Capability stages

The first three end-to-end milestones are:

1. Build `src/bin/red`, a zero-dependency text editor, both natively for Linux
   and for Motor OS. Before stage 1 closes, the dependency-free stage-1 Lorry
   revision also builds itself.
2. Build `src/bin/rush`, whose only external dependency on Linux is `libc`,
   both for Linux and Motor OS. This stage includes dependency-free Rust
   `build.rs` compilation/execution and its supported instruction protocol;
   `libc` must not be special-cased. It also supports the package's
   library-plus-binary target graph and its integration tests. Before stage 2
   closes, stage-2 Lorry builds its own locked, policy-approved dependency
   graph and itself on Linux and native Motor. The final Stage-2 submilestone
   adds the narrowly controlled transitive build-dependency/native-tool subset
   required by Motor curl, builds curl on both hosts, and proves the built
   executable by using it in a fresh-repository self-build cycle.
3. Build `src/bin/httpd-axum`, exercising a substantially more complicated
   third-party dependency graph and Motor OS dependency patches.

The repository, locking, acquisition, confirmation, patch, native-tool, core
dependency, and bootstrap-seed boundaries are settled at the architectural
level. Remaining pre-implementation work is the ordered acceptance plan and
the externally supplied prerequisite values/capabilities explicitly listed
below.

## Relevant repository facts

- The new crate currently has no dependencies and only a placeholder
  `main.rs`.
- The development toolchain is currently Rust/Cargo 1.98.0-nightly.
- The native Motor OS toolchain is installed in the image under
  `/sys/tools/rust`; `rustc` invokes the platform `cc` linker driver.
- The built-in Motor OS target triple is `x86_64-unknown-motor`.
- The existing `src/tests/full-test.sh` builds a debug or release VM image,
  launches that image's `run-qemu.sh`, waits for SSH on the standard test
  endpoint, runs host-driven commands in the guest, and shuts the VM down
  through a trap. The Lorry native harness can reuse this established image,
  SSH identity, and running-VM session instead of defining another VM format.
- The image builder assembles a writable Motor filesystem from the tracked
  `img_files/motor-os` tree and generated LLVM/Rust roots. SFTP upload landed
  in `cef41af`, and recursive guest copy/removal landed in `ca24c77`. The
  nested-tree, safe-error, and cleanup-isolation fixture in
  `src/tests/test-sftp.sh` passed against the debug Motor VM before Stage-1
  product implementation began. The native harness can therefore stage and
  clean its inputs dynamically instead of adding a generated image root.
- Existing Motor OS manifests already patch crates including `mio`, `tokio`,
  `smoltcp`, `ring`, `getrandom`, `home`, and `russh-cryptovec`, using a mix of
  git forks and repository-local paths. These existing declarations are useful
  evidence, but do not by themselves define or bypass Lorry's patch policy.
- Pure-Rust Motor OS binaries use the Rust sysroot without linking the C
  runtime by default. Rust projects that call C require additional rustc link
  settings. General C-FFI project support is outside stages 1 and 2; the
  policy-declared compiler/archiver path used by patched `ring` is the one
  bounded exception.
- `red` uses the conventional implicit `src/main.rs` binary target, edition
  2024, no features or dependencies, and custom release settings
  (`panic = "abort"`, fat LTO, stripping, and one codegen unit).
- Cargo builds `red` tests by compiling the binary target with `rustc --test`,
  rather than building a separate test target. Stage 1 therefore needs Rust's
  standard test harness and must execute the resulting test binary.
- A Cargo Motor cross-build selects the Motor development toolchain's `rustc`,
  passes `--target x86_64-unknown-motor`, places target artifacts under a
  target-triple directory, and adds both target and host dependency search
  paths. Lorry must reproduce the relevant target/host separation even before
  external dependencies are introduced.
- `rush` contains both an implicit `src/lib.rs` library and an explicit `rush`
  binary that links that library. Its dependency selection is target-specific:
  `libc = "0.2"` under `cfg(unix)`, and repository-local `moto-sys` plus
  `moto-rt` under `cfg(not(unix))`. The Motor target currently does not set the
  `unix` cfg.
- The `libc` version pinned by `rush/Cargo.lock` is 0.2.139. Building it
  requires compiling and running its Rust `build.rs` on the host, providing
  Cargo-compatible build-script environment variables, parsing its emitted
  rustc cfg directives, and passing those directives into the library build.
- That `libc` build script has no build-dependencies. It queries the selected
  rustc through its `RUSTC` environment variable and emits cfg and
  `rerun-if-changed` instructions.
- The published `libc` manifest also requires default/optional feature
  declarations and contains inert packaging/documentation fields plus opaque
  `[package.metadata.docs.rs]` data. These do not alter a normal build but must
  be recognized without misclassifying them as unsupported build semantics.
- The Motor-side `rush` graph exercises string and table dependency forms,
  target `cfg(...)` dependency tables, renamed dependencies, optional
  dependencies, default features, feature-to-dependency forwarding, implicit
  library discovery, an explicit binary, automatic `tests/*.rs` discovery,
  `[lib] test = false`, and `[lints.rust]`.
- Cargo's observed release invocation applies fat LTO to the final binary but
  linker-plugin LTO to its Rust library dependencies. It also translates
  `[lints.rust]` and `check-cfg` declarations into rustc arguments. These are
  required for release byte identity and cannot be treated as display-only
  manifest data.
- `httpd-axum` exercises default and explicitly disabled crate features,
  proc-macros, build scripts, a large transitive registry graph, and git-based
  patches for `ring`, `mio`, and `tokio`.
- `httpd-axum/Cargo.lock` currently contains 142 package entries: 137
  crates.io entries with checksums and four git-source entries representing
  the patched `ring`, `mio`, and `tokio` packages (the remaining entry is the
  root package). This makes a single-confirmation UX and concise dependency
  summaries important.
- The Motor-compatible `rustls` 0.23.42 graph already selected by
  `httpd-axum` is much smaller than the complete HTTP server graph. With
  default features disabled and only `ring` plus `std` enabled, adding
  `rustls-pemfile` selects 15 non-root package identities for a Motor build and
  no procedural macros. The non-Rust boundary is the patched `ring` provider:
  its `build.rs` has the `cc` build-dependency, compiles bundled C/assembly,
  declares `links`, and emits native link-library/link-search instructions.
  When built from a packaged source tree without `.git`, its pregenerated
  assembly avoids Perl and NASM, but a target C compiler and archiver are still
  required.
- `src/bin/russhd` does not use TLS or `rustls`; SSH supplies its own protocol
  and cryptographic stack. Its current lockfile contains 252 package entries,
  and an observed Motor normal/build Cargo tree contains 234 distinct rendered
  package entries. It unconditionally reaches eight procedural-macro crate
  names (nine selected package versions), including `serde_derive`,
  `tokio-macros`, `delegate`, and `enum_dispatch`; contains multiple packages
  with build-dependencies; uses git patches for `mio` and `tokio`; uses local
  path patches for `getrandom`, `home`, and `russh-cryptovec`; and declares a
  root dev-dependency. Disabling `russh` default features only removes its
  optional compression dependency and does not remove these structural
  requirements.
- The repository already contains a manually maintained `src/third_party`
  source tree, but it has no uniform registry/archive metadata layout and is
  not automatically assumed to be Lorry's local dependency repository.
- Cargo's local cache retains both registry `.crate` archives and extracted
  registry source trees. For git dependencies it retains a bare repository
  database plus commit-specific working checkouts. Lorry is not required to
  reproduce this internal cache layout.
- Nearly all `rush` integration tests use Cargo's conventional compile-time
  `CARGO_BIN_EXE_rush` variable to locate the built `rush` executable. This is
  part of stage-2 integration-test support, not treated as a deferred edge
  case.
- Cargo's artifact suffix is not cosmetic. An observed release build of `red`
  passed both `-C metadata=383c09b6fac15a9f` and
  `-C extra-filename=-3192ca1bd04bc552`. Replaying the complete rustc command
  with those values in an independent output directory produced a
  byte-identical stripped executable; replacing only those identity values
  changed the executable. Lorry therefore has to reproduce Cargo's compilation
  metadata, not merely its optimization and linker flags.
- With the same nightly rustc compiling `red`, Cargo 1.97 and Cargo 1.98
  produced the same metadata and extra-filename values. This is useful
  evidence for the current toolchains, but not a promise that Cargo's internal
  algorithm will remain stable.
- Cargo currently computes compilation metadata with its internal stable
  hasher over inputs including the package's stable identity, enabled features,
  profile and LTO selection, compilation mode and target, target identity,
  rustc version, and dependency metadata. Unit identity additionally covers
  command-line compilation inputs. These are Cargo implementation details, not
  a supported external API, so Lorry needs a small versioned compatibility
  implementation plus conformance fixtures rather than assuming one algorithm
  forever. The relevant Cargo source is:
  <https://doc.rust-lang.org/stable/nightly-rustc/src/cargo/core/compiler/build_runner/compilation_files.rs.html>.

## Planning sequence

The design will be settled in this order:

1. Define the initial user, first milestone, compatibility promise, and strict
   dependency policy.
2. Define the supported `Cargo.toml` subset and workspace/package model.
3. Define dependency resolution, lockfiles, crates.io access, caching, and
   offline/reproducible behavior.
4. Define Motor OS patch selection, ownership, storage, trust, and update
   policy.
5. Define the exact `rustc` invocation model required for Cargo-compatible
   artifacts.
6. Define commands, diagnostics, configuration, directory layout, and
   portability constraints.
7. Define incremental delivery stages and Linux/Motor OS acceptance tests.

## Decision record

### Resolved in round 1

- The first capability stages are `red`, `rush`, and `httpd-axum`, in that
  order.
- Byte identity covers Linux native builds, Linux-to-Motor cross-builds, and
  Motor native builds under equivalent inputs.
- Cargo is never an operational dependency; it is used only by compatibility
  tests.
- Motor OS and general Linux Rust developers are both first-class audiences.
- The strict dependency-approval mechanism is deferred until after initial
  zero-/single-dependency work.

### Round 2: initial manifest and command boundary

### Resolved in round 2

- Development and release profiles are both supported from stage 1.
- `build`, `run`, and `test` are initial commands; each accepts `--release`.
- Linux follows Cargo's Rust-tool discovery behavior; Motor has a known native
  rustc path.
- Lorry uses an isolated `target/lorry/` artifact tree.
- Stage 2 implements `build.rs` support rather than special-casing `libc`.
- Release binaries carry the byte-identity guarantee; debug builds carry
  semantic compatibility without a cross-host byte-identity promise.

### Round 3: exact stage-1 command semantics

### Resolved in round 3

- In-scope command behavior follows Cargo closely enough that users normally
  substitute `lorry` for `cargo`, including Linux toolchain selectors, run
  arguments, and cross-test behavior.
- Stage 2 supports `rush` integration tests and `CARGO_BIN_EXE_rush`.
- Unsupported manifest/profile keys are hard errors with actionable
  diagnostics.
- `--manifest-path` is deferred; commands initially run in the package
  directory.

### Round 4: vendoring and locked resolution

### Resolved in round 4

- The dependency repository path in `lorry.toml` is initially absolute.
- Confirmation is per new package, with all-or-nothing transactional commit.
- `lorry vendor --accept-all` accepts the complete policy-compliant tree.
- Native Motor OS supports `lorry vendor`; no Cargo or Git-command assumption
  is allowed. The required curl-compatible command is a first-party Motor
  utility.

### Resolved/superseded by rounds 19 and 20

- `lorry vendor` honors all still-valid locked selections. When the lock is
  absent or stale, it resolves dependencies and transactionally writes a
  Cargo-compatible lockfile only after every package is approved, fetched, and
  verified. Upgrading an already locked package requires a later explicit
  update option rather than ordinary vendoring.
- Store retained dependency data immutably: crates.io packages keyed by
  name/version/checksum. Builds never consult mutable source state. The
  equivalent git-derived key and integrity format remain post-Stage-2 with
  general Git support.

### Round 5: source and acquisition boundary

### Resolved in round 5

- Local path dependencies remain at their declared paths.
- Git-source admission is configurable rather than universally allowed or
  forbidden.
- `Cargo.lock` is mandatory and read-only during builds.
- Repository retention is configurable rather than unconditionally keeping
  both archives and extracted trees.

### Round 6: acquisition boundary and repository configuration

### Resolved in round 6

- This round's separate-`lorry-fetch` decision was superseded by Round 45.
  HTTPS acquisition now uses a curl-compatible command directly; general Git
  acquisition remains future work.
- Repository retention uses `keep-artifacts` and `keep-sources`, both true by
  default and not both false.
- Motor configuration layers are system, user, then repository-local.
- Motor system certificates live under `/sys/cfg/ssl/`, with a Lorry
  configuration override.

### Round 7: configuration semantics

### Resolved in round 7

- Linux uses only `$HOME/.config/lorry/lorry.toml` plus the repository-local
  layer; it never reads or writes `/etc`.
- The nearest ancestor `lorry.toml` is the repository-local config.
- Tables merge recursively; later scalars/arrays replace earlier values.
- System security constraints may be made non-overridable.
- Motor uses `/sys/cfg/ssl/ca-certificates.crt` with an absolute config
  override.
- Motor installs curl as `/bin/curl`; `[network].curl` overrides are absolute.

### Round 8: supported manifest subset

### Resolved stage-1/2 manifest policy

- Categorize manifest keys as:
  1. Supported build semantics, implemented compatibly.
  2. Recognized inert package/publication metadata, accepted but not used for
     build decisions; arbitrary `[package.metadata]` is opaque.
  3. Unsupported or unknown build semantics, rejected with an actionable
     diagnostic.
- Stage 1 supports one package, implicit `src/main.rs`, ordinary package
  identity/metadata, editions, the default dev profile, and the release profile
  keys exercised by `red`.
- Stage 2 adds implicit `src/lib.rs`, explicit `[[bin]]`, automatic
  `tests/*.rs`, target-cfg dependency tables, normal registry/path dependency
  forms, renaming, default/optional features and feature forwarding, `[lib]`
  settings exercised by Motor path crates, `[lints.rust]`, and
  `package.build`. Root build scripts remain dependency-free; approved
  dependency package build scripts may have transitive build-dependencies.
- Required stage-2 dependency execution is narrower than Cargo in general:
  the selected `rush` graph contains normal registry/path dependencies but no
  selected build-dependencies, dev-dependencies, git dependencies, proc macros,
  native `links` packages, or custom crate types. `libc` still requires
  compiling and running a dependency-free Rust build script. The final
  Motor curl submilestone additionally exercises transitive
  build-dependencies, native `links`, exact local path crates.io patches, and a
  policy-declared C-compiler/archiver subset; it still does not admit git
  sources, procedural macros, C++, or arbitrary custom crate types/tools.
- Evaluate target dependency expressions against `rustc --print cfg --target
  <triple>` rather than hard-coding platform cfgs.
- Workspaces, examples, benches, custom target auto-discovery switches, custom
  profiles, and CLI feature-selection flags are unsupported in stages 1 and 2.
  Their stage-3 status is deliberately undecided.
- Documentation tests are not run initially because native Motor does not ship
  `rustdoc`. `lorry test` reports this documented omission rather than silently
  implying that doc tests ran.

### Round 9: resolution, lock coverage, and registry scope

### Resolved in round 9

- `lorry vendor` creates a missing lockfile or repairs one made stale by
  manifest changes while preserving compatible locked versions.
- Explicit version-upgrade syntax is deferred for later discussion.
- Vendoring covers the union of configured target triples, defaulting to
  x86_64 Linux-musl and Motor.
- Only crates.io is initially supported.
- `Cargo.lock` stays Cargo-compatible and is the sole Stage-1/2 dependency
  lock. Round 33 supersedes the earlier automatic-overlay proposal with
  explicit required Cargo patch sources.
- Dependency-free/path-only builds do not require a dependency repository.

### Round 10: Motor patch rules

### Superseded and tightened in round 33

- Official required-source rules live in layered configuration and are exactly
  pinned.
- Cargo.toml and Cargo.lock must explicitly select the required source; Lorry
  refuses rather than automatically patching.
- Effective dependency policy applies separately; administrators can approve
  and lock the source rule without hard-coding a crate.
- Vendoring implicitly includes the current host target by default.

### Round 11: Cargo-compatible compilation identity

#### Findings

- For a supported Cargo version, Lorry must reproduce Cargo's complete rustc
  command semantics: crate names and target kinds, edition, emit modes,
  profiles, LTO selection, cfg/check-cfg and lint flags, dependency search
  paths and `--extern` arguments, metadata and extra-filename hashes, linker
  selection and arguments, relevant environment, and host/target unit graph.
- Cargo-compatible `-C metadata` values are necessary for final release-binary
  identity even when symbols are stripped. Artifact naming and downstream
  crate disambiguation must therefore use a compatibility implementation of
  Cargo's unit/metadata hashing.
- Cargo's hashing code is internal and coupled to Cargo's data model. Lorry
  will not depend on Cargo, but can implement the narrow compatible algorithm
  and use the small stable-hasher primitive it requires. Each supported Cargo
  compatibility version needs fixtures generated by the compatibility test
  suite and checked into the Lorry tests.
- Current evidence shows that the Cargo 1.97 and 1.98 algorithms agree for the
  stage-1 `red` unit when the same rustc is used. Before stages 1 and 2 may
  treat them as one compatibility family, fixtures must also cover every
  admitted unit shape: dependencies, features, target-specific units,
  libraries, tests, and build scripts. Procedural-macro units remain outside
  stages 1 and 2 and do not gate this family.
- Native-to-cross identity needs an explicit logical compilation identity.
  Cargo considers host compilation and an explicit target compilation
  different units. A plain native Motor build would otherwise identify target
  units as `Host`, while a Linux-to-Motor build identifies them as
  `Target(x86_64-unknown-motor)`.
- Host build scripts and proc macros are necessarily compiled for different
  physical hosts in a Linux cross-build and a native Motor build. Their target
  outputs can match only when their behavior is deterministic and does not
  leak host-specific inputs. Lorry's logical metadata treatment for those
  dependencies must also avoid introducing an otherwise irrelevant host
  identity into target artifacts.
- Cargo supplies compile-time environment values such as
  `CARGO_MANIFEST_DIR`, `OUT_DIR`, and package/target identity variables.
  Source code or build scripts can embed their values. Absolute source/output
  paths, the `CARGO` executable path, timestamps, randomness, directory
  enumeration, and arbitrary host observations can make cross-host binary
  identity impossible without restricting the promise or defining normalized
  values.
- Cargo's fingerprint cache is not itself part of binary compatibility. Lorry
  may use a smaller cache, provided a cache hit is valid for every input that
  can affect the command, generated files, or output.

#### Resolved in round 11

- Compatibility initially implements Cargo algorithm families 1.97 and 1.98,
  supports an explicit configured family for custom toolchains, and rejects
  unsupported families.
- Native Motor target units are logically normalized to the explicit Motor
  target identity.
- Cross-host identity is scoped to deterministic packages that do not embed
  differing host state or absolute paths.
- Canonical byte-identity acceptance uses clean builds from identical source
  and lock contents in isolated Cargo and Lorry artifact trees. Warm Lorry
  builds are tested additionally, but Cargo's incremental-cache state is not
  part of the contract.
- Stage 1 deliberately rebuilds instead of reusing artifacts. Stage 2 adds
  Lorry's own content-addressed fingerprint/cache. It tracks every input that
  may affect commands, generated files, or outputs, and never reads Cargo's
  cache.

### Round 12: toolchain, target, and compiler configuration

This round settled rustc discovery and overrides, leading `+toolchain`
selection, environment-supplied compiler flags, Cargo configuration
interoperability, linkers, runners, and native-versus-explicit target output
layout.

#### Resolved in round 12

- Linux toolchain selectors use rustup only to locate rustc; normal discovery
  honors `RUSTC` and then `PATH`. Motor defaults to its fixed system rustc and
  permits controlled overrides.
- Cargo-compatible `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` are supported and
  included in fingerprints.
- Lorry reads the narrow Cargo-configuration subset for default target, target
  linker, target rustflags, and target runner.
- The supported Cargo configuration uses Cargo's discovery/merge and
  target-environment conventions.
- Cross-target run/test uses a configured runner or attempts direct execution
  when no runner exists.
- Rustc wrappers are rejected in stages 1 and 2. Their later status is
  undecided.
- Artifact paths retain Cargo's native-versus-explicit-target shape beneath
  Lorry's isolated root; native Motor normalization is metadata-only.
- Target selection initially accepts installed triples and a single configured
  default, not JSON target specifications or multi-target arrays.
- Cargo target configuration supports exact-triple and `cfg(...)` selectors.

### Round 13: Lorry's own dependency and bootstrap boundary

#### Resolved in round 13

- Stage 1 deliberately requires zero third-party core dependencies. Stage 2
  uses only justified, reviewed dependencies rather than optimizing for an
  arbitrary count.
- Stage 1 uses a hand-written CLI parser. Stage 2 replaces it with the
  exact, no-derive Clap builder graph in Round 36.
- The Motor curl utility is a sibling package with an isolated dependency
  graph. Lorry invokes its curl-compatible CLI directly.
- Core self-buildability is now a stage-1 and stage-2 acceptance gate as
  specified in round 24.
- Lorry is dual MIT/Apache-2.0 and its own dependencies receive no admission
  bypass.

### Round 14: registry resolution and Cargo.lock semantics

This round settled the crates.io index protocol, supported lockfile versions,
Cargo feature-resolver behavior, yanked releases, version selection and
backtracking, checksum authority, and the exact conditions under which
vendoring may rewrite `Cargo.lock`.

#### Relevant Cargo semantics

- Cargo gives still-compatible versions already present in `Cargo.lock`
  priority over newly available versions. It normally selects the highest
  compatible new version when a locked selection cannot be retained.
- Lockfile graph resolution considers target-specific dependencies across all
  targets. Actual compilation then selects features for the requested target
  and command. This does not require Lorry to download irrelevant locked
  packages: the configured vendoring-target union can remain a strict subset
  of the complete lock graph.
- Resolver 2 separates feature activation for inactive target dependencies,
  host build/proc-macro dependencies, and inactive dev-dependencies. Resolver 3
  adds Rust-version-aware fallback selection. Editions 2021 and 2024 default
  to resolver 2 and 3 respectively.
- Cargo excludes yanked releases from new resolution but retains a yanked
  version already selected in a lockfile.
- The sparse crates.io index supplies dependency metadata, checksums, yank
  state, schema version, features, Rust version, and the archive-download URL.
  Cargo represents crates.io with its canonical registry source URL in the
  lockfile even when acquisition uses the sparse HTTP index.
- References:
  <https://doc.rust-lang.org/cargo/reference/resolver.html> and
  <https://doc.rust-lang.org/cargo/reference/registry-index.html>.

#### Resolved for stages 1 and 2

- Use only crates.io's sparse HTTPS index. Do not clone its Git index. Preserve
  Cargo's canonical crates.io source spelling in `Cargo.lock`.
- Read and write only lockfile format version 4. Older or unknown versions
  fail clearly; their later status is undecided.
- Default resolver behavior from the root edition exactly as Cargo does, honor
  an explicit root `resolver`, support versions 1, 2, and 3, and support
  `resolver.incompatible-rust-versions` because it affects resolver-3
  selections. Root editions 2015, 2018, 2021, and 2024 are admitted, and
  `package.rust-version` is enforced.
- Resolve the complete Cargo-compatible lock graph, including
  target-conditioned packages outside `[vendor].targets`, but fetch/admit only
  the closure selected by the configured vendoring-target union.
- Retain still-compatible locked selections; exclude yanked releases from new
  selections but allow a yanked release already locked.
- Treat the sparse-index SHA-256 as authoritative. A conflicting lock checksum
  or archive digest is a hard integrity failure, never an automatic repair.
  Store the exact index record used as acquisition evidence.

### Round 15: test target selection and portable test bundles

#### Findings

- Supporting `lorry test --test <name>` is a small graph-filtering feature once
  automatic integration-test discovery exists. It does not require a broader
  manifest, resolver, or acquisition capability.
- Rust unit-test harnesses and each `tests/*.rs` integration test are distinct
  crates with distinct crate roots and crate-level attributes. Combining their
  source into one generated Rust crate would change valid Cargo test semantics
  and create name/attribute conflicts.
- A single copyable artifact can instead be a target-native, self-extracting
  test launcher containing the separately compiled Cargo-compatible harness
  executables and required program binaries. It remains one file to copy and
  invoke, but extracts verified private payloads before executing them.
- Ten current `rush` integration-test crates embed `CARGO_BIN_EXE_rush` and
  spawn that executable. A complete `rush` bundle therefore includes `rush`
  itself and gives bundle-mode integration tests a stable extraction path for
  that compile-time variable.

#### Resolved in round 15

- Stage 2 supports named integration-test selection and build-only test mode.
- The explicit bundle mode produces one copyable, target-native,
  self-extracting executable while retaining separate test crates internally.
- Bundles include required package executables, use a verified private
  extraction cache, forward harness arguments, and aggregate results.
- Default test mode remains the Cargo-compatible path; bundle-specific path and
  writable-storage limitations are documented.

### Round 16: stage-1/2 target and workspace boundary

#### Resolved in round 16

- A root supports at most one library and one binary, implicit or explicit,
  with only the target fields needed by `red`, `rush`, and Motor path crates.
- Unit and automatically discovered integration tests are supported; broader
  target declaration/selection is rejected.
- Workspaces are deferred because even a basic member view affects nearly every
  parser, resolver, identity, and output subsystem. No detailed post-stage-2
  workspace design is committed.

### Round 17: stage-2 dependency-admission policy

#### Resolved policy model

1. Separate hard integrity invariants from configurable admission policy.
   HTTPS certificate validation, exact source identity, SHA-256 verification,
   safe archive paths/types, declared size limits, immutable repository
   identity, and transactional commit can never be disabled by a permissive
   policy.
2. Default-deny newly acquired non-path packages. A package must match an
   effective allow rule before it can be committed, and no effective deny rule
   may match it. Rules may range from an exact
   name/version/source/checksum tuple to deliberately broader version/source
   patterns, subject to locked system constraints.
3. Initial rules can test package name, semantic-version requirement, source,
   checksum, SPDX license expression, whether a build script exists, archive
   bytes, extracted bytes/file count, selected dependency depth, and total
   selected package count. A rule admitting a registry package with a build
   script must say so explicitly.
4. Ship the conservative graph/resource defaults resolved below, configurable
   downward or upward unless locked by system policy. Exceeding a limit fails
   before repository commit and reports the graph or artifact responsible.
5. Do not pretend stage-2 policy can reliably score maintainer reputation,
   popularity, project age, source-code safety, or the actual amount of
   `unsafe` Rust. Such criteria need trustworthy evidence and separate design;
   absence of those checks is reported honestly.
6. Path dependencies are not copied or admitted as registry packages. Lorry
   canonicalizes and reports them; policy may restrict them to configured
   absolute roots and reject symlink escapes. With no path-root restriction,
   local path dependencies retain Cargo behavior.
7. Resolution and acquisition use two policy passes: reject what can be
   rejected from index/graph facts first; then fetch remaining artifacts into
   transaction staging, verify and safely inspect them, apply manifest/archive
   rules, present the evidence during per-package confirmation, and commit
   nothing unless the complete selected tree passes and is approved.
8. A policy rejection prints the effective rule and configuration provenance.
   When safe, it also prints a minimal exact allow-rule example for review; it
   never edits policy automatically and `--accept-all` never bypasses policy.

#### Required initial exception

The stage-2 Motor/Linux development policy must admit the exact crates.io
`libc` 0.2.139 checksum already pinned by `rush`, its
`MIT OR Apache-2.0` license, and its dependency-free build script. This is
configuration evidence, not a hard-coded package exception.

#### Build-script isolation requirement

- Approved build scripts still execute untrusted dependency code. Stage 2 runs
  them in a mandatory platform sandbox that denies network access, makes
  package/dependency/toolchain inputs read-only, permits writes only in the
  assigned `OUT_DIR` and private temporary area, and restricts child process
  execution to Lorry-approved tools required by the supported build.
- The base Stage-2 `libc` case requires only the selected rustc to be available
  to the build script (`rustc --version`). The final Motor curl submilestone
  additionally permits only the policy-declared C compiler and archiver
  identities fixed for `ring` 0.17.14; this does not imply a general PATH or
  arbitrary native-tool execution.
- If the host cannot provide the required sandbox guarantees, a package with a
  build script fails before execution. There is no stage-2 flag that silently
  runs an approved dependency build script unsandboxed.
- Linux uses suitable existing OS enforcement. Native Motor support requires a
  corresponding Motor OS isolation feature. Designing that OS feature is
  explicitly outside the Lorry effort and is owned separately by the Motor OS
  project; Lorry records it as an external stage-2 prerequisite and tests the
  observable contract once available.

#### Resolved default limits

- Selected acquired packages: 64 maximum.
- Selected dependency depth: 16 maximum.
- Each package: 16 MiB compressed, 128 MiB extracted, and 20,000 files.
- Each vendor transaction: 256 MiB compressed and 1 GiB extracted.
- Each build-script execution: five minutes wall time and 8 MiB combined
  captured output.
- Archive extraction admits ordinary files and directories only. Links,
  devices, FIFOs, traversal, absolute paths, and other special entries are
  rejected.
- Limits are finite and configurable. System configuration may lock tighter
  ceilings.

### Round 18: stage-2 `lorry.toml` schema

Each present configuration layer must declare `config-version = 1`. Unknown
keys are errors. Missing files are normal; a dependency-free/path-only command
does not synthesize a configuration file.

The stage-2 schema is:

```toml
config-version = 1

# Optional; required when the selected/custom rustc cannot be mapped safely.
cargo-compat-version = "1.98"

[toolchain]
# Optional absolute configured override. RUSTC/PATH behavior is defined above.
rustc = "/absolute/path/to/rustc"

[repositories]
# Optional except when a required patch selects a seeded object.
system = "/absolute/read-only/system/vendor"
# Optional user-level writable store.
user = "/absolute/user/vendor"
# Optional repository-specific writable store.
local = "/absolute/repository/vendor"
keep-artifacts = true
keep-sources = true

[vendor]
targets = [
    "x86_64-unknown-linux-musl",
    "x86_64-unknown-motor",
]
include-host = true

[network]
# Both optional absolute overrides.
curl = "/absolute/path/to/curl"
ca-bundle = "/absolute/path/to/ca-certificates.crt"

[test]
# Optional; defaults are /tmp/lorry-tests on Linux and
# /user/tmp/lorry/test-extraction on Motor.
extraction-root = "/absolute/private/test-extraction-root"

[native-tools."x86_64-unknown-motor".c-compiler]
program = "/sys/tools/llvm/bin/llvm"
prefix-args = ["clang"]
flags = ["--target=x86_64-unknown-motor"]

[native-tools."x86_64-unknown-motor".archiver]
program = "/sys/tools/llvm/bin/llvm"
prefix-args = ["ar"]
flags = []

[policy]
default = "deny" # "deny" or "allow"
# Empty means Cargo-compatible unrestricted local path dependencies.
path-roots = []

[policy.limits]
max-packages = 64
max-depth = 16
max-package-bytes = 16777216
max-extracted-package-bytes = 134217728
max-package-files = 20000
max-transaction-bytes = 268435456
max-extracted-transaction-bytes = 1073741824
build-script-seconds = 300
build-script-output-bytes = 8388608

[policy.rules.allow-libc-0_2_139]
action = "allow" # "allow" or "deny"
name = "libc"
version = "=0.2.139"
source = "crates.io"
checksum = "201de327520df007757c1f0adce6e827fe8562fbc28bfd9c15571c66ca1f5f79"
license = "MIT OR Apache-2.0"
allow-build-script = true

# Honored in the system layer only. Each entry locks that key/table prefix
# against later-layer replacement.
[system-constraints]
locked = [
    "policy.default",
    "policy.limits",
]
```

Schema semantics:

- Omitted ordinary values use the defaults shown above except optional paths.
- All configured paths in version 1 are absolute and are canonicalized before
  use. An absent configured local/user repository is an empty lookup layer and
  may be created transactionally by `lorry vendor` after confirming its
  existing parent. A configured system repository must already exist whenever
  a selected required patch needs it and is never created or changed by Lorry.
- Policy rule IDs are unique across layers; redefining an ID is an error.
  Rules from all layers otherwise accumulate. Matching fields are conjunctive.
  Any matching deny vetoes admission; with `default = "deny"`, at least one
  matching allow is required.
- A package containing a build script is admitted only by a matching allow rule
  with `allow-build-script = true`, even under `default = "allow"`.
- The stage-2 license field matches the package's normalized SPDX expression
  exactly. Omitting it makes no license assertion; more elaborate SPDX
  satisfiability policy is deferred.
- `system-constraints` is rejected in user/repository files. A later layer that
  supplies a locked key or any descendant of a locked table fails and cites
  both layers.
- Rule tables are the one merge exception to ordinary replacement semantics:
  unique rule IDs accumulate so a later layer cannot erase an earlier deny.
- `repositories.system`, `.user`, and `.local` are layer-owned roles rather
  than ordinary overriding scalars. The trusted base/system layer alone
  defines `system`; the user/base layer alone defines `user`; and the
  repository-local layer alone defines `local`. Missing roles remain absent.
  Retention flags follow ordinary layered replacement unless locked.
- Native-tool target/role tables follow ordinary table replacement and locking
  semantics. Round 28 defines their validation, environment projection,
  fingerprinting, and sandbox contract. A policy rule's `native-tools` field
  is an array containing only `c-compiler` and/or `archiver`; it grants no role
  unless the same rule also explicitly sets `allow-build-script = true`.
- Rules may match `source = "path"` and the optional
  `source-tree-sha256 = "<64 lowercase hex digits>"` defined in Round 29.
  A path rule granting a native-tool role must include this digest. Ordinary
  path dependencies without build scripts remain governed only by
  `policy.path-roots`.
- Proxy, credential, and alternate-registry sections do not exist in config
  version 1. Rounds 31–33 add only the exact system-repository and generic
  required system-vendored path-patch portion of the schema.

Round 28 resolves the previously reopened native-build portion of this schema.
No generic command allowlist or inherited PATH is added.

### Round 19: resolved stage-2 repository and acquisition formats

#### Resolved repository format version 1

```text
<repository>/
  repository.toml
  objects/
    crates-io/
      sha256/
        <first-two-hex>/
          <full-64-hex-checksum>/
            package.toml
            index-record.json
            package.crate           # iff keep-artifacts
            source/                 # iff keep-sources
            source-manifest.json    # iff keep-sources
    seeded-git/
      sha256/
        <first-two-hex>/
          <source-tree-sha256>/
            package.toml
            source/
            source-manifest.json
  .staging/                          # writable repository only
    <unpredictable-transaction-id>/
```

- `repository.toml` contains only `format-version = 1` and
  `object-hash = "sha256"` initially. An existing unknown format is rejected.
- A crates.io object is addressed solely by its verified archive SHA-256.
  `package.toml` records format version, exact name/version, canonical crates.io
  source, checksum, archive/extracted sizes and file count, and retained forms.
  `index-record.json` is the exact sparse-index line used for resolution.
- Every archive entry must have a UTF-8 relative path under the exact
  `<crate>-<version>/` archive root. Lorry strips that one root when creating
  `source/`; all other path/root layouts are rejected.
- `source-manifest.json` is canonical versioned JSON, sorted by relative path,
  and records each directory/file's kind, portable mode, byte length, and each
  file's SHA-256. Lorry verifies the complete retained source tree before every
  build. Build-script sandboxing keeps repository/cache source read-only.
- Artifact-only objects are re-verified and safely extracted into Lorry's
  content-addressed build cache. Source-only objects retain the index evidence
  and source manifest after the staged archive is discarded. With both forms,
  builds use and verify the retained source.
- Existing objects are never modified. An object whose metadata/source does
  not match its checksum identity is repository corruption and a hard failure,
  not something `build` repairs.
- Writable transactions stage beneath the writable repository so object
  renames remain on one filesystem. Confirmation or pre-commit failure removes
  the transaction without touching `objects/`. The system repository never
  has Lorry-created staging.
- Multiple vendors may fetch, inspect, and commit concurrently because there is
  no mutable package index. Each object uses an atomic no-replace directory
  rename; a destination won by another process is accepted only after verifying
  identical immutable content. Concurrent vendoring in the same project is
  rejected using a project-scoped process-lifetime lock.
- A new/updated `Cargo.lock` is fully rendered and fsynced to a sibling
  temporary file before repository commit, then atomically renamed after the
  repository objects commit. Repository and project may be on different
  filesystems, so a final lockfile failure or crash can leave verified,
  user-approved but unreferenced objects. They are safe and never selected
  without a lock entry; deleting visible shared objects during rollback would
  be unsafe. Decline and all failures before commit still add no objects.
  Garbage collection is deferred; stale staging is diagnosed and ignored.

#### Resolved direct curl interaction

- Round 45 supersedes the former `lorry-fetch` protocol. Lorry invokes an
  upstream or compatible curl command directly, never through a shell or
  adapter.
- One curl process performs one public HTTPS GET. Curl emits the response body
  on stdout and a nonce-delimited status/final-URL/redirect/download-size
  trailer on stderr using `--write-out`; Lorry drains both streams with bounds.
- Curl does not follow redirects. Lorry validates each HTTPS redirect against
  the Stage-2 crates.io URL rules and starts at most five additional requests.
  It owns exclusive staging files, byte limits, status validation, parsing,
  archive hashing, policy, and commit.
- Ambient curl configuration, proxy, authentication, compression, and retry
  behavior are disabled. The exact argument vector, environment, stream
  grammar, error handling, Motor subset, and acceptance matrix are frozen in
  `curl-interaction.md`.

### Round 20: resolved stage-2 resolution and vendoring state machine

#### Resolved behavior

1. Load/validate configuration and the root/path manifests; acquire a
   process-lifetime project vendor lock; query rustc for the host and each
   configured vendor target's cfg set.
2. Read Cargo.lock v4 when present. Preserve every still-compatible locked
   selection, including a yanked selection. A selected locked registry package
   already in the repository is verified from stored evidence without network
   access.
3. Resolve a complete Cargo-compatible lock graph when the lock is absent or
   stale. The single-root resolver uses locked-compatible candidates first,
   otherwise Cargo-compatible candidate ordering/backtracking, resolver
   1/2/3 feature rules, Rust-version fallback, index schema 1/2 `features2`,
   all root features for lock coverage, all target-conditioned dependencies,
   and no unsupported source/dependency kinds. Cargo is a conformance oracle in
   tests only.
4. Independently compute the acquisition graph: only root default features
   (CLI feature selection is unsupported), across the union of
   `[vendor].targets` plus the optional host. Packages present solely for
   inactive root features or other targets remain legal lock entries but are
   not downloaded.
5. Re-evaluate effective policy from index/graph facts. Fetch remaining index
   records and archives through curl into Lorry-owned staging, verify checksums and
   safe extraction, inspect normalized manifests/licenses/build-script facts,
   calculate complete resource evidence, and apply post-fetch policy.
6. Present one deterministic summary sorted by package identity, followed by
   per-new-package approval prompts containing source, checksum, license,
   build-script status, size, and new transitive dependencies. Already present
   verified objects are not prompted again. `--accept-all` suppresses prompts
   only after every policy/integrity check passes.
7. Render the complete Cargo.lock v4 to a sibling temporary file in
   Cargo-compatible deterministic form. Stage all new repository objects.
   Until this point, rejection, interruption, or error commits nothing.
8. After approval, fsync staged files, atomically expose immutable objects, then
   atomically rename the new lockfile when one is needed. Apply the approved
   orphan-object behavior from round 19 if the final rename fails. Report every
   added/reused package and whether the lock changed.

#### Build-time lock/policy validation

- `build`, `run`, and `test` perform an offline consistency resolution of the
  selected command/target/default-feature graph against Cargo.lock, root/path
  manifests, and available immutable package manifests. A direct requirement,
  selected path graph, source, checksum, or dependency edge that cannot be
  satisfied by the lock is "stale" and fails with `lorry vendor` advice.
- Full unused lock entries do not need to be present in the repository for this
  selected-graph check. Registry contents are immutable by checksum, so stored
  index/package evidence is sufficient without refreshing the sparse index.
- Effective policy and resource limits are checked again offline for every
  selected non-path package on every build. Tightening policy therefore blocks
  a previously vendored object without deleting it. Path-root policy is also
  rechecked.
- Missing/corrupt objects fail; build commands never repair, resolve, rewrite,
  or contact curl.
- Stage 2 neither reads nor writes `Lorry.lock`. Root-manifest path patches and
  exact configured required vendored path patches are represented entirely by
  `Cargo.toml` and Cargo.lock. If `Lorry.lock` is present, Stage 2 rejects it
  rather than silently accepting a hidden source overlay.

### Round 21: resolved stage-1/2 compilation and build-script contract

#### Observed required unit behavior

- A release Linux `rush` build compiles one host build-script executable, runs
  it for the Linux target, compiles `libc` and `moto_rush` as dependency
  libraries with linker-plugin LTO, then compiles `rush` with fat LTO.
- A release Motor cross-build selects `moto_rt`, `moto_sys`, `moto_rush`, and
  `rush`; all are target units, and rustc receives both target and host
  dependency search paths.
- `cargo test --release --no-run` needs distinct panic-unwind dependency/library
  variants for test harnesses and panic-abort variants for the runnable
  `rush` binary. It compiles root library and binary unit-test harnesses plus
  each `tests/*.rs` crate, and supplies `CARGO_BIN_EXE_rush` and
  `CARGO_TARGET_TMPDIR` while compiling integrations.
- Cargo compiles a release build script with build-override-like settings
  (`embed-bitcode=no`, debug assertions off, no target release LTO), then runs
  it with target cfg/feature/package/profile variables. `libc` emits
  `rerun-if-changed=build.rs` and `rustc-cfg` directives.

#### Resolved unit/command model

1. Represent every compilation as an immutable unit key containing package
   identity/source, target identity/kind/name, compile kind (host or explicit
   target), enabled features, profile plus panic/LTO mode, compiler identity,
   Cargo-compatibility family, effective rustflags/linker/lints, build-script
   output identity, and dependency unit metadata.
2. Construct a deterministic DAG and topological schedule. Distinct panic,
   feature, profile, host/target, and harness contexts are distinct units even
   for the same package. Parallel scheduling may change log order but never
   unit keys, commands, or final bytes.
3. A versioned Cargo 1.97/1.98 adapter calculates profile defaults,
   build-script override behavior, LTO propagation, rustc flags, stable package
   identity, metadata/extra-filename hashes, artifact names, and primary output
   uplift. Golden Cargo-oracle fixtures cover every stage-1/2 unit shape.
4. Invoke rustc directly without a shell, with Cargo-compatible current
   directory, ordered arguments, JSON diagnostic/artifact output, feature
   cfg/check-cfg, dependency lint caps, manifest lints, `--extern` paths,
   target/host search paths, linker/rustflags, and emit modes. Final user-facing
   executables are atomically copied or hard-linked from hashed dependency
   artifacts exactly as applicable.
5. Query the selected rustc once per invocation for verbose version, host,
   sysroot, target cfg, target libdir, and supported print data. The exact query
   results and effective Cargo-compatibility family are unit/cache inputs.

#### Resolved build-script environment and protocol

- Compile each supported build script as a host binary, then execute it in the
  mandatory sandbox. Stage 1 supports no build-dependency edges; Stage 2
  compiles an approved dependency build script's transitive
  build-dependencies as host units and passes them with Cargo-compatible
  `--extern` arguments. Root build scripts remain dependency-free. The
  script's working directory is the package root; its `OUT_DIR` and private
  temporary directory are writable and everything else exposed by the sandbox
  is read-only.
- Supply the Cargo package/version fields, `CARGO_MANIFEST_DIR/PATH`,
  `CARGO_CFG_*`, `CARGO_FEATURE_*`, `DEBUG`, `HOST`, `TARGET`, `NUM_JOBS`,
  `OPT_LEVEL`, `OUT_DIR`, `PROFILE`, absolute `RUSTC`,
  `CARGO_ENCODED_RUSTFLAGS`, relevant dynamic-library search path, and
  `CARGO_MANIFEST_LINKS` for a `links` package, and `CARGO_PRIMARY_PACKAGE`
  only where Cargo does. Set `CARGO` to the running Lorry executable for
  identification, but the sandbox does not permit recursive tool invocation.
- Do not expose arbitrary parent environment, credentials, HOME, proxy
  variables, or a general executable PATH. This is an intentional stricter
  divergence from Cargo. Stage 2 may expose only the policy-declared native
  C compiler and archiver required by `ring` 0.17.14, through explicit
  target-specific tool variables. Pregenerated assembly is compiled through
  the C compiler; Stage 2 does not authorize a standalone assembler. Tool
  executable contents, fixed dispatch arguments, environment, and outputs are
  tracked. Undeclared ambient variables and arbitrary tools remain outside
  Stage 2. Temporary-directory variables point at the sandbox directory.
- Stage 2 accepts both `cargo:` and `cargo::` spellings of:
  `rustc-cfg`, `rustc-check-cfg`, `rustc-env`, `rustc-link-lib`,
  `rustc-link-search`, `rerun-if-changed`, `rerun-if-env-changed`, `warning`,
  and `error`. `rerun-if-changed` must resolve within the package source or
  assigned `OUT_DIR` as appropriate and is tracked, although Lorry may
  conservatively hash more source inputs. A `rustc-link-search` path must
  resolve inside the script's assigned `OUT_DIR`; linking ambient system
  libraries is not admitted by this subset. `rerun-if-env-changed` may name a
  variable in the approved build-script environment or any other
  syntactically valid variable name. A name outside the supplied safe
  environment is tracked as explicitly absent after `env_clear`; Lorry never
  imports its ambient parent value. The name and supplied value or explicit
  absence are unit inputs.
- Unknown directives and other link/metadata directives are actionable hard
  errors. Non-directive stdout is bounded diagnostic output. Nonzero exit,
  timeout, sandbox violation, malformed/oversized output, path escape, or an
  `error` directive fails the unit.
- The exact ordered parsed directives, complete `OUT_DIR` file manifest and
  contents, selected safe environment, build-script executable identity, and
  tracked source contents feed the downstream unit and cache identity.
- `CARGO`/manifest/output absolute paths necessarily differ from Cargo's in
  Lorry storage. A build script that embeds or derives target output from those
  paths is outside the already-agreed byte-identity promise.

### Round 22: resolved stage-2 content-addressed build cache

#### Resolved cache boundary

- Stage 1 has no artifact reuse. Stage 2 cache format 1 stores supported
  library metadata/rlib outputs and verified build-script
  `OUT_DIR`/directive results, including native objects/archives produced by
  the approved toolchain. It does not reuse final linked binaries,
  build-script executables, unit-test executables, integration-test
  executables, or bundle launchers.
- Final executables and harnesses are therefore linked on every invocation.
  This avoids claiming that a cache key captures opaque system-linker inputs.
  A later cache format may add linked artifacts only with a proven linker-input
  model.
- Build scripts are compiled and sandbox-executed on every invocation in stage
  2. Their deterministic outputs may match a stored entry and allow downstream
  library reuse, but Lorry does not skip approved dependency code execution
  based on incomplete Cargo-style rerun hints.

#### Unit key and source tracking

The cache lives under `target/lorry/.cache/v1/units/sha256/<prefix>/<hash>/`.
Its canonical versioned unit-key serialization hashes:

- Lorry executable identity/cache schema and Cargo-compatibility adapter
  family.
- Selected rustc binary content, verbose identity/query results, relevant host
  and target sysroot library contents, and compile target/cfg.
- For a native-producing build script, every approved C-compiler/archiver
  executable and queried identity, its complete ordered arguments and
  environment, and all native source/object/archive inputs and outputs.
- Complete ordered rustc arguments and the full rustc child environment digest,
  including effective rustflags/linker configuration.
- Package/source identity, manifest and lock selections, enabled features,
  profile/unit kind, target source, manifest lints, and dependency unit
  metadata/content hashes.
- For immutable registry sources, the verified repository object and source
  manifest. For root/path packages, all regular source inputs beneath the
  canonical package directory except `.git`, `target`, and Lorry output/cache.
  A rustc dep-info path outside the package root and that unit's assigned,
  content-tracked `OUT_DIR` is rejected in stages 1 and 2 rather than creating
  an unbounded ambient input.
- Parsed ordered build-script directives plus a canonical content manifest of
  `OUT_DIR`, the safe build-script environment digest, executable/source
  identity, and sandbox-contract version.

#### Cache integrity and concurrency

- A cache entry contains a canonical manifest of expected output filenames,
  kinds, sizes, and SHA-256 values. A hit re-hashes every output before reuse.
- Writers use unpredictable sibling staging, fsync content/manifest, and expose
  the completed entry with atomic no-replace rename. Concurrent identical
  writers accept only verified identical content.
- Failed/cancelled units are never cached. Partial staging is ignored. Corrupt
  cache entries produce a warning, are quarantined within Lorry's own target
  tree, and the unit rebuilds; dependency-repository corruption is never
  treated this way.
- Policy and lock validation always precede a cache lookup. Cache presence
  cannot bypass a newly tightened policy, missing dependency object, or stale
  lock.

### Round 23: resolved stage-1/2 CLI, process, and diagnostic contract

#### Resolved grammar

```text
lorry [+toolchain] [GLOBAL] build  [--release|-r] [--target TRIPLE]
lorry [+toolchain] [GLOBAL] run    [--release|-r] [--target TRIPLE] [-- ARGS...]
lorry [+toolchain] [GLOBAL] test   [--release|-r] [--target TRIPLE]
                                  [--test NAME] [--no-run] [--bundle]
                                  [-- ARGS...]
lorry [+toolchain] [GLOBAL] vendor [--accept-all]
lorry --help|-h
lorry --version|-V
lorry help [COMMAND]
```

- `+toolchain`, when present, is the first argument. Long value options accept
  `--name value` and `--name=value`. Duplicate options, unknown options,
  missing values, conflicting quiet/verbose, test arguments with `--no-run`,
  and options belonging to another command are usage errors.
- Global options are `--quiet|-q`, `--verbose|-v`, and
  `--color auto|always|never`. One verbose level shows redacted direct tool
  commands, unit/cache reasons, and effective configuration provenance. There
  is no stage-2 `-vv`, jobs flag, JSON message format, package/workspace
  selection, manifest path, output directory, feature flags, or arbitrary
  Cargo pass-through.
- `CARGO_TARGET_DIR` and Cargo `build.target-dir` are not honored because they
  would defeat the agreed isolated artifact root. If present, they produce an
  actionable error rather than being ignored. A Lorry-specific output override
  remains post-stage-2.

#### Resolved execution semantics

- `build` builds the root library and binary graph. `run` requires the single
  binary, finishes its build, then executes it from the package root with
  inherited terminal streams and user runtime environment, without a shell.
- Ordinary `test` builds all selected harnesses before execution, then uses
  Cargo's default fail-fast target order. `--test NAME` limits discovery/build
  to that integration target plus required libraries/program binary.
  Arguments after `--` go to each executed harness. `--no-run` prints the
  deterministic executable path(s).
- Bundle execution follows round 15 and deliberately runs all embedded
  harnesses to aggregate failures. Cross-target run/test invokes the configured
  runner as a parsed argument vector; bundle mode invokes the runner once.
- Run/test programs are user-requested runtime code and are not placed in the
  dependency build-script sandbox. Lorry forwards terminal signals where the
  platform supports them and returns the child/runner's exit status unchanged.
- Toolchain/compiler/build failures and Lorry operational errors return 101;
  CLI usage errors return 1; help/version return 0; an interactive interrupt
  returns 130 where the platform represents POSIX-style interruption.

#### Resolved human interface

- Progress, commands, warnings, prompts, and errors use stderr so child stdout
  remains usable. Default progress uses stable Cargo-familiar verbs such as
  `Compiling`, `Fresh`, `Finished`, `Running`, and `Bundling`, but does not copy
  Cargo's incidental spacing/timing text as an API.
- Rustc JSON diagnostics are rendered in order using rustc's supplied rendered
  text. Color defaults to auto based on the destination terminal, honors
  `NO_COLOR`, and is controlled explicitly by `--color`.
- Every Lorry error starts with a concise cause, then relevant package/target
  and source-location context, followed by an actionable suggestion where one
  exists. Unsupported semantics name the exact key/flag/directive and the
  stage-1/2 boundary.
- Vendor prompts use a controlling terminal when available, accept only
  `y`/`yes` or `n`/`no` case-insensitively, and default to no. If new approval
  is required without a terminal, vendoring fails before archive download and
  recommends `--accept-all`; EOF/decline commits nothing.
- Output never prints credentials or unredacted secret environment values.
  Verbose URLs and commands redact userinfo/query secrets even though stage 2
  supports only public crates.io.

### Round 24: per-stage self-buildability

#### Resolved core requirement

- Stage-1 core Lorry remains a dependency-free, single-binary package within
  its own stage-1 manifest/profile subset.
- A Cargo-oracle build of Stage-1 Lorry may supply the executable under test;
  this invocation exists only inside the compatibility/self-hosting test and
  is never a shipped, runtime, or user-workflow prerequisite. That executable
  builds the same revision into its isolated output tree on Linux and Motor.
  Release output is compared under the normal identity rules, and the produced
  Lorry repeats the build, proving the oracle seed is not operationally
  required. A direct one-file `rustc` seed is also kept as a Cargo-free
  bootstrap smoke path for the dependency-free Stage-1 source.
- Stage-2 core Lorry may add normal pure-Rust registry/path dependencies and
  dependency-free approved build scripts, but no capability stage 2 rejects.
  Its complete graph must satisfy the default-deny policy and be documented as
  part of Lorry's own dependency review.
- An installed stage-2 Lorry, with curl available only when vendoring is
  needed, vendors its graph and builds the same revision on Linux and native
  Motor. A second self-build verifies cache/warm-build behavior, while final
  executables are still relinked as required by round 22.
- An installed seed curl first populates curl's dependency graph. Stage-2 Lorry
  then builds `src/bin/curl`; that produced executable directly populates a
  second fresh repository from which Stage-2 Lorry builds curl again. This is
  a Stage-2 Linux and native-Motor acceptance gate.

### Round 25: stage-2 fetch-helper and `russhd` audit

#### Historical direction, superseded by Round 45

- Using the Rust `curl` crate does not avoid that boundary: it delegates to
  `curl-sys`/libcurl and therefore introduces a native library/link/build
  boundary of its own. A tiny handwritten FFI wrapper around a preinstalled
  system libcurl would make the Rust helper package easy to self-build, but
  would merely move the TLS implementation outside Lorry and would not prove
  that Lorry can build its own TLS graph.
- This round originally put the narrow blocking Rustls client in
  `lorry-fetch`. Round 45 retains the independent TLS dependency graph and
  self-build gate but moves the client to the general `src/bin/curl` utility;
  Lorry now invokes its curl-compatible CLI directly.
- Motor curl self-building is the final Stage-2 acceptance gate after the
  smaller `rush` and core-Lorry gates.
- Stage 2 supports transitive `[build-dependencies]` and their host-unit graph,
  `package.links`, `cargo:rustc-link-lib`, `cargo:rustc-link-search`,
  `cargo:rerun-if-env-changed`, the associated Cargo-compatible build
  environment, exact local path `[patch.crates-io]` replacements, and
  policy-declared sandboxed native tool execution. Tool identities, arguments,
  environment, generated objects, and archives participate in unit/cache
  identity. General Git dependencies and patch acquisition, procedural
  macros, and arbitrary build-script tools remain deferred.
- Provider sources used by this gate must be immutable, policy-approved local
  or vendored trees and must contain any pregenerated source/object material
  required to stay within the finally approved native-tool allowlist. No
  provider or native build receives a policy exemption merely because Lorry
  needs it.
- The bootstrap acceptance cycle is explicit: an installed seed curl
  populates a fresh dependency repository; Stage-2 Lorry builds Motor curl;
  the resulting executable populates another fresh repository; and Stage-2
  Lorry builds the same curl package again. This runs on Linux and native
  Motor, with Cargo/Lorry release identity comparisons where the equivalent
  Cargo build uses the same sources, patches, and native toolchain.
- The current `russhd` is not blocked by TLS. Even after adding the narrowly
  required Motor curl mechanisms, it would still require host procedural
  macro compilation/loading, a much larger dependency graph, general git patch
  sources, more build-script cases, and root dev-dependency handling. Adding
  all of that to stage 2 would erase most of the intended structural boundary
  between `rush` and the deferred complex-graph stage.
- The current `src/bin/russhd` therefore remains outside stages 1 and 2. It is
  a valuable later acceptance target for procedural macros, Git patches, and a
  large async/cryptographic graph, but its exact placement relative to
  `httpd-axum` is a stage-3-or-later decision and remains frozen.

#### Rustls cryptography-provider evaluation criteria (resolved in Round 27)

The provider evaluation used these agreed criteria:

- Do not default to `ring` merely because the repository has an existing Motor
  fork. That choice reflected the state of Motor cross-compilation roughly two
  years earlier and is not current evidence.
- At minimum, evaluate the maintained AWS-LC and `ring` provider options
  against current released versions. Other mature, security-appropriate
  providers may be considered, but an experimental provider is not chosen
  solely to make the graph appear more purely Rust.
- The evaluation must build real minimal HTTPS-client fixtures for Linux-musl,
  Linux-to-Motor cross-compilation, and native Motor using the current
  mlibc/LLVM C and C++ toolchain. It records the complete normal/build graph,
  source and license policy evidence, upstream maintenance/security posture,
  native languages and tools, build-script directives/environment, required
  Motor patches, binary-size impact, deterministic Cargo/Lorry command
  reproduction, and release byte-identity results.
- Prefer a maintained provider that works with the smallest reviewable graph
  and native-tool allowance, but do not trade away cryptographic maturity or
  correctness merely to minimize package count.
- The chosen provider must fit the agreed Stage-2 exclusions—no procedural
  macros, general Git acquisition, or arbitrary build tools—unless a newly
  discovered requirement is brought back for an explicit design decision.
- Provider selection fixes the exact local patch set, provider features,
  native tool roles, and Motor curl lock graph. Round 27 applies these
  criteria and selects current crates.io `ring` 0.17.14 with a new minimal
  reviewed Motor patch, not the repository's stale 0.17.8 Git fork.

### Round 26: Linux/cross/native test-harness structure

#### Resolved direction

- Lorry has a standalone host-driven native Motor test harness at
  `src/bin/lorry/test-native.sh`. It is independently invocable during Lorry
  development and is also callable from the repository's existing
  `src/tests/full-test.sh` workflow; it does not create a second incompatible
  VM/test mechanism.
- By default, `test-native.sh` builds/starts the selected existing Motor VM
  image, waits for it, runs the requested Lorry gate, and shuts it down with
  cleanup guaranteed on success, failure, or interruption.
- VM image construction is not part of boot timing. From launching the VM
  process until the SSH readiness probe succeeds, the host enforces a hard
  ten-second deadline in every mode. Lorry setup or compilation never extends
  or hides that deadline; fast sub-ten-second boot remains an independent
  Motor OS acceptance property.
- `test-native.sh --reuse-running-vm` skips VM build/start/stop and uses the
  established full-test SSH endpoint. `src/tests/full-test.sh` uses this mode
  so VM lifecycle ownership remains unambiguous.
- The native harness has a short smoke mode and an explicit `--full` mode.
  Repository `full-test.sh` runs the smoke mode by default. The longer
  self-build, fresh vendoring, and byte-identity cycles run through `--full`
  for milestone and portability-sensitive gates rather than slowing every
  repository full-test invocation.
- Linux is the continuous development loop. Every relevant change runs the
  fast unit/fixture tests and affected Linux Cargo-oracle comparisons before a
  native test is considered.
- Native Motor testing is a required gate:
  1. before Stage 1 closes;
  2. at the Stage-2 `rush` plus core-Lorry checkpoint;
  3. at final Stage-2 Motor curl closure; and
  4. after changes to portability-sensitive compiler discovery/invocation,
     target handling, filesystem/repository behavior, sandboxing, networking/
     certificates, process execution, or native-tool handling.
- Linux-to-Motor cross-build checks precede the corresponding native gate.
  Release artifacts are compared under the agreed Cargo/Lorry and cross/native
  byte-identity rules. Debug builds, command behavior, tests, and diagnostics
  are checked semantically.
- Cargo use remains confined to host-side compatibility/oracle preparation.
  The native Motor portion invokes only installed/staged Lorry, rustc, the
  approved native toolchain, and built test programs; it never assumes a
  native Cargo executable.
- Each gate uses fresh isolated Lorry output, configuration, dependency-
  repository, and test-extraction roots as appropriate. Warm-cache/self-build
  passes happen only after a clean pass, so stale host or VM state cannot make
  the clean acceptance case pass.
- Once the external prerequisites are available, the host uploads pristine
  sources/configuration/repository seed data through SFTP after boot beneath
  `/user/tmp/lorry/<run-id>/`. Guest `cp -r` creates any separate clean-pass
  work trees there and `rm -r` removes only that run-ID subtree. Before any
  recursive operation, the harness canonicalizes the path and requires it to
  be a strict child of `/user/tmp/lorry`; it rejects an unsafe, empty, `/`,
  `/user`, `/user/tmp`, `/user/tmp/lorry`, `/sys`, or otherwise non-owned
  target.
- Native-produced artifacts needed for identity comparison are transferred
  back to the Linux host and hashed there; the result does not depend on Motor
  having a particular checksum utility.
- Host-enforced timing accounts for phases separately:
  - VM readiness: at most 10 seconds, excluding image construction.
  - The pre-existing/non-Lorry smoke phase: at most 30 seconds.
  - The pre-existing/non-Lorry full Motor test phase: at most five minutes.
  - The Lorry-specific smoke phase has a separate five-minute deadline.
  - The Lorry-specific `--full` phase has a separate thirty-minute deadline.
    Lorry compile/link time is never charged to, or allowed to extend, the
    three non-Lorry limits above. The Lorry deadlines may be overridden
    explicitly by the test harness and should be tightened when measured
    Stage-1/2 workloads justify it.
- On failure or timeout, the host retrieves available Lorry logs, command/
  environment summaries, output manifests, and relevant comparison artifacts
  before VM shutdown into
  `src/bin/lorry/target/lorry/native-tests/<run-id>/`, then prints that path.
  Successful runs discard bulky artifacts and retain only their concise
  summary. An explicit test-harness keep option may retain a successful run.

Round 26's harness structure, ownership, staging, cleanup, evidence retention,
and initial timeout budgets are resolved. Exact commands and fixture contents
belong to the ordered implementation/acceptance plan.

### Round 27: measured Stage-2 Rustls-provider evaluation

This round records design-fixture results only. The fixtures live outside the
repository and are not Lorry implementation. Versions below are the current
released versions selected on 2026-07-19; the eventual Motor curl lockfile fixes
exact versions and checksums.

#### Measured common boundary

- Both candidates were evaluated with Rustls 0.23.42, `std` and TLS 1.2
  enabled, Rustls default features disabled, and `rustls-pemfile` 2.2.0.
  Neither selected graph contains a procedural macro.
- Rustls treats both AWS-LC and `ring` as first-party providers. Its current
  guidance recommends AWS-LC for performance and its complete feature set,
  including post-quantum algorithms, while describing `ring` as easier to
  build on more platforms but less feature-complete. Lorry's narrow crates.io
  HTTPS client does not itself require post-quantum algorithms. See the
  [Rustls provider guidance](https://github.com/rustls/rustls#cryptography-providers).
- Both providers can use only pregenerated Rust bindings/assembly plus a C
  compiler and archiver for the Stage-2 target set. No tested fixture selected
  a procedural macro, bindgen, or Git dependency. AWS's own non-FIPS platform
  documentation says CMake, bindgen, and Go are never required, although the
  `cmake` Rust crate remains an unconditional build dependency in the observed
  graph. See the
  [AWS-LC non-FIPS build requirements](https://aws.github.io/aws-lc-rs/platform_support.html#build-requirements-summary).
- Current `cc` 1.3.0 maps the unknown Motor target to
  `x86_64-unknown-none-elf`. Both candidates therefore need the approved
  target-specific compiler flag `--target=x86_64-unknown-motor` to occur later
  and override that inference. This is an exact toolchain environment value,
  not inherited ambient `CFLAGS`.
- Linux-to-Motor final linking uses the Motor Rust linker driver. On native
  Motor, the LLVM multicall can be represented to `cc` as fixed-prefix tool
  commands such as `/sys/tools/llvm/bin/llvm clang` and
  `/sys/tools/llvm/bin/llvm ar`; `cc` accepts a program followed by fixed
  arguments in its `CC`/`AR` environment values. Consequently neither
  candidate requires Perl, a general shell, or a new `/bin/ar` merely to
  invoke the native toolchain. The final configuration schema must represent
  and policy-lock the executable plus its fixed prefix arguments, not an
  arbitrary command string.

#### Comparison

| Measured property | AWS-LC | `ring` |
| --- | ---: | ---: |
| Exact provider/sys version tested | 1.17.3 / 0.43.0 | 0.17.14 |
| Non-root packages in Linux-musl/Motor union | 19 | 15 |
| Union compressed archives | about 11.6 MiB | about 3.1 MiB |
| Union extracted source | about 76 MiB | about 16 MiB |
| Largest provider source tree | 66.7 MB / 2,011 files | 7.8 MB / 392 files |
| Minimal unstripped Linux release fixture | 3,523,320 bytes | 1,296,736 bytes |
| Minimal unstripped Motor release fixture | 3,707,256 bytes | 1,975,464 bytes |
| Motor native objects/archives in measured build | 366 / about 13.7 MB | 45 / about 2.6 MB |
| Build-script captured output | about 286 KiB | about 7 KiB |
| Extra Stage-2 directive mechanism | `links` metadata/`DEP_*` | none |

The sizes are fixture comparisons rather than a promise for the completed
HTTP client, but the relative native-build and review burden is material. Both
graphs fit the agreed Stage-2 package, transaction, file-count, and captured-
output defaults.

#### AWS-LC findings

- Unmodified crates.io `aws-lc-sys` 0.43.0 successfully compiled and linked
  for Motor with the current mlibc/LLVM toolchain. An execution trace showed
  only the configured C compiler and LLVM archiver for its native build: no
  C++, CMake, `pkg-config` executable, Perl, bindgen, NASM, or Go was invoked.
- Motor already implements POSIX `getentropy()` in mlibc through
  `moto_rt_fill_random_bytes`. Unmodified AWS-LC does not recognize
  `__motor__`, selects its `/dev/urandom` fallback, and would fail at runtime
  because that device is absent. A one-line source patch classifying
  `__motor__` with AWS-LC's existing `getentropy` platforms compiled and linked
  successfully. Native execution still needs the gated Motor fixture.
- `aws-lc-sys` emits `include`, `libcrypto`, `root`, and `conf` metadata from
  its `links` build script. `aws-lc-rs` receives these as versioned `DEP_*`
  variables and re-emits them. Selecting AWS-LC would therefore expand Stage
  2 from rejecting unknown build-script directives to bounded Cargo-compatible
  `links` metadata forwarding: only a package declaring `links` may emit it;
  keys/values are size- and syntax-bounded; values go only to immediate
  dependent build scripts as `DEP_<LINKS>_<KEY>`; and all values are tracked
  as build/cache inputs. This is tractable but genuine structural scope.
- The exact build graph also includes `cmake`, `dunce`, `fs_extra`,
  `pkg-config`, `jobserver`, and a host `libc`. `cc`'s parallel feature falls
  back to the supplied `NUM_JOBS` if no inherited Cargo jobserver is present,
  so Lorry need not implement Cargo's jobserver protocol merely to compile the
  provider. Native Motor behavior remains part of the required native test.

#### `ring` findings

- Unmodified crates.io `ring` reaches the unsupported-target error in
  `getrandom` on Motor. The repository's older Motor Git fork is not suitable
  evidence for the current choice: it is based on 0.17.8, invokes Perl when
  built from its Git tree, and adds a now-obsolete no-system-headers rule that
  fails with the current Clang intrinsic headers.
- A fresh 0.17.14 crates.io archive retains pregenerated assembly and needs
  only two small Motor source changes: classify Motor under the existing
  x86-64 Linux ABI assembly set in `build.rs`, and admit Motor as an
  OS-random-backed target in `src/rand.rs`. With those changes it cross-
  compiles and links successfully using only the same C compiler and archiver.
  The obsolete no-system-headers change must not be carried forward.
- Motor curl can enable `getrandom` 0.2.17's existing `custom` feature and,
  on Motor only, register a small callback to
  `moto_rt_fill_random_bytes`. This uses Motor's existing OS random abstraction
  without patching `getrandom`, using its RDRAND fallback, or adding another
  package. The callback and the patched `ring` target classification compiled
  and linked in the Motor fixture; native execution remains gated.
- The `ring` build script emits only the Stage-2 directives already agreed:
  `rerun-if-env-changed`, `rerun-if-changed`, `rustc-link-lib`, and
  `rustc-link-search`. Its crates.io form performs no Perl generation.

#### Resolved provider decision

Stage 2 selects `ring` 0.17.14 for the Motor curl lock graph, using an exact
path patch to a system-vendored tree derived from the exact crates.io archive
plus the two Motor changes above. Host tools acquire the pinned Git provenance
and seed that tree into the system Lorry repository. The reasons are:

1. It satisfies the complete cryptographic feature set needed by the narrow
   Motor curl HTTPS subset and remains a first-party Rustls provider.
2. It uses the same native-tool classes as AWS-LC while producing a
   substantially smaller source, output, and compilation footprint.
3. It fits the already-agreed Stage-2 build-script protocol, preserving the
   intentional Stage-2 boundary instead of adding generic `links` metadata
   solely for Motor curl.
4. The current Motor port is small and is based on the released crates.io
   archive with pregenerated assembly, rather than retaining the stale Git
   fork or its Perl/no-sysroot assumptions.

AWS-LC is demonstrated to be a viable later provider rather than ruled out by
Motor's toolchain. Its one-line entropy patch and measured build are useful
future acceptance evidence. Supporting it is a post-Stage-2 decision and would
require a separately approved bounded `links`-metadata design.

The provider choice is fixed, while operational validation remains gated: the
same entropy-using fixture must run natively on Motor, a minimal verified HTTPS
exchange must succeed, and Cargo/Lorry plus cross/native release identity
checks must pass after the external SFTP/`cp -r`/`rm -r` gate is available.

### Round 28: exact Stage-2 native-tool representation

#### Resolved direction

- Native tools are configured per target triple and are never discovered by
  Lorry from ambient `PATH`, `CC`, `CFLAGS`, `AR`, or `ARFLAGS`. The host seed
  installer resolves the host-compatible `clang` and `ar` defaults once,
  canonicalizes their absolute paths, and writes them to a new Linux
  configuration; Cargo oracle builds are forced to that same pair. Clang keeps
  the current compilation inside the declared executable, whereas GCC invokes
  a separate `cc1` helper that the Stage-2 process closure does not admit.
  Explicit absolute installer arguments can select another closed pair. A
  build requiring a native tool fails before its build script runs if the
  selected target has no complete matching configuration. The diagnostic names
  the missing target and `lorry.toml` keys.
- Stage 2 has exactly two native-tool roles: `c-compiler` and `archiver`.
  A matching dependency-admission rule must explicitly grant each role with
  `native-tools = ["c-compiler", "archiver"]`; `allow-build-script = true`
  alone grants neither. The rule for the system-vendored `ring` path
  replacement is pinned by package name, exact version, required vendored
  source-tree digest, Git URL/commit provenance, and these two roles; its
  originating crates.io checksum is separately recorded provenance. Other
  packages may use the mechanism only through their own equally explicit
  policy rule; there is no package-name special case.
- Each role is an absolute executable `program`, a list of `prefix-args` that
  select a trusted multicall mode, and a list of role flags. For the C compiler
  those flags become target-specific `CFLAGS`; for the archiver they become
  target-specific `ARFLAGS`. All values are arrays in TOML rather than an
  arbitrary shell command. Stage 2 rejects NUL, ASCII whitespace within a
  program or individual argument, empty arguments, relative paths, shell
  metacharacter interpretation, and a program that is not a regular executable
  file.

  ```toml
  [native-tools."x86_64-unknown-motor".c-compiler]
  program = "/sys/tools/llvm/bin/llvm"
  prefix-args = ["clang"]
  flags = ["--target=x86_64-unknown-motor"]

  [native-tools."x86_64-unknown-motor".archiver]
  program = "/sys/tools/llvm/bin/llvm"
  prefix-args = ["ar"]
  flags = []
  ```

- Lorry serializes those arrays into only the target-specific `cc`-crate
  variables, for example `CC_x86_64_unknown_motor`,
  `CFLAGS_x86_64_unknown_motor`, `AR_x86_64_unknown_motor`, and
  `ARFLAGS_x86_64_unknown_motor`. It removes the unqualified, `HOST_*`,
  `TARGET_*`, hyphenated-target, and other target variants from the build-
  script environment so that `cc` cannot select a higher-precedence ambient
  value. Linux system/user configuration names absolute Linux tools in the
  same schema; repository policy remains portable and grants roles rather than
  embedding host paths.
- The executable bytes, canonical path, metadata, fixed prefix arguments,
  flags, target triple, and resulting environment are fingerprint inputs and
  appear in the audit record. The executable is opened/hashed before the build
  and checked for replacement before outputs commit.
- The mandatory build-script sandbox must enforce the configured executable
  and multicall prefix for every child execution and deny undeclared helper
  processes. Compiler self-execution is allowed only when it is the same
  configured executable in its verified compiler mode. If current Motor OS
  isolation cannot express this, Motor gains that feature outside the Lorry
  project; Stage 2 may not weaken the rule. Native provider validation proves
  the exact compiler/archiver process closure rather than adding a general
  tool directory.
- Cargo release-identity oracle builds receive the same four target-specific
  environment values constructed from `lorry.toml`. Lorry itself never reads
  Cargo's cache or ambient native-tool variables to obtain them.

This representation deliberately handles only the current `ring` requirement.
C++, a standalone assembler, `ranlib`, link-metadata forwarding, `pkg-config`,
CMake, arbitrary child tools, wrapper/cache programs, and general native-tool
discovery remain post-Stage-2.

### Round 29: local path dependency execution policy

#### Resolved direction

- The root package is explicitly selected user code rather than an admitted
  dependency. It does not need a dependency allow rule. Any supported root
  build script is still dependency-free and runs under the same filesystem,
  network, and process sandbox, but Stage 2 grants it no native-tool role.
- An ordinary local path dependency containing only Rust targets remains local
  and needs no package allow rule. The configurable `policy.path-roots`
  boundary still applies, and all path source inputs are included in unit
  fingerprints. This retains the previously agreed Cargo-like local
  development workflow.
- A path dependency does not need a `version` key, whether its path is
  relative, absolute, or the logical path of a verified vendored object. Its
  package name/version still come from the selected source manifest and must
  match Cargo.lock's path-package node. If `version` is present, Lorry enforces
  it. Crates.io dependencies remain externally resolved inputs and always
  require a version requirement.
- A local path dependency that contains a build script must match an allow
  rule with `source = "path"` and `allow-build-script = true`, even when
  `policy.default = "allow"`. A path dependency granted native tools must also
  list the exact Round-28 roles in that same rule.
- Version-1 policy adds an optional `source-tree-sha256` match field. It is the
  SHA-256 of Lorry's canonical, versioned path-source manifest: sorted relative
  UTF-8 paths plus file kind, portable executable mode, length, and content
  hash, excluding only `.git`, `target`, and Lorry's own output tree. Stage 1
  and 2 reject special files and source-tree symlinks rather than hashing an
  ambiguous external referent.
- A Stage-2 rule granting any native-tool role to a path dependency must
  include `source-tree-sha256`; a rule granting only sandboxed Rust build-
  script execution may include it but is allowed to be broader for an actively
  developed local crate. System policy can lock an exact rule/digest.
- Round 31 backs `ring`'s required logical path with an externally seeded
  system object. It therefore uses this path mechanism plus the stricter
  required-patch checks. A repository-local or user object may satisfy lookup
  only when its identity, provenance metadata, and complete source-tree digest
  equal the rule; an arbitrary same-named local tree is never a fallback.

This preserves low-friction pure-Rust local development while making the
privileged boundary explicit. It does not introduce acquisition or copying for
path packages, and it does not claim that Lorry can cryptographically prove
how a reviewed patched tree was derived from an upstream archive.

### Round 30: exact Stage-2 Motor curl dependency graph

#### Resolved registry graph and patch source model

The `src/bin/curl` manifest pins these direct requirements rather than using
floating requirements:

```toml
[dependencies]
rustls = { version = "=0.23.42", default-features = false, features = [
    "ring",
    "std",
    "tls12",
] }
rustls-pemfile = "=2.2.0"
getrandom = { version = "=0.2.17", features = ["custom"] }

[patch.crates-io]
ring = { path = ".lorry/vendor/ring-0_17_14/source" }
```

TLS 1.3 is always present in Rustls; `tls12` is retained deliberately for
secure endpoint compatibility rather than relying on crates.io/CDN endpoints
always negotiating TLS 1.3. Rustls defaults remain disabled so this does not
select AWS-LC, logging, or post-quantum provider features. The direct
`getrandom` dependency exists to register Motor's callback and unify its
`custom` feature with `ring`'s same 0.2.17 dependency.

For the configured Linux-musl, Motor, and current Linux host union, the exact
selected non-root graph is:

| Package | Source identity | Selected features | License | Privileged behavior |
| --- | --- | --- | --- | --- |
| `cc 1.3.0` | crates.io `c89588d05638b5b4594a3348a2d6c20277e43a7f5c5202b05cc56888475a47b8` | none | `MIT OR Apache-2.0` | host library used by `ring` build script |
| `cfg-if 1.0.4` | crates.io `9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801` | none | `MIT OR Apache-2.0` | none |
| `find-msvc-tools 0.1.9` | crates.io `5baebc0774151f905a1a2cc41989300b1e6fbb29aff0ceffa1064fdd3088d582` | none | `MIT OR Apache-2.0` | host library; no process on supported targets |
| `getrandom 0.2.17` | crates.io `ff2abc00be7fca6ebc474524697ae276ad847ad0a6b3faa4bcb027e9a4614ad0` | `custom` | `MIT OR Apache-2.0` | Motor callback registered by curl |
| `libc 0.2.186` | crates.io `68ab91017fe16c622486840e4c83c9a37afeff978bd239b5293d61ece587de66` | none | `MIT OR Apache-2.0` | dependency-free Rust build script; no native tool |
| `once_cell 1.21.4` | crates.io `9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50` | `alloc`, `race`, `std` | `MIT OR Apache-2.0` | none |
| `ring 0.17.14` | exact system-vendored path tree selected for all targets; Git URL/commit and crates.io archive `a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7` are seed provenance | `alloc`, `default`, `dev_urandom_fallback` | `Apache-2.0 AND ISC` | build script; C compiler and archiver |
| `rustls 0.23.42` | crates.io `3c54fcab019b409d04215d3a17cb438fd7fbf192ee61461f20f4fe18704bc138` | `ring`, `std`, `tls12` | `Apache-2.0 OR ISC OR MIT` | dependency-free selected build script; emits nothing |
| `rustls-pemfile 2.2.0` | crates.io `dce314e5fee3f39953d46bb63bb8a46d40c2f8fb7cc5a3b6cab2bde9721d6e50` | `default`, `std` | `Apache-2.0 OR ISC OR MIT` | none |
| `rustls-pki-types 1.15.0` | crates.io `764899a24af3980067ee14bc143654f297b22eaebfe3c7b6b211920a5a59b046` | `alloc`, `default`, `std` | `MIT OR Apache-2.0` | none |
| `rustls-webpki 0.103.13` | crates.io `61c429a8649f110dddef65e2a5ad240f747e85f7758a6bccc7e5777bd33f756e` | `alloc`, `ring`, `std` | `ISC` | none |
| `shlex 2.0.1` | crates.io `f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba` | `default`, `std` | `MIT OR Apache-2.0` | host library; no shell execution |
| `subtle 2.6.1` | crates.io `13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292` | none | `BSD-3-Clause` | none |
| `untrusted 0.9.0` | crates.io `8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1` | none | `ISC` | none |
| `zeroize 1.9.0` | crates.io `e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e` | `alloc`, `default` | `Apache-2.0 OR MIT` | none |

The Cargo.lock v4 complete all-target graph additionally records but does not
vendor/admit for the configured target union:

| Package | crates.io checksum |
| --- | --- |
| `wasi 0.11.1+wasi-snapshot-preview1` | `ccf3ec651a847eb01de73ccad15eb7d99f80485de043efb2f370cd654f4ea44b` |
| `windows-sys 0.52.0` | `282be5f36a8ce781fad8c8ae18fa3f9beff57ec1b52cb3de0789201425d9a33d` |
| `windows-targets 0.52.6` | `9b724f72796e036ab90c1021d4780d4d3d648aca59e491e6b98e725b84e99973` |
| `windows_aarch64_gnullvm 0.52.6` | `32a4622180e7a0ec044bb555404c800bc9fd9ec262ec147edd5989ccd0c02cd3` |
| `windows_aarch64_msvc 0.52.6` | `09ec2a7bb152e2252b53fa7803150007879548bc709c039df7627cabbd05d469` |
| `windows_i686_gnu 0.52.6` | `8e9b5ad5ab802e97eb8e295ac6720e509ee4c243f69d781394014ebfe8bbfa0b` |
| `windows_i686_gnullvm 0.52.6` | `0eee52d38c090b3caa76c563b86c3a4bd71ef1a819287c19d586d7334ae8ed66` |
| `windows_i686_msvc 0.52.6` | `240948bc05c5e7c6dabba28bf89d89ffce3e303022809e73deaefe4f6ec56c66` |
| `windows_x86_64_gnu 0.52.6` | `147a5c80aabfbf0c7d901cb5895d1de30ef2907eb21fbbab29ca94c5b08b1a78` |
| `windows_x86_64_gnullvm 0.52.6` | `24d5b23dc417412679681396f2b49f3de8c1473deb516bd34410872eff51ed0d` |
| `windows_x86_64_msvc 0.52.6` | `589f6da84c646204747d1270a2a5661ea66ed1cced2631d546fdfb155959f9ec` |

The shipped development policy uses exact name/version/source/checksum/license
allow rules for all 14 selected registry packages. Only `libc 0.2.186` and
`rustls 0.23.42` set `allow-build-script = true` without native-tool roles.
The separately pinned `ring` rule sets `allow-build-script = true` and grants
both native-tool roles. Cargo.toml explicitly selects its verified vendored
path view on Linux and Motor, and Cargo.lock records it as a path package; the
14 registry identities and features above are unaffected. Lock-only target
packages require no allow rule or archive acquisition unless the configured
vendoring-target set later selects them; then ordinary policy must admit them
before fetching.

Any version, checksum, selected-feature, patch-tree, license, build-script, or
target-union change is a reviewed curl graph change. It is not silently
accepted merely because the dependency remains semver-compatible.

### Round 31: permanent `ring` patch layout and path-tree identity

#### Rejected checked-in-source direction

The initially proposed `src/third_party/ring-0.17.14/` path package and sibling
patch file are rejected. The patched `ring` source remains in its Git
repository and is not copied into the main Motor OS repository.

#### Resolved architecture

- Host bootstrap tools, outside Lorry, acquire and verify the pinned `ring`
  Git source and seed it into a system Lorry dependency repository. Lorry and
  Motor curl do not need a Git network client to bootstrap themselves.
- Host tools seed the required system-vendored crates both into the host's
  Lorry environment and into the generated Motor OS guest image. A native
  build must not depend on fetching its own TLS provider before Motor curl
  exists.
- The host seed contains the complete selected Stage-2 bootstrap graph,
  including the exact Git `ring` selected on both Linux and Motor. The
  unselected upstream crates.io `ring` archive is provenance, not a second
  build source. Lock-only packages for unconfigured targets need not be seeded.
- The host and guest seeds represent the same package/source identities and
  verified contents. Lorry re-verifies them before use; “system seeded” is not
  an integrity or policy bypass.
- The system seed is distinct from the fresh writable repository used to prove
  native `lorry vendor` and the second Motor curl self-build cycle.
- `src/bin/curl/Cargo.toml` explicitly contains a `[patch.crates-io]` path entry
  naming the stable logical `ring` artifact path. Cargo.lock contains the
  resulting path-package entry. The system/base `lorry.toml` rule requires
  this path source and independently pins the seed's Git URL/commit
  provenance and source-tree digest.
- The Motor system seed is `/sys/tools/rust/lorry/vendor`. Its path and patch
  rule live in `/sys/tools/rust/cfg/lorry.toml` and may be locked against
  user/repository weakening.
- Linux never uses `/etc`. Its control root is exactly
  `$HOME/.config/lorry/`: the base config is
  `$HOME/.config/lorry/lorry.toml`, the externally seeded system repository is
  `$HOME/.config/lorry/system/vendor`, and its ordinary writable repository is
  `$HOME/.config/lorry/vendor`. The config stores expanded absolute paths;
  version-1 TOML values still do not expand `~` or environment variables.
- The installed full system seed is read-only to Lorry. Fresh-fetch acceptance
  tests use a separate isolated system seed containing only the externally
  required Git replacement plus an empty writable repository, so registry
  acquisition is actually exercised.
- General Git acquisition/resolution remains post-Stage-2 and no checked-in
  path-patch fallback is permitted. Round 33 defines the generic required-
  patch validation; no hidden lock overlay is used.

### Round 32: layered repositories and seeded-Git object

#### Resolved direction

Version-1 configuration replaces the single repository path with three
non-overwriting roles:

```toml
[repositories]
# Optional except when a selected required patch uses a seeded system object.
system = "/absolute/read-only/system/vendor"
# Optional user-level writable repository.
user = "/absolute/user/vendor"
# Optional repository-specific writable repository.
local = "/absolute/repository/vendor"
keep-artifacts = true
keep-sources = true
```

- Motor permits `repositories.system` only in
  `/sys/tools/rust/cfg/lorry.toml`; Linux permits it only in
  `$HOME/.config/lorry/lorry.toml`. A repository-local file cannot introduce
  or replace the system repository. The trusted/base layer normally locks it.
  Acceptance tests use an isolated Motor system config or isolated Linux
  `HOME`, not a command-line bypass.
- Motor permits `repositories.user` only in `/user/cfg/lorry.toml`; Linux
  permits it only in `$HOME/.config/lorry/lorry.toml`.
  `repositories.local` is permitted only in the nearest repository-root
  `lorry.toml`. Every value is an absolute path. These layer-owned roles are
  retained together rather than replacing one another during configuration
  merge.
- The canonical local, user, and system paths must be pairwise distinct and
  none may contain another. Lorry never writes, repairs, quarantines, garbage-
  collects, or creates staging under the system repository. `lorry vendor`
  stages and commits under `local` when configured, otherwise under `user`; if
  neither exists in effective configuration, it fails before acquisition with
  an exact configuration example.
- Build/resolution searches local, user, then system. An identity absent from
  one layer falls through. Registry objects are addressed by exact crates.io
  archive checksum, so an identity present in multiple layers must verify
  identically. A present corrupt, mismatched, or policy-rejected higher-layer
  object is a hard error, not precedence and not a reason to continue to a
  lower layer.
- An absent configured local/user repository is treated as an empty lookup
  layer; `lorry vendor` may create it transactionally after validating its
  existing parent. The configured system repository must already exist when
  required. Already present valid objects are not copied or presented for
  approval again, but their effective admission policy is rechecked on every
  command.
- A Git-provenanced source object used by a required path patch is guaranteed
  to be seeded in the system repository, but lookup follows the common
  repository-local, user, then system order. A higher layer satisfies the rule
  only if its complete object identity, provenance metadata, and source-tree
  digest equal the configured requirement. A present wrong or corrupt object
  is an error and cannot shadow the system object by causing silent fallback.
  If no valid object exists, the diagnostic reports the exact URL/commit/tree
  digest and tells the user to run the host bootstrap/image-seeding workflow;
  it does not suggest that Stage-2 `lorry vendor` can fetch Git.
- Retention flags govern newly written crates.io objects. The Stage-2 system
  bootstrap seed retains both verified crates.io archives and extracted source
  trees; its Git object retains the verified source tree and metadata but need
  not contain a Git repository, checkout metadata, or bundle.

Repository format 1 uses source-kind namespaces:

```text
<repository>/
  repository.toml
  objects/
    crates-io/
      sha256/<first-two-hex>/<archive-sha256>/
        package.toml
        index-record.json
        package.crate
        source/
        source-manifest.json
    seeded-git/
      sha256/<first-two-hex>/<source-tree-sha256>/
        package.toml
        source/
        source-manifest.json
  .staging/                    # local/user repositories only
```

- The crates.io object is the Round-19 object with only its namespace made
  explicit. `repository.toml` still declares format version 1 and SHA-256.
- A seeded-Git `package.toml` records format version, package name/version,
  exact Cargo source spelling, exact HTTPS repository URL, requested full
  revision, resolved 40-hex commit, Git tree ID, optional package
  subdirectory, `source-tree-sha256`, license expression, extracted bytes/file
  count, and `retained-source = true`. Stage 2 accepts only the exact
  `https://github.com/moturus/ring.git`/commit object selected by the system
  patch; this is a format, not general Git-source permission.
- The host seed workflow verifies that the checkout commit and Git tree match
  the configured source, removes `.git` and excluded build outputs, rejects
  links/special files, writes the immutable object transactionally, and
  produces identical host/guest object contents. This Git-to-source
  attestation is the host bootstrap tool's responsibility. Lorry has no Git
  parser and honestly verifies only the locked metadata plus the complete
  stored source-tree digest.
- Both path-package policy and seeded-Git objects use the Round-31 streaming
  `lorry-source-tree-v1` identity: sorted UTF-8 relative paths, entry kinds,
  portable executable bits, file lengths, and file SHA-256 values. Timestamps,
  ownership, and all other permission bits are excluded so host/guest seeding
  need preserve only names, bytes, and executability rather than general Unix
  metadata. Symlinks and special files remain unsupported.
- Source trees and manifests are rehashed before and after each build. The
  selected artifact tree is exposed to the sandbox as a read-only build-script
  input and never with `.git`, regardless of which repository layer supplied
  it. Cache/unit identities include the Cargo logical path-package identity,
  locked seed provenance, independent SHA-256 source-tree identity, and the
  supplying repository layer.

The full production seed contains every selected Stage-2 bootstrap registry
object plus the seeded-Git `ring` identity used throughout the Linux/Motor
target union. The upstream crates.io `ring` archive is retained only as host
provenance for the fork, not as a selected build object. The minimal
fresh-fetch fixture contains only the seeded-Git `ring` object; all registry
objects must then be obtained by Lorry invoking curl into its separate writable
repository.

### Round 33: explicit required path-patch validation

#### Agreed direction

- `lorry.toml` describes crates that projects must explicitly patch to a
  verified logical Lorry artifact path. It never silently changes dependency
  sources.
- The mechanism is generic. Rule IDs are arbitrary and unique; rules may
  require `ring`, `tokio`, or another crates.io package without crate-specific
  Lorry code. Rules accumulate across layers, later layers cannot erase earlier
  requirements, and conflicting requirements fail with both provenances.
- The initial `ring 0.17.14` rule is unconditional: every selected reference on
  Linux or Motor must resolve through the required path patch. Conditional/
  target-flexible required-patch rules are deferred to Stage 3 or later.
- Cargo.toml must contain a semantically matching root
  `[patch.crates-io]` path entry. Cargo.lock v4 must contain the selected
  `ring 0.17.14` path-package node rather than a crates.io or Git source.
  Lorry refuses build/run/test if either side is wrong and prints the rule
  provenance, a ready-to-paste manifest snippet, and the appropriate vendor or
  host-seeding action. Builds never edit Cargo.toml or Cargo.lock.
- Cargo's version-4 lock format does not record a filesystem path for a path
  package: its absence of `source` and `checksum`, together with the
  name/version/dependency node, is the standard Cargo-compatible path-package
  representation. Lorry therefore verifies the actual source path and tree
  from Cargo.toml plus `lorry.toml`; it cannot place a literal path in
  Cargo.lock without breaking Cargo compatibility.
- The replacement tree remains acquired from pinned Git by external host
  tools, stored and verified in the system Lorry repository, and exposed to
  Cargo/Lorry as a path source. Cargo Git dependency and patch forms remain
  unsupported in Stage 2.
- Required-source validation and dependency admission are separate. A correct
  path patch does not bypass source-tree integrity, policy, build-script/native
  tool permission, or limits; an allow rule does not excuse a missing patch.
- Stage 2 does not use `Lorry.lock`; a present file is rejected as an unknown
  hidden overlay.

#### Resolved logical path and repository fallback

An absolute Cargo.toml path cannot satisfy the already-agreed portability
model: the Linux system repository is below `$HOME/.config/lorry/`, while the
Motor repository is `/sys/tools/rust/lorry/vendor`. Cargo does not expand `~`,
environment variables, or Lorry configuration in a manifest path. Naming the
true absolute source would therefore require a different manifest for each
Linux user and another manifest for Motor.

The absolute path is also a Cargo artifact-identity input. A local probe built
the same package twice from byte-identical dependency trees at two absolute
paths, keeping the application path and all other inputs fixed. Cargo emitted
different dependency and application `-C metadata` values and different final
release binaries. The checked-in manifest must therefore retain one stable
logical path:

```toml
[required-patches.crates-io.ring-0_17_14]
name = "ring"
version = "=0.17.14"
upstream-checksum = "a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7"
git-url = "https://github.com/moturus/ring.git"
git-commit = "b1dad2579de791d0c31ad33300187e584ba6c268"
source-tree-sha256 = "776e07288265b7ececb54ef5ed914c3a6093f00b49bd4d12d34764325659b351"

[policy.rules.allow-ring-0_17_14]
action = "allow"
name = "ring"
version = "=0.17.14"
source = "system-vendored-path"
source-tree-sha256 = "776e07288265b7ececb54ef5ed914c3a6093f00b49bd4d12d34764325659b351"
license = "Apache-2.0 AND ISC"
allow-build-script = true
native-tools = ["c-compiler", "archiver"]
```

Cargo.toml then contains the same portable entry on both hosts:

```toml
[patch.crates-io]
ring = { path = ".lorry/vendor/ring-0_17_14/source" }
```

- The required-patch rule ID is also the safe logical artifact name; Stage
  2 rule IDs admit only ASCII letters, digits, `_`, and `-`. Lorry derives
  `.lorry/vendor/<rule-id>/source`, so `lorry.toml` gains no relative path
  value and preserves its version-1 absolute-path rule for actual configured
  filesystem paths.
- For an ordinary Cargo path dependency, the declared filesystem path must
  exist and remains local exactly as Round 29 specifies. Repository fallback
  is enabled only when the normalized path is exactly the derived logical path
  of an applicable `required-patches` rule. This does not turn arbitrary broken
  path dependencies into package searches.
- Required-patch rules independently declare and enforce the guarded package
  version. The corresponding Cargo path patch does not need a redundant
  dependency version key; Lorry verifies the selected source manifest and
  Cargo.lock path-package version against the rule.
- The logical path is not implicitly materialized beneath the crate and Lorry
  does not test that literal path as an ordinary dependency directory. It
  looks up the exact rule identity and digest through the configured absolute
  artifact repositories in order: repository-local, user, then system. An
  absent identity falls through to the next layer. A present but corrupt,
  mismatched, or policy-rejected identity is an error rather than a reason to
  hide the problem by falling through.
- The lookup result supplies physical source bytes, while dependency
  resolution and Cargo-compatible `-C metadata` calculation retain the
  manifest's normalized logical path and path-package Cargo.lock node. The
  physical repository path is a cache/fingerprint and audit input, not a Cargo
  package-identity input.
- No `.lorry/vendor` directory, copy, hard link, or symlink is required in the
  project. Motor OS needs no new symlink facility. `lorry vendor` populates an
  admitted writable artifact repository; it does not materialize this logical
  path in every consuming project.
- A direct Cargo invocation necessarily reports a missing path when no local
  artifact is materialized. This is an intentional required-patch extension,
  analogous to the already allowed case where Lorry's configured Motor patch
  succeeds and Cargo does not. Ordinary in-scope projects without this
  extension retain direct Cargo compatibility.
- Cargo-oracle tests may have the host fixture generator materialize the exact
  verified source temporarily at the logical local path. This disposable test
  input is not normal Lorry behavior. Lorry is then tested without that local
  source, resolving the same identity from the system repository.
- A pure-Rust probe found that compiling from the physical repository source
  with the logical Cargo `-C metadata` produced a different intermediate
  `.rlib` but a byte-identical final stripped release binary. The contract is
  final executable identity, not intermediate archive identity.
- Stage-2 acceptance repeats that Cargo-oracle comparison with the actual
  patched `ring` build script and separately compares Linux-cross and
  Motor-native final executables. Build-script environment and source-path
  handling are not assumed to be path-insensitive: any embedded host-specific
  path or output difference fails the gate and must be resolved before Stage 2
  closes.

### Round 34: exact patched-`ring` Git seed

#### Local evidence

- Existing Motor manifests pin
  `https://github.com/moturus/ring.git?branch=motor-os_2025-09-20` at
  `e9cc4c62bd3883bb6b09462e9decf10c3e583cb5`.
- That commit is `ring 0.17.8`, not the selected `0.17.14`. Relative to its
  parent it enables `getrandom`'s `rdrand` feature, admits Motor to the Linux
  ABI set, adds a Motor target-sysroot bypass in `build.rs`, and admits Motor
  in `src/rand.rs`.
- It therefore cannot be the Stage-2 Lorry seed: its version and dependency
  graph differ, and two of its legacy choices contradict the agreed custom
  `getrandom` callback and the successfully probed current LLVM toolchain path.

#### Resolved prerequisite

- The externally maintained `moturus/ring` branch `motor-os-0.17.14` resolves
  to fetchable commit `b1dad2579de791d0c31ad33300187e584ba6c268`,
  directly on upstream `ring 0.17.14` commit
  `2723abbca9e83347d82b056d5b239c6604f786df`.
- Its Motor delta contains only the two already validated source changes:
  classify Motor in the x86_64 Linux-ABI pregenerated-assembly set in
  `build.rs`, and admit Motor in `src/rand.rs`'s supported OS list. It does not
  enable `getrandom/rdrand` or retain the old target-sysroot bypass.
- The fork commit also removes three upstream GitHub-only CI/issue-template
  files. Review confirmed that these removals do not change packaged or built
  source; the only product-source changes are the two lines above.
- A descriptive branch such as `motor-os-0.17.14` is an acquisition aid only.
  All trusted configuration and seed metadata pin the final 40-hex commit;
  branch movement never changes an admitted object.
- The exact Git tree is `824d5b8e9755603070a8167e0c5529acb627d956`.
  Exporting that tree without `.git` yields 414 regular files, 71 directories,
  11,764,800 file bytes, and the `lorry-source-tree-v1` digest
  `776e07288265b7ececb54ef5ed914c3a6093f00b49bd4d12d34764325659b351`.
  Round 33 and the checked-in seed/config inputs contain these concrete values.
- Human review establishes that the fork has the intended upstream baseline
  and patch. Lorry does not claim to derive or prove a Git diff from the
  crates.io archive checksum; it verifies the configured commit metadata and
  complete seeded tree bytes.

### Round 35: `.crate` decompression and archive parsing

#### Measured constraints

- A crates.io `.crate` file is a gzip-compressed tar archive. Rust's standard
  library supplies neither DEFLATE/gzip decoding nor tar parsing, and Stage 2
  cannot invoke ambient `gzip` or `tar` executables on Linux or Motor.
- A disposable all-Rust probe selected `flate2 1.1.9` with
  `default-features = false, features = ["rust_backend"]` and cross-checked
  successfully for `x86_64-unknown-motor`.
- That exact probe graph contains six non-root pure-Rust packages:

| Package | crates.io checksum | License |
| --- | --- | --- |
| `flate2 1.1.9` | `843fba2746e448b37e26a819579957415c8cef339bf08564fe8b7ddbd959573c` | `MIT OR Apache-2.0` |
| `crc32fast 1.5.0` | `9481c1c90cbf2ac953f07c8d4a58aa3945c425b7185c9154d67a65e4230da511` | `MIT OR Apache-2.0` |
| `cfg-if 1.0.4` | `9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801` | `MIT OR Apache-2.0` |
| `miniz_oxide 0.8.9` | `1fa76a2c86f704bdb222d66965fb3d63269ce38518b83cb0575fca855ebb6316` | `MIT OR Zlib OR Apache-2.0` |
| `adler2 2.0.1` | `320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa` | `0BSD OR MIT OR Apache-2.0` |
| `simd-adler32 0.3.9` | `703d5c7ef118737c72f1af64ad2f6f8c5e1921f818cdcb97b8fe6fc69bf66214` | `MIT` |

- `crc32fast` has a dependency-free Rust build script, already within Stage
  2's approved build-script capability; the other five selected packages have
  no build script or native tool.
- Adding `tar 0.4.46` with default features disabled expands the host graph and
  unconditionally selects `filetime 0.2.27`. A measured Motor cross-check
  fails because `filetime` selects Unix implementation code while Motor does
  not expose `std::os::unix` or a `cfg(unix)` `libc` dependency. Patching that
  graph solely to read a narrow archive format is not justified.

#### Resolved design

- Stage-2 core Lorry directly pins `flate2 1.1.9` with only its pure-Rust
  backend and the exact graph above. This is the archive portion of the
  complete reviewed core graph in Round 36; it is seeded by the external host
  bootstrap and must pass the normal default-deny policy and Stage-2
  self-build gates.
- Lorry implements its own small streaming tar reader/extractor rather than
  importing the general `tar` crate. It supports only the formats needed for
  valid crates.io packages: v7/ustar regular files and directories, ustar
  prefix paths, GNU long-name records, and per-entry POSIX PAX records for
  `path` and `size`. It accepts UTF-8 package paths only.
- The reader validates header checksums and numeric fields, requires exactly
  one `<name>-<version>/` archive root, enforces the configured compressed,
  expanded-byte, file-count, path-length, and per-file limits while streaming,
  and rejects duplicate/conflicting entries.
- Absolute paths, `..`, empty/interior-dot components, links, sparse files,
  devices, FIFOs, sockets, global/unknown PAX keys, unknown type flags,
  malformed padding, and nonzero trailing archive data are hard errors.
  Timestamps, owners, groups, and non-executable permission bits are ignored;
  only the portable executable bit is retained in the source manifest.
- Extraction occurs only inside a newly created unpredictable private staging
  directory. Files use exclusive creation, every parent is revalidated as a
  real directory, and any race/type mismatch aborts the transaction. No
  partially extracted tree becomes a repository object.
- `flate2` verifies the gzip CRC and length. Lorry accepts one gzip member and
  rejects trailing bytes or concatenated members for a deliberately canonical
  `.crate` subset.
- Parser fixtures include every accepted tar variant plus checksum, truncation,
  gzip, bomb-limit, duplicate, traversal, link, PAX, GNU-long-name, and
  filesystem-race rejection cases. Every fixed Stage-2 crates.io archive must
  extract to the same file-name/content manifest on Linux and Motor.

### Round 36: Stage-2 core parsing and integrity dependencies

#### Resolved dependency boundary

- Stage-1 Lorry remains dependency-free and uses only its deliberately tiny
  Stage-1 manifest/config readers. Stage 2 replaces those readers rather than
  growing a home-built general TOML implementation.
- Existing unpatched use by `src/sys` or another `src/bin` package is accepted
  as useful Motor-portability and review evidence. It is not an automatic
  policy exemption: Lorry still pins exact versions/features, records the full
  graph, and admits every selected package through ordinary default-deny rules.
- Stage-2 core Lorry has these seven exact direct registry dependencies:

```toml
[dependencies]
clap = { version = "=4.6.0", default-features = false, features = [
    "error-context",
    "help",
    "std",
    "suggestions",
    "usage",
] }
flate2 = { version = "=1.1.9", default-features = false, features = [
    "rust_backend",
] }
semver = { version = "=1.0.26", default-features = false, features = ["std"] }
serde = { version = "=1.0.228", default-features = false, features = ["std"] }
serde_json = { version = "=1.0.150", default-features = false,
               features = ["std"] }
sha2 = { version = "=0.10.8", default-features = false,
         features = ["force-soft", "std"] }
toml_edit = { version = "=0.22.26", default-features = false,
              features = ["parse"] }
```

- Stage 2 uses Clap's builder API, never its derive feature. The leading
  rustup-style `+toolchain` token is removed by Lorry's small pre-parser before
  Clap sees the remaining grammar. Lorry renders/intercepts Clap errors to
  preserve Round 23's exit codes, stream choice, color policy, and diagnostics.
- `flate2` and its exact graph are resolved in Round 35.
- `toml_edit` is used only as a standards-compliant, source-spanned TOML 1.0
  parser for Cargo.toml, Cargo.lock, Cargo configuration, `lorry.toml`, and
  repository metadata. Its Serde, display, performance, and proc-macro-related
  features remain disabled. Lorry converts the parsed document into its own
  narrow typed model and applies all supported-key and semantic checks. TOML
  1.1-only syntax is outside the Stage-1/2 subset and receives a parse error
  with that limitation named.
- `semver` supplies Cargo-flavored version/version-requirement parsing and
  matching. Its Serde feature remains disabled. Lorry still owns dependency
  candidate ordering, feature resolution, target selection, lock behavior,
  and policy; using `semver` does not import Cargo's resolver.
- Lorry writes Cargo.lock and its own metadata with small deterministic writers
  for the exact versioned formats in this plan. It does not enable a general
  TOML serializer merely to emit those closed schemas.
- Sparse-index records and source manifests use `serde_json` without derive. A
  small hand-written Serde visitor enforces
  duplicate-key rejection plus byte, nesting, string, collection, and
  node-count limits while constructing the bounded value/schema. Lorry either
  rejects or explicitly ignores only the forward-compatible fields named by
  that schema.
- `sha2` supplies streaming SHA-256 for archives, files, source trees,
  repository/cache manifests, tools, and unit keys. `force-soft` avoids a
  runtime backend distinction; the output is still checked against standard
  known-answer vectors, chunk-boundary partitions, large streams, and host
  `sha256sum` oracles.
- Hex encoding/decoding, canonical closed-schema JSON/TOML rendering, and Cargo
  cfg-expression parsing remain small in-core modules with exhaustive
  malformed-input, depth/size, and round-trip fixtures.

#### Exact selected graph

A combined offline oracle fixture selected the same 32 non-root packages for
x86_64 GNU Linux, x86_64 musl Linux, and x86_64 Motor, and successfully
cross-checked the complete graph for Motor:

| Package | Version | crates.io checksum |
| --- | --- | --- |
| `adler2` | `2.0.1` | `320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa` |
| `anstyle` | `1.0.14` | `940b3a0ca603d1eade50a4846a2afffd5ef57a9feac2c0e2ec2e14f9ead76000` |
| `block-buffer` | `0.10.4` | `3078c7629b62d3f0439517fa394996acacc5cbc91c5a20d8c658e77abd503a71` |
| `cfg-if` | `1.0.4` | `9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801` |
| `clap` | `4.6.0` | `b193af5b67834b676abd72466a96c1024e6a6ad978a1f484bd90b85c94041351` |
| `clap_builder` | `4.6.0` | `714a53001bf66416adb0e2ef5ac857140e7dc3a0c48fb28b2f10762fc4b5069f` |
| `clap_lex` | `1.1.0` | `c8d4a3bb8b1e0c1050499d1815f5ab16d04f0959b233085fb31653fbfc9d98f9` |
| `cpufeatures` | `0.2.17` | `59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280` |
| `crc32fast` | `1.5.0` | `9481c1c90cbf2ac953f07c8d4a58aa3945c425b7185c9154d67a65e4230da511` |
| `crypto-common` | `0.1.7` | `78c8292055d1c1df0cce5d180393dc8cce0abec0a7102adb6c7b1eef6016d60a` |
| `digest` | `0.10.7` | `9ed9a281f7bc9b7576e61468ba615a66a5c8cfdff42420a70aa82701a3b1e292` |
| `equivalent` | `1.0.2` | `877a4ace8713b0bcf2a4e7eec82529c029f1d0619886d18145fea96c3ffe5c0f` |
| `flate2` | `1.1.9` | `843fba2746e448b37e26a819579957415c8cef339bf08564fe8b7ddbd959573c` |
| `generic-array` | `0.14.7` | `85649ca51fd72272d7821adaf274ad91c288277713d9c18820d8499a7ff69e9a` |
| `hashbrown` | `0.17.1` | `ed5909b6e89a2db4456e54cd5f673791d7eca6732202bbf2a9cc504fe2f9b84a` |
| `indexmap` | `2.14.0` | `d466e9454f08e4a911e14806c24e16fba1b4c121d1ea474396f396069cf949d9` |
| `itoa` | `1.0.18` | `8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682` |
| `memchr` | `2.8.3` | `cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98` |
| `miniz_oxide` | `0.8.9` | `1fa76a2c86f704bdb222d66965fb3d63269ce38518b83cb0575fca855ebb6316` |
| `semver` | `1.0.26` | `56e6fa9c48d24d85fb3de5ad847117517440f6beceb7798af16b4a87d616b8d0` |
| `serde` | `1.0.228` | `9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e` |
| `serde_core` | `1.0.228` | `41d385c7d4ca58e59fc732af25c3983b67ac852c1a25000afe1175de458b67ad` |
| `serde_json` | `1.0.150` | `e8014e44b4736ed0538adeecded0fce2a272f22dc9578a7eb6b2d9993c74cfb9` |
| `sha2` | `0.10.8` | `793db75ad2bcafc3ffa7c68b215fee268f537982cd901d132f89c6343f3a3dc8` |
| `simd-adler32` | `0.3.9` | `703d5c7ef118737c72f1af64ad2f6f8c5e1921f818cdcb97b8fe6fc69bf66214` |
| `strsim` | `0.11.1` | `7da8b5736845d9f2fcb837ea5d9e2628564b3b043a70948a3f0b778838c5fb4f` |
| `toml_datetime` | `0.6.11` | `22cddaf88f4fbc13c51aebbf5f8eceb5c7c5a9da2ac40a13519eb5b0a0e8f11c` |
| `toml_edit` | `0.22.26` | `310068873db2c5b3e7659d2cc35d21855dbafa50d1ce336397c666e3cb08137e` |
| `typenum` | `1.20.0` | `40ce102ab67701b8526c123c1bab5cbe42d7040ccfd0f64af1a385808d2f43de` |
| `version_check` | `0.9.5` | `0b928f33d975fc6ad9f86c8f283853ad26bdd5b10b7f1542aa2fa15e2289105a` |
| `winnow` | `0.7.15` | `df79d97927682d2fd8adb29682d1140b343be4ac0f08fd68b7765d9c059d3945` |
| `zmij` | `1.0.23` | `29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b` |

All selected licenses are recorded and admitted exactly. Most are
`MIT OR Apache-2.0`; the reviewed exceptions are `adler2`
(`0BSD OR MIT OR Apache-2.0`), `generic-array` (`MIT`), `memchr`
(`Unlicense OR MIT`), `miniz_oxide` (`MIT OR Zlib OR Apache-2.0`),
`simd-adler32`, `strsim`, and `winnow` (`MIT`). `version_check` uses the
legacy manifest spelling `MIT/Apache-2.0`; its allow rule omits the strict SPDX
match while review records the included MIT/Apache license files.

`crc32fast`, `generic-array`, `semver`, `serde`, `serde_core`, `serde_json`,
and `zmij` contain dependency-free Rust build scripts. They receive
`allow-build-script = true` but no native-tool role. No selected package is a
proc macro. Cargo.lock also contains the inactive coverage-only packages
`libc`, `proc-macro2`, `quote`, `serde_derive`, `syn`, and `unicode-ident`;
the configured x86_64 host/musl/Motor graph neither acquires nor builds them.
Any graph/feature/checksum change reopens this review.

### Round 37: external host bootstrap seeder

#### Closed seed set

- The full Stage-2 production seed is the union of Round 36's 32 selected core
  registry packages and Round 30's 14 selected Motor curl registry
  packages. `cfg-if 1.0.4` is shared, so this is exactly 45 unique crates.io
  objects plus the one patched `ring` seeded-Git object.
- Coverage-only inactive lock packages are not seeded. The checked-in
  bootstrap manifest lists every selected name, version, checksum, license,
  retained archive/source choice, and the Cargo.lock(s) that justify it.
  Changing that manifest is a reviewed dependency-graph change.
- The minimal fresh-fetch acceptance seed contains only patched `ring`.
  Installed Lorry and curl executables then populate an empty
  local/user repository with the selected registry graph under test.

#### Resolved host tool

- A checked-in host-only Python 3.11+ script uses only the standard library
  (`hashlib`, `json`, `pathlib`, `ssl`, `tarfile`, `tempfile`, `tomllib`, and
  `urllib`) plus the host `git` executable. It never invokes Cargo, rustup,
  rustc, a shell command string, or code from a downloaded package.
- The script accepts an explicit seed-manifest path, destination repository,
  optional CA bundle, offline/download-cache directory, and mode selecting
  full production or minimal acceptance seed. Defaults are supplied only by
  the surrounding checked-in host/image build scripts, not hidden inside the
  repository format.
- For each registry object it downloads the exact public static.crates.io URL
  into private staging with a compressed-byte limit, verifies SHA-256 before
  parsing, and never executes an archive's contents. It iterates tar entries
  itself rather than calling `extractall`, applies Round 35's path/type/size/
  count rules, and writes regular files with exclusive creation.
- For `ring`, the wrapper obtains the configured branch only as a way to make
  the pinned commit reachable, verifies the resolved 40-hex commit and Git
  tree ID, exports the exact checkout without `.git`, and hands the ordinary
  file tree to the same validator. A mutable branch never enters object
  identity.
- The tool builds an entire repository under a sibling private staging
  directory, fsyncs files/directories, verifies every completed object, and
  installs with no-replace atomic renames. A matching existing object is
  reused only after full verification; a mismatch is corruption and is never
  overwritten. Interruption leaves no visible partial object.
- One generated repository is installed/merged into the Linux host system
  store and independently copied into
  `img_files/generated/rustc/sys/tools/rust/lorry/vendor` for the imager's
  `/sys/tools/rust/lorry/vendor`. The script re-verifies both destinations and
  requires identical repository/object manifests.
- On Linux, the wrapper creates `$HOME/.config/lorry/lorry.toml` from the
  checked-in template only when it is absent. If present, it is never merged
  or overwritten; it must already name the seeded absolute system repository
  or the wrapper stops with a snippet for the user to apply. The generated
  Motor system config is wholly build-owned and may be replaced atomically.
- The host seeder is a bootstrap trust boundary, not a general package
  manager. It accepts only identities in the reviewed seed manifest, has no
  resolver or policy override, and is tested with local malicious archive/Git
  fixtures. Once Lorry exists, acceptance tests require Lorry to independently
  parse every retained `.crate`, reproduce every source manifest/digest, and
  reject deliberately corrupted seed copies.

#### Exact `lorry-source-tree-v1` digest framing

The seed tool and Lorry share this language-independent byte specification:

```text
ASCII "lorry-source-tree-v1" followed by one NUL byte
u64 big-endian entry count
for every entry in ascending unsigned UTF-8 relative-path byte order:
    u8  kind: 1 = directory, 2 = regular file
    u8  executable: 0 or 1 (directories require 0)
    u32 big-endian path byte length
    path bytes, using "/" separators and no leading/trailing "/"
    u64 big-endian file length (directories require 0)
    32 raw SHA-256 bytes (directories require 32 zero bytes)
```

- The root itself is not an entry. All explicit and implied directories,
  including empty directories, are entries. Every file's parent appears
  exactly once.
- Paths must be valid UTF-8 and canonical portable relative paths: no empty,
  `.`, or `..` component; NUL, backslash, control characters, absolute forms,
  and platform prefixes are rejected. Unicode bytes are not normalized or
  case-folded.
- `executable = 1` when any source execute bit is set; all other permission,
  ownership, timestamp, and filesystem-allocation metadata is excluded.
- Each file is hashed while streaming and checked for size/content change
  before the enclosing tree digest is accepted. Entry-count, path-length,
  tree-byte, and file-byte limits are enforced before allocation.
- `source-manifest.json` is the human/audit representation of the same ordered
  entries, but its textual serialization is not the tree digest input. This
  binary framing is exercised by fixed cross-language golden vectors so the
  Python seed tool and Rust Lorry cannot drift silently.

### Round 38: ordered implementation and acceptance sequence

#### Resolved sequence

No phase below starts until the global pre-implementation gate in Phase 0 is
green. A later phase may add capability without weakening an earlier phase's
tests; the complete earlier gate remains in continuous regression coverage.
Cargo invocations occur only in explicitly labelled oracle lanes.

0. **Freeze external prerequisites and oracle inputs.**
   - Verify the Motor SFTP upload, safe `cp -r`, and safe `rm -r` fixtures from
     Round 26. This is satisfied by the nested-tree fixture recorded above.
   - Create and review the final `ring 0.17.14` Motor commit, record its full
     commit and Git tree IDs, generate its `lorry-source-tree-v1` digest, and
     replace every placeholder in this plan and the seed/config fixtures. This
     is satisfied by the Round-34 identities and checked-in Phase-0 inputs.
   - Capture checked-in Cargo 1.97/1.98 command/metadata fixtures for every
     Stage-1 unit shape and establish deterministic, isolated Linux Cargo
     oracle directories. This is satisfied by
     `src/bin/lorry/tests/oracles/cargo-1.97.json` and `cargo-1.98.json`;
     capture rejected any metadata, extra-filename, or executable-byte
     difference across all eight Stage-1 unit shapes. No product code was
     written before these inputs passed.

1. **Complete (2026-07-20): implement the dependency-free Stage-1
   foundation.**
   - Add the small Stage-1 CLI, manifest, root-only Cargo.lock, layered
     configuration, toolchain/target discovery, process, diagnostic, hashing,
     and atomic-output modules using only `std`.
   - Add exhaustive unit and malformed-input fixtures before the build engine
     consumes each module. Unknown keys/flags and missing or stale lockfiles
     must already fail with the agreed diagnostics.
   - Keep the Stage-1 source compilable by one documented direct `rustc`
     command. It must not rely on Cargo-only compile-time environment values;
     the resulting seed is only a bootstrap executable, not an identity
     oracle.

2. **Complete (2026-07-20): close Stage 1 on Linux, cross-Motor, and native
   Motor.**
   - Implement the single-package/single-binary unit graph, Cargo 1.97/1.98
     identity adapter, dev/release rustc commands, `build`, `run`, and binary
     unit-test harness behavior, with no artifact reuse.
   - On Linux, run parser/CLI/process fixtures and clean `red` build/run/test
     integrations. The oracle lane builds the same pristine tree with Cargo
     and requires byte-identical clean release executables for native Linux
     and Linux-to-Motor; debug behavior is compared semantically.
   - The direct-rustc seed builds Stage-1 Lorry, that Lorry rebuilds itself,
     and the second-generation executable repeats the `red` gate. A separate
     Cargo-oracle Lorry build is compared for release identity but is not
     needed to continue the bootstrap.
   - Upload pristine inputs and run the same build/run/test and self-build
     smoke on native Motor. Require native-Motor Lorry outputs to equal the
     Linux-to-Motor outputs under the scoped identity promise. Stage 1 closes
     only after the Round-26 boot/smoke timing and cleanup rules pass.

   Closure evidence:
   - `src/bin/lorry/tests/stage1-linux.sh` passes the 26-test Lorry unit gate,
     native-Linux and Linux-to-Motor Cargo release-identity comparisons,
     native and release 66-test `red` gates, run/test argument and status
     checks, and native/cross second-generation Lorry self-builds.
   - `src/tests/full-test.sh` builds a fresh debug image, reaches SSH within
     the 10-second boot deadline, passes the SFTP prerequisite fixture, and
     runs `src/bin/lorry/test-native.sh --reuse-running-vm` before the
     remaining Motor regression tests. The closure run completed the isolated
     native phase in 155438 ms, passed all 66 `red` tests, matched the
     Linux-to-Motor release artifacts, exercised run argument forwarding, and
     removed its isolated remote tree.
   - The closure artifact SHA-256 values were
     `251d46b5cd79d0625fe8a7157c0595912c8d7061c5cacc3be1fe991fb1c7aa06`
     for `red` and
     `c696316be8d4ff7f0fef445f08e12c9bcf294575f8ea3f15e14f7a7128c6beb3`
     for the native run fixture.

3. **Complete (2026-07-20): implement and validate the external Stage-2
   system seeder.**
   - Implement the Round-37 Python tool, reviewed 45-registry-object/full and
     patched-`ring`-only manifests, malicious archive/Git fixtures, canonical
     tree-digest golden vectors, offline-cache mode, and atomic install logic.
   - Produce and independently verify the Linux and image system repositories
     and their base `lorry.toml` files. Generate a disposable Cargo vendor
     view only for oracle tests; it preserves registry source identities and
     materializes the exact logical `ring` path only inside the oracle tree.
   - Seed reproduction from an empty destination, idempotent re-run, offline
     reproduction, interrupted install, existing corruption, and host/image
     equality are hard gates before Stage-2 dependency work.

   Closure evidence:
   - The 16-test bootstrap suite passes the fixed digest vectors, closed
     45-object registry manifest, malicious archive/Git fixtures, atomic
     no-replace install, interruption/corruption handling, idempotent copy,
     generated-config ownership, and offline reproduction gates.
   - A full online seed and a second empty-destination offline seed produced
     the same repository fingerprint,
     `ad4ae463a27f1f7564a9dd8d51d153dbb13805fce0c6aaed2d8f05d55882f433`,
     with 45 registry objects and the attested `ring` Git object. The
     `ring`-only minimal seed fingerprint was
     `5282f1f781f5a729aa2e26b8d6c5fd3fa9b3802fee64c64c3b3d253122858c21`.
   - Independently copied host and image repositories re-verified to the full
     fingerprint. The disposable Cargo oracle view materialized all 45
     registry checksum manifests and the exact logical
     `.lorry/vendor/ring-0_17_14/source` path.

4. **Complete (2026-07-20): implement Stage-2 parsing, graph, repository, and
   policy foundations.**
   - Switch core Lorry to the exact Round-36 dependency graph. Add the bounded
     TOML/JSON/semver models, manifest subset, Cargo.lock v4 reader/writer,
     cfg evaluation, resolver 1/2/3, sparse-index model, feature/target graph,
     layered repositories, immutable object verification, required-patch
     checks, and two-pass default-deny policy.
   - Test each subsystem with fixed positive, duplicate/unknown-field,
     truncation/limit, graph-conflict/backtracking, stale-lock, corruption,
     higher-layer-shadowing, and path-escape fixtures. Differential fixtures
     compare supported resolution/lock results with Cargo 1.97/1.98 without
     letting Cargo participate in Lorry's resolver.
   - An oracle-built Stage-2 executable may be the initial test subject while
     implementing these foundations and the dependency unit/build-script path
     in Phase 5. The original placement of the self-build gate here was
     impossible before Phase 5 supplied those compilation units. Phase 5 must
     build Lorry from the externally seeded repository as soon as that path is
     complete; the self-built executable, not Cargo, is then used for `rush`
     and every following non-oracle Stage-2 acceptance action.

   Closure evidence:
   - The bounded TOML, JSON, semantic-version, manifest, Cargo.lock v4,
     sparse-index, archive, source-tree, layered-repository, resolver 1/2/3,
     cfg-selection, required-patch, offline validation, and two-pass policy
     modules pass the 108-test host suite and cross-check for Motor.
   - Offline selected-graph preparation loads only reached lock objects,
     admits dependency-free/path-only graphs without a repository, re-verifies
     retained sources, and privately extracts and cleans up a real seeded
     archive-only object.
   - The frozen offline Stage-2 resolution fixture is independently reproduced
     byte-for-byte by Cargo 1.97 and 1.98. Lorry resolves its complete graph,
     renders the same Cargo.lock, and derives the expected smaller Linux
     default-feature graph without invoking Cargo.

5. **Add Stage-2 units, sandboxed build scripts, and `rush`.**
   - Extend the unit DAG to libraries, the single explicit binary,
     target-conditioned registry/path dependencies, host build dependencies,
     distinct build-script units, Cargo lints/check-cfg, and the exact
     build-script directive/environment protocol.
   - Implement Linux build-script isolation first and require denial fixtures
     for network, writes, environment, and undeclared child tools. Add the
     equivalent Motor isolation hook; if Motor cannot yet enforce the contract,
     this phase pauses for the external OS feature instead of adding an
     unsandboxed mode.
   - As soon as the dependency library and approved build-script path can
     compile Lorry's selected core graph, require the oracle-built executable
     to build Lorry from the external seed. Use that self-built executable for
     the remaining `rush` work and non-oracle acceptance in this and later
     phases.
   - Build/test `rush` in dev and release for native Linux and Linux-to-Motor,
     covering `libc 0.2.139`, Motor path crates, `CARGO_BIN_EXE_rush`, all
     discovered integration tests, `--test`, and `--no-run`. Require clean
     Cargo/Lorry release identity and then native-Motor/cross-Lorry identity.

   Progress evidence:
   - The selected dependency graph now expands into a deterministic
     topological unit DAG with distinct target/host libraries and
     build-script compile/run units. Resolver-1 unified features still retain
     separate host and target compilation activations, and seeded external
     graphs validate the same invariants.
   - The generalized compilation-identity adapter preserves every frozen
     Stage-1 identity and matches clean Cargo 1.97/1.98 release identities for
     registry and local-path libraries, host build dependencies,
     build-script compile/run units, enabled features, LTO, and sorted
     transitive dependency identities.
   - The dependency executor compiles the selected library DAG, compiles and
     runs admitted build scripts through the platform sandbox interface,
     applies their validated directives and generated outputs, and supplies
     the resulting artifacts and identities to the root unit. Path dependency
     and dependency build-script engine fixtures pass on Linux, and the full
     seeded Lorry graph builds without consulting Cargo artifacts.
   - The explicit `--use-cargo-registry` lane resolves locked crates.io
     packages from checksum-verified Cargo cache archives and manifests,
     compiles from Cargo's unchanged physical source paths, and detects source
     changes through the end of dependency execution. Missing pairs,
     corruption, ambiguity, marker errors, required-patch drift, and policy
     enforcement have deterministic fixtures. A clean Cargo release build and
     two successive Lorry self-builds produced byte-identical dependency
     artifact names and executables on Linux; the closure SHA-256 for this
     checkpoint was
     `7f716130606d70b59acca2208c44215e46a8320291b061c302fa8a1ddb6ed48d`.
   - Normal root builds now compile the supported library before the binary,
     use metadata artifacts for library inputs and linkable artifacts for the
     binary, preserve declared target names and Cargo's root-relative source
     paths, forward selected default root features, and support library-only
     packages. Frozen Stage-1 identities remain unchanged. The captured
     `moto_rush`/`rush` release identities pass, and a clean Cargo build and
     explicit-Cargo-registry Lorry build produced the same `moto_rush` rlib
     and byte-identical `rush` executable with SHA-256
     `16f893a510b7f364f7ad511d10ec165a7c1173018f76f5b54f5014a26989940c`.
   - Root manifests now discover direct `tests/*.rs` integration targets in
     deterministic target-name order, ignore out-of-scope nested/non-Rust
     files, and reject linked, special, non-UTF-8, invalid, or crate-name-
     colliding entries before compilation.
   - Ordinary tests now build the normal panic-abort program graph and the
     distinct panic-unwind harness graph, reusing only identical dependency
     units. Library and binary unit harnesses precede sorted integrations;
     named selection builds one integration plus its required library/program
     graph, and `--no-run` prints deterministic final paths. Integrations
     receive Cargo-compatible `CARGO_BIN_EXE_rush` and `CARGO_TARGET_TMPDIR`
     values, and their identities include the program artifact edge. A clean
     Cargo oracle and Lorry produced identical Linux and Motor OS release
     identities for all 12 `rush` harnesses, with byte-identical root binary
     and unit harnesses on both targets. The generated Linux `phase0`
     integration harness also passed all 12 tests. Unix-only `fuzz` and Phase
     7 host tests are explicitly target-gated; Phase 7's Motor OS behavior
     remains covered by its existing VM self-check.

6. **Finish Stage-2 cache, bundle, and core self-hosting.**
   - The Round-22 content-addressed library/build-output cache is implemented
     below `target/lorry/.cache/v1`. Its versioned keys cover Lorry, rustc and
     relevant sysroot/tool identities, normalized rustc arguments and the full
     effective environment, manifests/lock/source trees, dependency artifact
     contents, and sandboxed build-script environment, executable, directives,
     and `OUT_DIR` contents. Canonical entry/payload/build-output manifests are
     fully re-hashed on every hit; incomplete staging is ignored, corrupt
     entries are warned about and quarantined, and concurrent identical writers
     use first-writer-wins publication. Rustc dep-info is rejected if it names
     an input outside the package and assigned `OUT_DIR`.
   - Cold/warm/source-invalidation, concurrent-writer, interrupted-staging,
     corruption, build-output normalization, and root-relink fixtures pass.
     A two-build Lorry trial reused every dependency library on the second
     build while recompiling/rerunning all build scripts and relinking the root;
     both root executables had SHA-256
     `4e77dd6c3fa45dee8a2436dd7082bbfaa85d63bdf703dd2422685bcd85d26aa6`.
     The cache implementation also passes the Motor OS compile check.
   - The one-file test bundle has a canonical embedded manifest and verified,
     race-resistant extraction cache. Linux fixtures cover copying away from
     the output tree, embedded program execution through `CARGO_BIN_EXE_*`,
     deterministic paths/`--no-run`, argument forwarding, failure
     aggregation, `--test`, one-shot cross-runner invocation, cleanup,
     unexpected-file, permission, and content-tamper rejection. Its generated
     launcher also passes the Motor OS compile check and executes in Motor OS
     independently of its source/output tree. A real 12-harness `rush` bundle
     passes `phase0`'s `simple_command_stdout` test through its extracted
     `CARGO_BIN_EXE_rush` program.
   - Stage-2 Lorry vendors/verifies its exact 32-package graph from the seeded
     repository, builds itself on Linux and Motor, and repeats with the
     self-built executable and warm cache. The Cargo oracle lane separately
     checks clean release identity.

7. **Implement vendoring and the Motor curl acquisition path.**
   - This step resumes only after external Gate 12 is satisfied. The first
     vendoring substage wires the project-scoped process-lifetime lock through
     `std::fs::File::lock` and verifies same-project exclusion and
     different-project independence on Linux and Motor OS. No temporary Motor
     OS lock implementation belongs in Lorry.
   - Implement the direct curl interaction in `curl-interaction.md` and the
     `lorry vendor` sparse-index/download state machine, per-package
     confirmation, `--accept-all`, transaction/lock ordering, and all-or-none
     behavior. Redirect sites use initially empty persistent allow/deny lists;
     an unknown site requires an operation-scoped or persistent allow/deny
     choice, independently of `--accept-all`. Network tests use a local
     deterministic TLS server for malformed HTTP, redirect trust and
     persistence, certificate, hostname, truncation, size, timeout, and
     stream/trailer cases; a minimal public crates.io fetch is a separate
     opt-in integration test.
   - First exercise pure-registry fresh vendoring with an installed curl.
     Then enable only the configured compiler/archiver roles, build patched
     `ring` and Motor curl, run the Motor entropy and verified-HTTPS
     fixtures, and prove that all undeclared native process attempts fail.
   - On Linux and Motor, use the built curl directly to populate a second fresh
     writable repository from the minimal `ring`-only system seed. Build Motor
     curl again solely from that repository plus the required system
     `ring`, and compare clean Cargo/Lorry and Linux-cross/native-Motor release
     executables.

8. **Run final Stage-2 closure and freeze the supported surface.**
   - Run the complete unit/security/fixture suite, all Cargo 1.97/1.98 oracle
     comparisons, `red`, `rush`, core self-build, curl self-build,
     cold/warm/corrupt-cache, full/fresh vendor, cross-target, and native-Motor
     matrices from pristine roots.
   - Run Round-26 smoke continuously and `--full` for closure, preserving the
     independent ten-second boot limit and separate Lorry timeout budgets.
   - Audit dependency graphs, checksums, features, licenses, patches, native
     tools, manifests, configs, and checked-in oracle/seed fixtures against this
     plan. Document every rejected Cargo feature with its actionable error and
     publish a Stage-2 support matrix.
   - Only after this gate passes is Stage 2 complete. Workspaces,
     `httpd-axum`, `russhd`, procedural macros, general Git, CLI feature
     selection, and every other Stage-3+ choice may then be reopened.

### Round 39: optional version requirements for local path sources

#### Resolved during Stage-2 implementation

- The earlier requirement that every path dependency include `version` was
  unnecessarily strict and is superseded.
- Crates.io dependencies must still carry a semantic version requirement
  because Lorry resolves and vendors them as external packages.
- Dependencies whose Cargo source is `path` may omit `version`, including
  ordinary relative/absolute local paths and logical paths backed by verified
  vendored objects. Their selected package name/version are verified from the
  source manifest and Cargo.lock path-package node. An explicitly supplied
  version remains a constraint and must match.
- Required-patch rules retain their own exact guarded version and source-tree
  identity checks, so omitting a redundant version from the Cargo path entry
  does not weaken patch integrity or policy enforcement.

### Round 40: temporary Motor sandbox adapter

#### Resolved during Stage-2 implementation

- Lorry defines the complete platform sandbox boundary before build-script
  execution is wired into the engine. Linux must enforce that boundary and
  its denial fixtures remain Stage-2 gates.
- The Motor implementation is temporarily an explicit warning stub which
  returns success without enforcing the requested policy. This development
  exception permits the platform-independent Stage-2 engine and Linux path to
  progress while the Motor isolation facility is implemented asynchronously.
- The stub does not satisfy Gate 11, may not be described as sandboxed, and
  cannot pass native-Motor build-script or final Stage-2 acceptance. Those
  gates remain pending until the stub is replaced and the same observable
  denial fixtures pass on Motor.

### Round 41: explicitly absent build-script environment inputs

#### Resolved during Stage-2 implementation

- Cargo build scripts such as `libc` legitimately emit
  `rerun-if-env-changed` for optional variables that are normally absent.
  Requiring every such name to be present in Lorry's safe environment would
  either reject the selected graph or expose knobs that Lorry intentionally
  leaves unset.
- Lorry therefore accepts every syntactically valid variable name in this
  directive. If the name exists in the supplied post-`env_clear` environment,
  its exact value is recorded. Otherwise the directive records an explicit
  absent value. Ambient parent values remain inaccessible and cannot affect
  the build.
- The ordered directive, variable name, and value-or-absence remain unit and
  cache inputs. Invalid names, malformed directives, and attempts to obtain
  ambient values remain hard failures.

### Round 42: explicit Cargo-registry compatibility mode

#### Resolved during Stage-2 implementation

- Lorry does not rewrite physical source paths to manufacture release-byte
  identity. Source-path normalization is visible compiler behavior and must
  not be introduced implicitly.
- The global `--use-cargo-registry` flag selects an explicit, offline
  compatibility/oracle mode for `build`, `run`, and `test`. In that mode,
  crates.io resolution and compilation use Cargo's populated registry below
  `CARGO_HOME`, or `$HOME/.cargo` when `CARGO_HOME` is unset. Normal commands
  continue to use only Lorry's configured repositories.
- Every selected crates.io package must have both Cargo's cached `.crate`
  archive and its extracted source directory in the same crates.io registry
  cache. Lorry hashes the archive against Cargo.lock, extracts and validates it
  privately under the normal policy limits, compares the extracted contents
  with Cargo's source directory apart from Cargo's own top-level `.cargo-ok`
  marker, and parses the verified cached manifest. Missing, ambiguous,
  modified, linked, special, or checksum-mismatched cache entries are hard
  errors; this mode never fetches or repairs Cargo's cache.
- Resolver records for locked crates.io packages are derived from those
  verified cached manifests and Cargo.lock checksums. Lorry repositories are
  not consulted for crates.io index records, archives, source trees, or policy
  evidence in this mode. Policy evaluation and all graph, archive, tree, and
  transaction limits remain enforced.
- Ordinary path dependencies and patches remain at their Cargo-declared
  paths. A configured required patch must be materialized at its declared
  logical Cargo path and match the rule's exact name, version, and source-tree
  digest; compatibility mode does not silently redirect it to a Lorry object.
- Because rustc receives the same physical package paths as Cargo, path text
  embedded by macros, diagnostics, or panic locations is naturally identical.
  No `--remap-path-prefix`, symlink view, source copy, or hidden compiler flag
  is added. Clean Cargo/Lorry release comparisons use this explicit mode.

### Round 43: Motor OS whole-file locking prerequisite

#### Satisfied during Stage-2 implementation

- Stage-2 vendoring requires the project-scoped process-lifetime lock already
  specified in Rounds 19 and 20. Motor OS now supplies the stable
  `std::fs::File` whole-file locking API and native locking coverage.
- The Motor OS implementation is a platform prerequisite, specified
  independently in `docs/file-locking-plan.md`. It must be completed in the
  filesystem/runtime/standard-library layers rather than worked around in
  Lorry.
- Lorry now uses `std::fs::File::lock` directly and retains the owning `File`.
  Its multi-process fixture proves same-project exclusion and different-project
  independence; the lock will be wired around the complete vendor transaction
  when that command is enabled.

### Round 44: vendoring implementation checkpoint and atomic rename gate

#### Completed incremental patches

- Lorry's Motor dependency pin follows the in-tree `moto-rt` 0.16.3.
- The project vendor lock, staged-lockfile fsync/close operation, lazy sparse
  catalog loading seam, multi-target resolution union, and resolution-derived
  lock preferences are implemented with focused tests.
- Writable repositories are initialized transactionally with the exact
  format-1 layout. Downloaded crates can be checksum-verified, safely
  extracted beneath private transaction staging, rendered into canonical
  repository metadata, retained according to configuration, and fully
  re-verified before publication.
- Repository publication persists every staged file and directory, uses
  Linux `renameat2(RENAME_NOREPLACE)` or Motor
  `moto_rt::fs::move_noreplace`, and re-verifies either the newly published
  object or an identical concurrent winner. Focused Linux coverage and the
  native Motor two-process competing-publisher fixture pass.
- `lorry vendor` now holds the project lock across the complete transaction,
  re-resolves the configured target union, applies path policy before any
  visible change, stages and persists `Cargo.lock` while hidden, and renames
  it last. Dependency-free and path-only projects can create, verify, and
  repair their lockfile without repository or network access.
- The native smoke harness now builds its initial Stage-2 Linux and Motor
  executables through the offline Cargo oracle, then performs all guest work
  with staged Lorry alone. Cross artifacts use the exact Rust sysroot embedded
  in the VM image. The standalone smoke gate and the debug and release
  full-test paths with that gate enabled pass, including cross/native artifact
  identity and all 66 native `red` tests.

#### Current checkpoint and remaining work

- Gate 13 is satisfied. The native debug and release full-test runs exercise
  two competing publishers and prove that exactly one no-replace directory
  move wins while the visible object contains that winner's data.
- Registry graphs still stop before any lockfile or repository change with an
  explicit curl-acquisition-pending diagnostic. The path-only transaction does
  not perform network access.
- Still to do in implementation item 7: direct curl process/stream handling,
  bounded sparse-index/archive acquisition, approval UI and `--accept-all`,
  registry-path interrupted/concurrent transaction fixtures, configured
  native compiler and archiver roles, patched `ring`/curl self-builds, and
  Linux/native-Motor fresh-repository acceptance cycles.

### Round 45: direct curl acquisition and Motor curl utility

#### Superseded helper design

- The separate `src/bin/lorry-fetch` package and its private version-1 protocol
  are removed. The package did only one public HTTPS GET, so a Lorry-specific
  executable and result schema added a redundant interface.
- This supersedes the helper placement decisions in Rounds 6, 13, 19, 24, and
  25. It does not reopen Lorry's repository, policy, transaction, TLS-provider,
  native-tool, or exact Stage-2 dependency-graph decisions.

#### Resolved replacement

- Lorry invokes curl directly on both platforms. Linux requires upstream curl
  7.63.0 or newer. Motor supplies a general curl-compatible `/bin/curl` from
  the independent `src/bin/curl` package; there is no adapter binary.
- Lorry performs one request per curl process, owns redirect validation and
  body staging, enforces all size and URL rules, and interprets a bounded
  nonce-delimited `--write-out` trailer. Curl owns only HTTPS transport.
  `curl-interaction.md` is the normative command, environment, stream, error,
  security, and conformance contract.
- Redirect trust is keyed by canonical HTTPS site. Initially empty persistent
  user allow/deny lists are stored outside repository-controlled configuration.
  Unknown sites require an explicit allow/deny plus operation/always choice;
  `--accept-all` applies only to package approval.
- The exact Round-30 Rustls graph, patched `ring` 0.17.14 provider, Motor
  entropy callback, and compiler/archiver roles move from `lorry-fetch` to
  `src/bin/curl`; they remain outside core Lorry.
- Stage-2 closure builds curl on Linux and native Motor, uses the result
  directly through Lorry to populate a second fresh repository, then rebuilds
  curl from that repository. Thus Motor's network utility is itself buildable
  by Stage-2 Lorry.
- The bootstrap manifest's graph ID and lockfile path change from
  `lorry-fetch` to `curl`. The reviewed curl Cargo.toml/Cargo.lock graph and
  the corresponding 45-object production seed are now checked in.

### Round 46: composite crates.io-plus-Git `ring` seed

#### Completed implementation

- The complete buildable base is the exact crates.io `ring 0.17.14` archive
  with SHA-256
  `a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7`.
  Safe archive extraction preserves its published `pregenerated/` assembly,
  which is not present in a Git checkout.
- The independently acquired Git commit
  `b1dad2579de791d0c31ad33300187e584ba6c268` and tree
  `824d5b8e9755603070a8167e0c5529acb627d956` supply exactly two reviewed
  replacement blobs: `build.rs` and `src/rand.rs`. The seeder requires that
  both paths are mode-`100644` regular blobs at that commit and that each
  replacement changes an existing regular archive file.
- `patch-files` is closed manifest and repository-object metadata. The
  resulting immutable source tree contains 391 files, 63 directories, and
  7,757,154 file bytes. Its `lorry-source-tree-v1` digest is
  `c05dbfa4d748bce2b66093633c0a644cc1e5f480d73f3b0a975e409f69386af6`.
- Online acquisition followed by fully offline reproduction produced the
  production seed fingerprint
  `0f12be3e526e48aee5aa6fb761cadc43ffa1a8f5498e19384c113d7d5f5a0bcd`.
  The bootstrap fixture proves that unpatched archive files, including a
  pregenerated artifact, survive and that linked Git patch paths are rejected.
- This round supersedes the whole-Git-export build-source statements in
  Rounds 31, 32, 34, and 37 and their former seed fingerprints. The full Git
  tree identity remains independently verified provenance; the composite
  source-tree digest is the build object identity.

## Stage-1/2 design closure and external start gates

Design items 1–8 are resolved by the rounds above and are reflected in the
ordered acceptance sequence. They remain change-controlled: altering one
reopens only the affected review and downstream gates.

1. Exact root editions, resolver versions, manifest keys, target kinds, and
   dependency forms admitted by stages 1 and 2.
2. Stage-2 dependency-admission policy, defaults, rule semantics, inspection
   evidence, and treatment of local path dependencies/build scripts.
3. Exact `lorry.toml`, repository, transaction, lockfile, sparse-index, and
   direct curl interaction; selection and measured validation of the Rustls
   cryptography provider; and the resulting native tool, patch, feature, and
   curl-lock graph.
4. Exact package/unit graph, rustc command/environment, build-script protocol,
   run/test behavior, and Cargo-identity adapter for `red` and `rush`.
5. Stage-2 content-addressed fingerprint/cache inputs, invalidation, generated
   outputs, and failure behavior.
6. CLI grammar, exit status, diagnostics, logging, terminal interaction, and
   non-interactive behavior for all stage-1/2 commands.
7. Linux/Motor portability constraints and the precise native/cross
   installation and periodic-test workflow.
8. An ordered implementation plan with unit, fixture, integration,
   Cargo-comparison, cross-build, and native-Motor acceptance gates.

Implementation was prohibited until both Phase-0 external start gates below
were present, tested, and their concrete evidence was recorded:

9. **Satisfied.** Motor SFTP uploads and round-trips a nested representative
   tree; guest `cp -r` copies it and rejects a destination inside the source;
   guest `rm` rejects the directory without `-r`; and `rm -r` removes only the
   selected copy while an outside sentinel survives. The checked-in fixture
   passed against the debug Motor VM.
10. **Satisfied.** The reviewed `moturus/ring` commit based on upstream
    `ring 0.17.14` is fetchable at
    `b1dad2579de791d0c31ad33300187e584ba6c268`. Its Git tree ID is
    `824d5b8e9755603070a8167e0c5529acb627d956`. Round 46 defines the
    buildable composite source derived from the exact crates.io archive plus
    its two reviewed Git blobs; its source-tree digest is
    `c05dbfa4d748bce2b66093633c0a644cc1e5f480d73f3b0a975e409f69386af6`.
    These identities appear in the checked-in bootstrap/config inputs.

The following later external gates do not prevent the completed Stage-1 work,
but each blocks the indicated Stage-2 work:

11. Motor exposes the build-script isolation enforcement needed to match
    Round 17's observable sandbox contract. If the existing facilities already
    suffice, the acceptance fixture records that fact; otherwise the Motor OS
    feature is delivered outside this Lorry effort. This must be green before
    Phase 5 starts and before final Stage-2 acceptance.
12. **Satisfied.** Motor OS implements the stable `std::fs::File` whole-file locking APIs as
    specified in `docs/file-locking-plan.md`, and the native two-process
    exclusive-lock/release coverage is present. Lorry's process fixture also
    verifies same-project exclusion and different-project independence.
13. **Satisfied.** Motor OS exposes
    `moto_rt::fs::move_noreplace`, Lorry uses it for atomic no-replace
    directory publication, and the native two-process competing-publisher
    fixture passes. Linux uses `renameat2(RENAME_NOREPLACE)` and has matching
    focused coverage.

Gates 9, 10, 12, and 13 are green, and the checked-in Cargo-oracle inputs
pass. Phase 0 and the cache/bundle portions of implementation item 6 are
complete. Immutable object publication and the path-only vendor transaction
from item 7 are implemented. Gate 11 remains required for the sandbox and
final acceptance work described above.

### Design stop point

The Stage-1/2 product boundary, dependency graphs, formats, security policy,
commands, Cargo-compatibility contract, portability model, bootstrap path,
implementation order, and acceptance gates are now settled. Detailed
Stage-3+ design remains intentionally frozen. The next Lorry implementation
work is item 7's direct curl process/stream layer and bounded registry
acquisition loop.

## Deferred post-stage-2 design

All stage-3 and later capability decisions, including the detailed
`httpd-axum` and `russhd` graphs, general git acquisition, and proc macros are
revisited only after stage 2 passes its acceptance gates. Motor curl
self-building and its `ring` 0.17.14 provider are Stage-2 requirements.

## Post-split implementation notes

### 2026-07-28: child-pipe endpoint closure

The remaining exact curl exit-code fixture exposed two independent layers.
First, dropping a parent's piped `ChildStdout` removed the runtime descriptor
but did not close its shared kernel endpoint until incidental `Arc<SysObject>`
references disappeared. A blocked child could consequently keep writing
instead of observing the missing reader.

`SysObject` now counts process handles separately from kernel references.
Dropping the last handle, or process exit removing it, idempotently marks a
shared endpoint closed, wakes its sibling, and makes later peer queries and
wakes reject the closed endpoint. The close path is constant-time even for a
process with many unrelated handles. A native systest child writes more than
the pipe capacity through `moto_rt`; its parent reads one byte and drops the
reader, and the test requires the writer to receive the close error.

The exact isolated patch passed `src/tests/full-test.sh` three consecutive
times in debug mode and `src/tests/full-test.sh --release` three consecutive
times. Every pass included the new `test_child_stdout_reader_drop` regression,
the existing stdio close/drain/wake cases, and the Motor-native Lorry gate; the
kernel watchdog did not recur.

Tracing also found a separate toolchain limitation: Motor's Rust
`std::sys::stdio::is_ebadf` currently returns true for every `io::Error`.
`StdoutRaw` therefore converts the correctly propagated `BadHandle` error to
success. Rebuilding the external Rust sysroot is outside this repository.
Motor curl now gives transfer output a direct `moto_rt` writer, maps its errors
back into `io::Error`, and consequently reports the required status 23 when
Lorry closes the body pipe.

The selected-curl exit fixture covers malformed URL 3, name resolution 6,
connection failure 7, TLS handshake failure 35, and local write failure 23.
The existing selected-curl timeout and certificate fixtures require statuses
28 and 60. The deterministic Rust and Python TLS servers both provide raw
non-TLS and one-megabyte response modes, so the same test works through
upstream Linux curl, Lorry-built Linux curl, and native Motor curl.

The exact patch passed the curl crate's 19 unit and nine HTTPS tests, the
Lorry-built Linux curl contract, and a focused Motor VM smoke gate. It then
passed an initial `src/tests/full-test.sh` three consecutive times in debug
mode and `src/tests/full-test.sh --release` three consecutive times. Those
runs temporarily narrowed the native lane to the new case, which review caught
before commit.

After restoring all prior native coverage, the exact final patch passed
`src/tests/full-test.sh` three more consecutive times in debug mode and
`src/tests/full-test.sh --release` three more consecutive times. Every final
pass included all 214 Lorry tests, the 20-test selected-curl Linux contract,
and all ten selected-curl native Motor tests; the kernel watchdog did not
recur.

### 2026-07-27: Cargo-oracle lock closure classified

`stage2-seed.toml` now identifies the 16 inactive Cargo.lock packages needed
only by Cargo oracle builds: five from the Stage-2 core lock and eleven from
the curl lock. The manifest parser validates their names, versions, checksums,
lock-graph membership, and disjointness from the 45 production objects.

The manifest fixture proves that the complete registry union of both reviewed
lockfiles is exactly the disjoint production and oracle-only sets. The next
patch will acquire and safely extract these packages only when constructing an
explicit disposable Cargo oracle view.

All 18 bootstrap fixtures pass. The exact isolated patch also passed
`src/tests/full-test.sh` three times in debug mode and three times with
`--release`; every pass included the Motor-native Lorry smoke gate, and the
kernel watchdog did not recur.

### 2026-07-28: repository sources bound to Rust mappings

Dependency planning now assigns a mapping to every selected crates.io source
prepared from a Lorry repository, including a privately extracted
archive-only object. The locked checksum alone defines its presented root.
Verified required-patch fallbacks use their configured logical roots. The
explicit Cargo-registry lane and ordinary path packages with equal physical
and logical roots receive no mapping.

Planning rejects one logical root resolving to different physical trees and
one physical tree being presented under different logical roots. The seeded
graph fixture checks every planned registry and required-patch unit and proves
both mapping families are present. Native C compiler projection remains the
next patch.

All 198 Lorry tests pass. The isolated binding patch passed
`src/tests/full-test.sh` three times in debug mode and three times with
`--release`; every run included the Motor-native Lorry smoke gate, and the
kernel watchdog did not recur.

### 2026-07-27: Cargo-oracle view completed

The installer now acquires the 16 lock-only archives only while constructing
an explicitly requested full Cargo oracle view. It reuses the bounded
checksum-verifying download/cache path and safe archive extractor, computes
Cargo directory-source checksums from the extracted trees, and removes its
private acquisition staging directory before publishing the view. Offline
materialization fails clearly when an oracle archive is absent. A focused
fixture proves the package appears in the disposable view but not in the
production repository.

The complete offline Cargo 1.98 curl release build now succeeds with the
pinned Clang and `ar`. Comparing it with repository-mode Lorry established
that the remaining difference is source presentation: Cargo uses its oracle
view, hosted Lorry embeds `/home/.../objects/.../source`, and native Lorry
embeds `/sys/.../objects/.../source`. Both ordinary crates.io dependencies and
the required `ring` patch contribute release source strings.

The selected remapping design therefore covers every immutable
repository-backed dependency, not only required patches. Crates.io objects use
`.lorry/registry/sha256/<locked-checksum>/source`; required patches keep their
declared `.lorry/vendor/<rule-id>/source`. Compilers see logical paths, while
all reads, checks, build scripts, and sandbox policy continue to use physical
paths. Cargo-registry compatibility mode remains unmapped.

All 18 bootstrap fixtures and Python syntax checks pass. The isolated
materialization patch passed `src/tests/full-test.sh` three times in debug mode
and three times with `--release`; all six runs included the Motor-native Lorry
smoke gate, with no kernel watchdog recurrence.

### 2026-07-28: Rust remapping execution support

`SourceRemap` now distinguishes the absolute logical root used for validation
from the workspace-relative path presented to compilers. Normal repository
crates.io packages derive that path only from the locked archive checksum:
`.lorry/registry/sha256/<checksum>/source`. Required patches retain their
declared `.lorry/vendor/<rule-id>/source` identity. Cargo-registry mode and
ordinary path packages remain unmapped.

Dependency rustc runs from the workspace root, receives an optional internal
prefix mapping after configured rustflags, and retains the physical manifest
environment. Dep-info validation reverses a presented path before applying the
existing canonical containment check. The effective current directory and
argument remain cache inputs.

Production planning does not assign these mappings yet. Repository-source
binding and native compiler projection are the next two self-contained
patches.

All 198 Lorry tests pass. The isolated execution-support patch passed
`src/tests/full-test.sh` three times in debug mode and three times with
`--release`; every run included the Motor-native Lorry smoke gate, and the
kernel watchdog did not recur.
