# Making Lorry smaller and faster to change

Status: implementation tracker. Updated through the eighth compact-admission
implementation patch on 2026-08-06.

This note analyzes why the dependency-upgrade change was large and why the
Lorry-local verification gate historically took hours. It proposes
alternatives that keep Lorry reproducible, offline at build time, and
fail-closed while making normal dependency upgrades and development practical.

Some analysis below describes the harness before the completed work. Those
sections are retained as the baseline and are labeled historical. The status
here and the numbered work list at the end are authoritative.

## Implementation status

Completed:

- Every local and native phase records machine-readable and console timing.
- Tests under `src/bin/lorry` build only Lorry and its dependencies. Red,
  Rush, curl, the synthetic Stage-1 package, and downstream second-generation
  tests are owned by `src/tests/lorry-integration-test.sh`.
- crates.io and GitHub acquisition tests are fail-closed and use local Cargo
  caches. The curl protocol tests use a repository-local TLS fixture; none of
  these tests has an Internet fallback.
- Stage-1 artifact identity is a same-environment byte comparison between
  Lorry and Cargo, including native, cross-Motor, test-harness, self-build,
  and second-generation outputs. It no longer pins compiler-specific artifact
  digests or hash-derived executable names.
- Ordinary Lorry-local debug and release artifacts run in a release Motor OS
  VM. Debug image coverage remains in the repository integration gate.
- Fast, acceptance, and exhaustive verification have separate entry points.
  The fast gate orders both profiles' host checks before native work and has a
  warm mode that preserves separate host and guest targets. It executes both
  cross-built profiles but reserves the native self-build and byte comparison
  for release. Acceptance adds one release downstream/native smoke campaign;
  exhaustive retains the clean repeated and second-generation campaigns.
  Changed paths select these gates mechanically.
- The Lorry-local native self-gate builds, runs, and tests one compact Motor
  fixture covering a library, binary, integration test, admitted build script,
  Motor-only path dependency, and reviewed registry dependency.
- Step 8's first eight inactive foundations add the canonical writer and review
  table model, complete model validation and rendering, digest helper, and
  empty and representative golden vectors, plus the compact-state model and
  strict parser and bounded writer, without changing active format-1 admission.

Remaining:

- complete the canonical review model and compact admission, then implement
  vendoring reconciliation, upgrade-core deletion, and derived bootstrap-state
  work described below.

Next step: **begin the direct compact-admission cutover**.

## Summary

At the time of the original analysis, the design was over-specified in four
places. The implementation status above records which observations have since
been addressed.

1. Dependency admission copies graph and source facts already represented by
   Cargo.lock and immutable repository objects.
2. Every supported Cargo release adds a permanent 1,100-line frozen oracle
   family, and all retained families are exercised in every gate.
3. The test harness hardcodes other packages' dependency versions, checksums,
   and build-script sets, so upgrades elsewhere in the repository break
   Lorry's gate without any Lorry change.
4. The test harness multiplies artifact profile, build topology, Motor OS image
   profile, and reliability repetition into one clean-room matrix.

The recommended direction is:

- keep Cargo.toml as the only human-edited dependency file;
- keep Cargo.lock as the only resolved-graph representation;
- keep immutable repository objects as the source-evidence authority;
- replace the full generated admission file with a compact cryptographic
  commitment plus exceptional capability grants;
- make ordinary `lorry vendor` reconcile intentional dependency changes;
- bound the retained Cargo oracle families and derive harness dependency
  facts from the consumed packages' lockfiles; and
- split testing into fast, acceptance, and exhaustive gates.

## Size of the dependency-upgrade change

Commit `0c148180` inserted 5,077 lines. The largest additions were:

| Area | Added lines |
|---|---:|
| Cargo 1.99 compatibility oracle | 1,106 |
| `src/admission_state.rs` | 1,024 |
| `src/upgrade.rs` | 866 |
| Generated `.lorry/dependencies-v1.toml` | 534 |
| Documentation and plans | about 800 |
| CLI, resolver, vendor integration, tests, and harness | remainder |

The admission and upgrade modules alone added 1,890 lines. With their vendor,
resolver, and CLI integration, explicit dependency upgrading added roughly
2,300 lines of Rust. The feature became a manifest editor, resolver mode,
approval database, acquisition workflow, and transaction coordinator.

The largest single file addition was not admission machinery: the frozen
Cargo 1.99 oracle exists because the same commit moved `cargo-compat-version`
from 1.98 to 1.99. Toolchain upgrades are a distinct breakage vector and are
analyzed separately below.

Lorry currently contains about 38,500 lines of Rust including inline tests.
This makes continued expansion of the supported package-manager surface a
material maintainability concern.

## Problems with the dependency design

### Repeated representations of the same graph

The dependency graph is represented in four places:

1. Cargo.toml contains human dependency intent.
2. Cargo.lock contains resolved identities, dependency edges, and checksums.
3. `.lorry/dependencies-v1.toml` repeats direct intent and locked identities,
   then adds admitted evidence.
4. `bootstrap/stage2-seed.toml` repeats much of the Lorry and curl graph for
   bootstrapping.

For Lorry itself, the admission file has 534 lines and the bootstrap seed has
553 lines. The admission file repeats 8 direct dependencies, 38 locked
packages, and 33 admitted packages.

Much of this information already has an authoritative source:

- Cargo.lock records exact registry identities and checksums.
- Repository `RegistryObject` metadata records license and source-tree
  evidence and is verified during lookup.
- Cargo.toml records direct requirements.

The generated state is described as evidence rather than another version
requirement, but operationally it is a denormalized copy that must remain
synchronized with the authoritative inputs.

### Approval, integrity, and policy are conflated

Four concerns can be kept separate:

- Cargo.lock defines the graph.
- Repository objects establish source integrity and evidence.
- System and project policy impose constraints and explicit denials.
- Project admission state proves that a graph and its evidence were reviewed.

The current admission file serializes the underlying graph and evidence and
then translates every admitted identity back into a generated policy allow
rule. A compact commitment to a canonical review document can establish the
same approval without copying the entire document into the project.

### Ordinary vendoring cannot reconcile an intentional edit

`lorry vendor` validates existing admission state before it resolves or
acquires anything. An intentional Cargo.toml or Cargo.lock change therefore
forces the separate `vendor upgrade` path.

Vendoring is already the networked, policy-enforcing, human-approval boundary.
Build, run, and test should reject stale state, but `lorry vendor` should be
the command that repairs it.

### Upgrade owns too many responsibilities

The current upgrade path:

- edits Cargo.toml while preserving its formatting;
- selectively unlocks one package;
- resolves and acquires the candidate graph;
- constructs temporary review policy;
- presents and records approval;
- replaces Cargo.toml, Cargo.lock, and admission state; and
- implements an exact-command recovery journal.

If Lorry does not edit Cargo.toml, only Cargo.lock and an admission commit
marker need replacement. Repository objects can be published first,
Cargo.lock can be atomically replaced second, and admission can be written
last. A crash leaves a detectable mismatch, and rerunning `lorry vendor` can
safely reconstruct and review the candidate.

### Bootstrap state is still a synchronization exception

The original upgrade plan stated that upgrades update
`bootstrap/stage2-seed.toml` in the same transaction. The implementation has a
fixed three-file transaction containing Cargo.toml, Cargo.lock, and
`.lorry/dependencies-v1.toml`; it does not update the bootstrap seed. The
recent seed change was committed separately.

Consequently, upgrading a dependency of Lorry itself can leave its bootstrap
seed stale. The bootstrap representation should be derived or explicitly
regenerated rather than being another implicit upgrade responsibility.

## Upgrade breakage beyond the admission file

The admission file is only one of the frozen copies that fail closed when
something is upgraded. The recent upgrade cycle exercised two more, and the
first observation below narrows what the admission file is actually
responsible for.

### Admission invalidation is narrower than it appears

Both admission fingerprints cover only crates.io packages: the manifest hash
skips non-registry dependencies and the lock hash skips packages without a
crates.io source. Bumping an in-tree path dependency such as moto-rt
therefore does not invalidate admission state. What broke Lorry during the
moto-rt 0.17 move was an exact `=0.16.4` version pin on the path dependency
in Cargo.toml, which had to be removed in a separate commit. Two rules
follow: in-tree path dependencies must never carry version pins, and a
diagnosis of "upgrades break Lorry" must name which frozen copy failed,
because the admission file is only one of several.

### Toolchain upgrades add a permanent frozen oracle

`src/tests/lorry-fixtures/stage1-oracles/cargo-1.99.json` added 1,106 lines
because commit `0c148180`
moved `cargo-compat-version` from 1.98 to 1.99. Oracle families accumulate:
1.97, 1.98, and 1.99 are all checked in, the spec requires identity checks
for all of them, and the Stage-2 resolution check re-runs every retained
Cargo binary in each gate pass. The per-family runtime is small; the
unbounded growth is the problem. Without a lifecycle rule, every future
Cargo release produces another 1,100-line commit and another permanent lane,
independent of any admission redesign.

The oracle set needs a retention policy: keep the oldest-supported and the
newest family, or keep full captures only for the newest family and digests
for the rest. A `cargo-compat-version` bump should be a documented, small
workflow — regenerate, verify family equivalence once, retire whatever the
policy allows — not an open-ended compatibility project.

### The harness freezes other packages' dependency facts

The repository integration harness hardcodes exact versions and checksums for
libc, parking_lot_core, rustix, and signal-hook in the host policy it generates,
and hardcodes the build-script package set by name in the generated Motor
configuration. When Red or Rush upgrades a dependency, Lorry's gate breaks
with no Lorry change — exactly the reported failure mode. The Motor
configuration already derives package identities from the Red and Rush
lockfiles; the host policy and the build-script set must be derived the same
way, from those lockfiles plus verified repository evidence.

## Dependency-state alternatives

| Alternative | Ergonomics | Security and reproducibility | Complexity |
|---|---|---|---|
| Current full admission file | Large diffs and synchronization burden | Strong fail-closed checks | Highest |
| Compact review commitment | Small generated state and simple reconciliation | Equivalent integrity and stale-state detection | Moderate |
| Cargo.lock plus policy only | Simplest workflow | Reproducibility retained, explicit review persistence weakened | Lowest |
| Signed compact commitment | Small state with authorization | Strongest against unauthorized state changes | Requires key and reviewer infrastructure |
| Cargo-backed Linux provisioner | Best Cargo compatibility | Lorry can independently verify Cargo's result | Violates the current no-operational-Cargo requirement |
| Linux provisioning with an offline Motor executor | Smaller Motor surface | Strong offline boundary | Motor cannot acquire or upgrade dependencies itself |

### Recommended compact commitment

Keep a small generated file such as:

```toml
format-version = 2
review-sha256 = "..."
targets = ["x86_64-unknown-linux-gnu", "x86_64-unknown-motor"]

[[capability]]
package = "libc"
version = "0.2.187"
checksum = "..."
build-script = true
```

The hash would commit to a canonical review document containing:

- direct dependency semantics;
- Cargo.lock identities and dependency edges;
- reviewed target closures;
- checksums, licenses, source-tree digests, and build-script presence;
- exact native-tool and build-script grants; and
- relevant format versions.

Lorry would reconstruct this document from Cargo.toml, Cargo.lock, and
verified repository objects. It would compare the hash before treating the
graph as approved. `lorry review` could print the full document or compare it
with a previous admission, while CI could retain the report as review
evidence.

This does not weaken source integrity or reproducibility. Corrupt sources are
still rejected by checksum and source-tree verification, graph changes still
invalidate admission, and explicit policy denials still win. The existing
full state is not signed, so someone able to maliciously change project files
can already replace it. A signature is the appropriate additional mechanism
if admission must resist an unauthorized committer.

The cost is that a one-line hash is opaque in a raw Git diff. Cargo.lock and
exceptional capability changes remain visible, but today's full admission
file lets a reviewer see what was admitted directly in the diff. The
reviewable report is therefore a requirement of this design, not a
mitigation: `lorry review` must reconstruct the complete document offline
and diff any two admissions, and CI must retain the rendered report as
review evidence.

Two boundary conditions need stating. A checkout without the vendored
repository objects cannot recompute the review document; it stays fail-closed
until `lorry vendor` reconstructs and verifies them, which matches today's
behavior for missing sources. There are no external format-version 1 users, so
the repository uses a direct cutover with no reader, translation, or
compatibility window for the old state.

### Recommended reconciliation workflow

The normal direct-upgrade workflow should be:

```sh
# Edit the exact version in Cargo.toml.
lorry vendor
```

`lorry vendor` should:

1. load previous admission only as a comparison baseline;
2. resolve the current manifest using Cargo.lock entries as preferences;
3. acquire and verify missing sources;
4. display the graph, evidence, and capability difference;
5. require approval;
6. publish immutable objects;
7. atomically replace Cargo.lock; and
8. atomically write compact admission last.

An exact direct requirement naturally selects the intended version. A narrow
option can remain for a transitive-only update:

```sh
lorry vendor --update package@old-version --to new-version
```

A one-command direct update could be a convenience wrapper that visibly edits
Cargo.toml and then invokes the same reconciliation path. It need not restore
the old manifest if acquisition fails: the requested edit can remain, and all
build operations remain fail-closed until vendoring succeeds.

This direction should permit deletion of most of the upgrade transaction and
much of the admission parser. A reasonable design target is a net reduction
of roughly 1,000 to 1,500 lines — counted after adding the new canonical
review renderer and comparison code — and generated project state measured
in tens of lines rather than hundreds.

## Why the test gate took hours (historical baseline)

Before the completed test-scope work, the three successful debug native phases
took between 70.73 and 71.27 minutes
each, or 213.1 minutes total. The release phases took between 11.12 and 11.15
minutes each, or 33.4 minutes total. Native execution alone therefore took
246.5 minutes, excluding host preparation and image builds.

The two matrices perform closely comparable native work — the release matrix
compiles Lorry with fat LTO and a single codegen unit, which is heavier, yet
finishes six times faster — so the difference is almost entirely the debug
Motor OS image executing the work. Moving Lorry-only validation to a release
image should bring the debug-artifact passes near the eleven-minute release
figure, cutting the mandated six-pass gate from roughly 247 native minutes
to roughly 67 before any coverage is removed. This is the largest single win
and the least controversial change.

The same evidence directory records seven failed full runs beside the three
passes, so reaching three consecutive passes cost roughly ten runs that day.
A serial 71-minute gate that can fail near its end amortizes poorly; phases
must be ordered so likely failures surface in the first minutes. Host
preparation and image builds are untimed today, so every figure above
understates the true cost of a pass.

Every `test-local.sh` repetition reruns:

- all Cargo compatibility oracles;
- Rust tests and hosted builds;
- Motor image preparation;
- fresh repositories and staged source trees;
- Linux-to-Motor builds of Lorry, Red, Rush, curl, and test fixtures;
- Motor-native debug and release builds of Red and Rush;
- Red tests, simple run tests, and curl/TLS tests;
- first-generation native Lorry self-build;
- second-generation native Lorry self-build; and
- second-generation Red, Rush, and simple-package builds.

Before guest staging, the harness deliberately deletes the staged target
directories. This is valuable for one clean-room acceptance run but ensures
that every matrix repetition pays for another cold native build.

The matrix conflates independent assurance dimensions:

- Lorry debug versus release artifact profile;
- Linux, cross-Motor, and native-Motor build topology;
- debug versus release Motor OS image;
- deterministic reproducibility versus transport/VM reliability; and
- ordinary development versus milestone acceptance.

These dimensions should receive representative coverage without taking their
full Cartesian product on every change.

## Recommended test structure

### Fast local gate: minutes warm, ten to fifteen minutes cold

Run once for an ordinary Lorry code change:

- all Rust tests and Cargo compatibility oracles;
- Linux debug and release Lorry builds;
- Linux-to-Motor debug and release Lorry cross-builds;
- one release Motor OS VM;
- execution of both cross-built Lorry profiles in that VM;
- one Motor-native release Lorry self-build and byte comparison; and
- one small purpose-built package covering library, binary, integration test,
  build script, target dependency, registry dependency, run, and test.

Use a release Motor OS image for Lorry-only debug and release artifact tests.
The OS image profile is relevant when system code changes; it is not a useful
multiplier when only Lorry changed.

Targets are stated warm and cold separately because the currently quoted
native timings exclude host preparation, image building, and boot. The
complete release matrix already finishes its native phase in about eleven
minutes, so this trimmed set fits the cold budget. During iteration the
staged target directories should stay warm; the deliberate clean-room
deletion belongs to the acceptance and exhaustive gates, paid once before
merge rather than on every run.

### Acceptance gate: ten to twenty minutes

Run for high-risk Lorry changes or before merge:

- one cold repository cycle;
- Red or Rush as a real package;
- curl acquisition and TLS only for repository, archive, redirect, curl, or
  policy changes;
- one native self-host generation; and
- release byte-identity comparison.

Executing the native Lorry and using it to build one representative package
establishes basic self-host usability. Rebuilding the complete downstream set
with a second-generation Lorry should not be part of every local gate.

### Exhaustive gate

Reserve the full clean-room campaign for:

- nightly CI and milestone closure;
- bootstrap, compiler-identity, cache-identity, native-tool, or harness
  changes; and
- system changes covered by the repository-wide full test.

Second-generation Lorry plus Red, Rush, curl, both OS image profiles, and full
repetition belong here.

### Repeat nondeterministic boundaries, not the full build

The three release runs produced identical hashes. Debug artifacts are
intentionally not compared because paths and debug information can differ.
Repeating every deterministic compilation therefore adds little information.

If three repetitions are required for reliability, repeat only:

- VM boot and SSH readiness;
- upload/download integrity;
- a tiny native build and run; and
- explicitly concurrent vendoring cases.

Do not repeat image construction, resolver oracles, native self-hosting, and
the complete downstream package set.

### Resize and parallelize the VM before cutting coverage

The guest runs with 4 vCPUs and 2 GiB of memory on a 16-core host, and
native compilation dominates every long phase. Before any coverage is
removed, measure whether more vCPUs and memory shorten the native phase; a
host-resource change may buy back much of the remaining cost without losing
any assurance. The debug and release Lorry matrices are also independent and
can run concurrently in separate VMs once they stop sharing the single tap
network endpoint — the user-mode networking knob in `run-qemu.sh` already
provides per-instance port forwarding.

## Test-policy ownership

`src/bin/lorry/AGENTS.md` should route verification by affected scope:

- Lorry-only changes use the fast local gate plus risk-selected acceptance
  tests.
- Lorry bootstrap or harness changes use the exhaustive Lorry gate.
- Kernel, sys-io, shared-library, image-construction, or repository-harness
  changes use the repository-wide debug and release full tests.

The product specification should define behavioral coverage and acceptance
invariants. A requirement for three consecutive local runs is contributor
workflow and belongs in AGENTS.md rather than spec.md.

Routing should be mechanical: a small script maps changed paths to the
required gate so the decision is never re-derived from prose. The exhaustive
gate also needs a named trigger — a nightly CI job, a cron entry, or a
release-checklist item with an owner. A gate that no schedule invokes
silently stops existing.

## Proposed order of work

1. **Completed 2026-08-04.** Added machine-readable and console per-phase
   timing to the local and native harnesses, including explicit Stage 2 seed,
   Motor image build, host preparation, VM startup, input staging, smoke, and
   full-gate phases. Native evidence summaries retain every phase duration.
2. **Completed 2026-08-05.** Decoupled the Lorry artifact profile from the VM
   image profile and ran both artifact profiles in a release image. The debug
   native self-gate fell from 1,215.6--1,217.0 seconds to 193.9 seconds; total
   measured native phases fell from 1,272.6--1,275.0 seconds to 252.1 seconds.
   The release native self-gate remained stable at 203.5 seconds versus the
   203.7--204.7 second baseline, including byte-identity verification. The
   repository integration gate retains debug image coverage.
3. **Completed 2026-08-05.** Added separate fast, acceptance, and exhaustive
   entry points. The fast gate runs both profiles cheapest-first and supports
   persistent host and guest target directories with `--warm`; acceptance adds
   one release downstream/native smoke campaign; exhaustive retains three
   clean local passes, both second-generation integration campaigns, and the
   dedicated-image Motor registry campaign.
   `test-changed.sh` maps changed paths to the strongest required gate, with a
   contract test for the routing policy. The combined fast gate measured 488.6
   seconds cold and 442.2 seconds with populated warm targets. Warm reuse cut
   the release guest self-build from 203.0 seconds to 100.7 seconds; the first
   warm population run took 583.4 seconds. The first exhaustive campaign passed
   all three local debug/release repetitions and both integration profiles; its
   full native phases took 3,156.5 seconds for debug and 501.9 for release.
4. **Completed 2026-08-06.** The repository integration harness now vendors
   Red and Rush before building either, then derives exact host and Motor policy
   rules from each Cargo.lock, Lorry's generated admission state, and verified
   retained repository sources. The acquisition-only build-script grant is
   replaced before any build runs. The focused contract rejects mismatched
   locks, missing or changed evidence, and incorrect build-script facts while
   allowing locked packages not selected for the tested targets. A release
   native smoke campaign passed in 147.4 seconds.
5. **Completed 2026-08-06.** Added a purpose-built Motor-native fixture to the
   Lorry self-gate. It uses a reviewed `cfg-if` registry object, a Motor-only
   path dependency, and an admitted path dependency whose build script emits
   compiled source. Lorry builds and runs its binary, then runs its library,
   binary, and integration tests. A focused warm release native gate passed in
   218.5 seconds with all three fixture tests green. The exhaustive campaign
   then passed three local debug matrices in 301.7--302.6 seconds, three local
   release matrices in 318.5--321.8 seconds, the full debug native gate in
   3,149.3 seconds, and the full release native gate in 502.8 seconds.
6. **Completed 2026-08-05.** Moved Red, Rush, curl, the synthetic Stage-1
   package/oracles, and downstream second-generation coverage to the repository
   integration gate. The Lorry-local matrix now builds only Lorry and its
   dependencies. crates.io and GitHub acquisition use fail-closed fixtures
   derived from local Cargo caches, with no Internet fallback. Stage-1
   artifact identity is now relational against Cargo rather than pinned to
   compiler-specific digests.
7. **Completed 2026-08-06.** Large Stage-1 captures are retained only for the
   oldest and newest supported Cargo families. Regeneration still captures
   every supported family and rejects adjacent identity or artifact drift;
   every supported family also remains in the live Stage-2 resolution gate.
   The oracle README documents the `cargo-compat-version` bump and separate
   family-retirement workflows.
8. **Designed 2026-08-06; implementation started.** The first inactive patch
   adds the bounded canonical writer, digest helper, empty-registry golden
   vector, and writer limit tests. Model rendering, compact state, command
   integration, and direct repository cutover specified in `step-8-review.md`
   remain; there is no format-version 1 migration or compatibility path.
9. **Remaining.** Make ordinary `lorry vendor` reconcile intentional
   dependency changes.
10. **Remaining.** Remove manifest editing and the three-file transaction from
    the trusted upgrade core.
11. **Remaining.** Derive bootstrap registry entries from lockfiles and
    verified cached objects, retaining only exceptional seeded-Git provenance
    explicitly.

The test items precede the dependency items deliberately: once verification
takes minutes, every later change is cheaper to land and to revert.

This preserves Lorry's independent, offline, fail-closed build model while
making routine dependency upgrades small and making normal verification take
minutes rather than hours.
