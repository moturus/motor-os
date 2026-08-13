# Making Lorry smaller and faster to change

Status: active roadmap. Current behavior is defined by `spec.md`; the compact
admission design is defined by `step-8-review.md`. This document records only
the problem, the completed direction, and the remaining work.

## Problem

Lorry has become expensive to change for two related reasons.

First, dependency changes cross too many representations and workflows.
Cargo.toml already records human intent, Cargo.lock records the resolved graph,
and immutable repository objects record verified source evidence. Historically,
generated admission state copied much of that information again, while the
upgrade command also edited the manifest, resolved and acquired packages,
managed approval, and committed three project files through a recovery journal.
Bootstrap state and compatibility oracles added more synchronized copies. A
routine dependency upgrade consequently produced thousands of lines of code,
generated state, fixtures, and documentation.

Second, verification historically multiplied artifact profile, build topology,
Motor image profile, downstream package coverage, self-host generation, and
repetition into one clean-room matrix. Native compilation was sequential and
the debug Motor image was much slower than release. A healthy exhaustive run
took hours, and failures near the end made small Lorry patches take days to
validate.

The solution must preserve Lorry's important boundaries:

- build, run, and test remain offline;
- Cargo is not an operational dependency;
- lockfiles, source objects, policy, and approval continue to fail closed;
- equivalent release builds remain reproducible across supported hosts;
- test reductions must remove redundant multiplication, not hide defects with
  retries, ignored failures, or longer timeouts; and
- normal development must still exercise Linux, cross-Motor, and native-Motor
  behavior in proportion to the risk of the change.

## What has been done

- Compact format-2 admission replaced the large generated format-1 file. The
  committed state now contains a review commitment, reviewed `(host, target)`
  contexts, and exceptional build-script/native-tool grants. Lorry reconstructs
  and verifies the full review from Cargo.toml, Cargo.lock, and repository
  evidence before compilation.
- Verification was split into mechanically selected fast, acceptance, and
  exhaustive gates. Lorry-local tests now own Lorry; repository integration
  owns Red, Rush, curl, Stage-1 oracles, downstream rebuilds, debug-image
  coverage, and isolated registry-cache campaigns.
- Harness dependency policy is derived from consumed lockfiles and verified
  repository evidence. Acquisition fixtures are fail-closed and offline. Large
  Cargo identity captures are retained only for the oldest and newest supported
  families, while live resolution checks still cover every supported family.
- Phase and per-command timings were added. Lorry now compiles independent DAG
  units concurrently, with deterministic scheduling inputs, isolated outputs,
  and atomic diagnostic blocks. `LORRY_JOBS` can pin the worker count.
- The ordinary native gate uses a compact fixture covering a library, binary,
  integration test, build script, target dependency, and registry dependency.
  Cross-built debug and release Lorry artifacts run in a release Motor image;
  exhaustive repository integration retains debug-image coverage.
- The heavier native workload exposed OS and harness defects in descriptor
  metadata, directory iteration, frame-slab accounting, TCP teardown, VM
  cleanup, and minimal-image selection. Those fixes and focused regressions are
  now part of the repository rather than workarounds in Lorry's tests.

The current exhaustive gates pass. Parallel compilation reduced the debug
native full phase from about 3,036 seconds to about 2,226 seconds; the release
native full phase is about 378 seconds. The remaining performance work is
therefore about campaign concurrency and scope, not an unexplained native
correctness failure.

## Work in progress and future steps

### 1. Bring exhaustive integration below thirty minutes

Target: `lorry-integration-test.sh --exhaustive` and its release counterpart
must complete in at most thirty minutes of combined wall clock. The measured
native full phases alone currently total about 43 minutes when run
sequentially, before host suites, image preparation, staging, and the isolated
registry-cache campaigns.

Instrumentation and parallel unit compilation are complete. The remaining
milestones are:

1. **Overlap independent work within each campaign.** Run the host suite,
   tap-networked native integration, and user-networked registry-cache lane
   concurrently where their inputs are already prepared. Preserve separate
   targets and evidence directories, prefix child output, wait for every child,
   and report every exit status deterministically.
2. **Run debug and release campaigns concurrently.** The existing tap endpoint
   is singular. Parameterize the user-network host-forward port in
   `run-qemu.sh`, add a user-network mode to native integration, parameterize
   the registry-cache port and ownership guard, then give the two profiles
   disjoint endpoints. Combined wall clock should become the slower campaign
   rather than their sum.
3. **Review debug-campaign scope.** The debug image currently repeats both
   Lorry generations and downstream rebuilds at roughly five times the release
   image's execution cost. The proposed debug lane keeps one pass through every
   distinct flow: vendoring, build, test, curl/HTTPS fixtures, and one native
   Lorry self-build. The release lane retains second-generation reproducibility,
   byte identity, and duplicate downstream builds. This coverage change needs
   explicit review before implementation.
4. **Re-measure VM sizing last.** Eight-vCPU guests passed three repaired-
   harness runs at roughly the four-vCPU runtime, proving there is no known
   width-related correctness ceiling but not yet proving a speedup. Select the
   default vCPU and memory values only from end-to-end measurements and memory
   headroom; keep the overrides for controlled comparisons.

After every milestone, record total wall time and the slowest command. Stop and
re-plan if concurrency merely moves contention between lanes or if the target
would require weaker coverage. Do not add retries, extend budgets, or serialize
around a product defect.

One separate system issue can materially distort these measurements:
`sys-tty`'s stdout and stderr pumps loop on `read` returning `Ok(0)`, so an EOF
can consume a full guest core. Fixing that requires its own reviewed system
patch and focused regression; Lorry's harness must not compensate for it.

### 2. Finish the compact-admission workflow

The format-2 cutover is complete, but the user workflow still exposes the old
upgrade architecture. Finish the dependency work in this order.

#### 2.1 Complete: `lorry review` and approval output

The offline, non-mutating command specified in `step-8-review.md` now
reconstructs and verifies the committed review before writing stdout, then
emits exact canonical TOML for CI retention or ordinary `diff` comparison. It
does not modify the project, target tree, cache, or repositories.

The vendor/upgrade approval display pairs an unambiguous changed item's removal
immediately with its addition while retaining stable semantic order for
unpaired changes.

Acceptance coverage proves byte stability, execution from an inspection host
not present in the reviewed contexts, stale or missing evidence, no partial
stdout on failure, and filesystem non-mutation.

#### 2.2 Reconcile intentional changes in ordinary `lorry vendor`

Cargo.toml should remain the only human-edited dependency declaration. The
normal direct-upgrade workflow should become:

```sh
# Edit the exact requirement in Cargo.toml.
lorry vendor
```

Ordinary vendoring should use the committed graph as its review baseline,
resolve the edited manifest while retaining compatible Cargo.lock preferences,
acquire and verify missing objects, display the semantic graph/evidence/
capability diff, request approval, publish immutable objects, replace
Cargo.lock, and write compact admission last. Build, run, and test remain
read-only and fail closed while the manifest, lock, or commitment is stale.

The transaction should rely on reconstructible state rather than copying the
old graph into another project file. A crash after object publication is safe;
a missing or stale final admission marker is detectable and a later identical
`lorry vendor` run can reconstruct the candidate. The final CLI for selecting a
transitive-only update must be reviewed before implementation.

#### 2.3 Remove the trusted upgrade core

Once ordinary vendoring owns reconciliation, delete manifest source-span
editing and the fixed Cargo.toml/Cargo.lock/admission three-file journal from
the trusted upgrade path. Any remaining convenience command should feed the
same vendor reconciliation implementation rather than maintain a second
resolver, review, acquisition, and commit workflow.

The intended result is a net code reduction: generated project state should
remain tens of lines, and dependency upgrading should no longer require a
separate transaction coordinator.

#### 2.4 Derive bootstrap registry state

Derive Stage-2 bootstrap registry membership from the Lorry and curl lockfiles
and verified cached objects. Keep only exceptional seeded-Git provenance and
the independently required Cargo-oracle objects explicit. Regeneration must
fail if a required object is missing or its evidence differs; it must not
silently fetch during offline reproduction.

This removes the remaining routine version/checksum copy that can become stale
when Lorry or curl changes dependencies.

### 3. Closure criteria

This roadmap is complete when:

- both exhaustive repository campaigns finish within thirty minutes combined
  without hiding failures or weakening the agreed coverage;
- `lorry review` provides stable offline review artifacts and change displays
  pair related removals/additions;
- ordinary `lorry vendor` safely reconciles intentional manifest changes;
- the separate manifest-editing upgrade transaction has been removed or
  reduced to a thin wrapper around reconciliation; and
- bootstrap registry membership is derived from authoritative lockfiles and
  verified objects.

Each implementation step remains a separate small patch with the gate selected
by `test-changed.sh`. Any change to verification scope, update CLI, transaction
semantics, or bootstrap trust boundaries requires review before code changes.
