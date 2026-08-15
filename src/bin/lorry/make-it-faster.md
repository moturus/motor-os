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
OS-packaging seed state and validation-only compatibility oracles added more
synchronized copies. A routine dependency upgrade consequently produced
thousands of lines of code, generated state, fixtures, and documentation.

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
- Verification now has one Lorry-owned suite with a hard 30-minute budget.
  Focused Rust tests cover internal behavior; small external contracts cover
  only Cargo identity, real registry acquisition, curl process behavior,
  offline review, and native Motor execution.
- Acquisition fixtures are fail-closed and offline. Live resolution checks
  cover every supported Cargo family, while one dependency-free package is the
  release artifact oracle for the paired Cargo.
- Phase and per-command timings were added. Lorry now compiles independent DAG
  units concurrently, with deterministic scheduling inputs, isolated outputs,
  and atomic diagnostic blocks. `LORRY_JOBS` can pin the worker count.
- The native gate uses one release Motor image and a compact fixture covering a
  library, binary, integration test, build script, target dependency, and
  registry dependency. It also retains one byte-identical native self-build.
- The heavier native workload exposed OS and harness defects in descriptor
  metadata, directory iteration, frame-slab accounting, TCP teardown, VM
  cleanup, and minimal-image selection. Those fixes and focused regressions are
  now part of the repository rather than workarounds in Lorry's tests.

The former exhaustive matrix spent hours rebuilding downstream applications,
custom images, repositories, profiles, and Lorry generations. Those are not
distinct Lorry features. Their application and OS behavior belongs to their
own suites, while their Lorry semantics are exercised by compact fixtures.

## Work in progress and future steps

### 1. Complete: one bounded product suite

`tests/test-all.sh` is the only Lorry gate. It runs each distinct boundary once
and fails if total wall time exceeds 1,800 seconds. It contains:

1. the complete Rust test suite in one profile;
2. live supported-Cargo resolution and one native/cross release identity
   fixture against the paired Cargo;
3. the offline, non-mutating review contract;
4. one fresh 13-package registry acquisition and one warm no-download reuse;
5. one curl build followed by the ignored external-process/TLS cases; and
6. one release Motor VM in which cross-built Lorry self-builds byte-identically
   and builds, runs, and tests the compact native fixture.

The complete suite measured 412 seconds on 2026-08-15. Its slowest phase was
the native Lorry self-build and fixture at 155 seconds; host preparation for
that phase took another 88 seconds.

The following multiplication was removed:

- three-run repetition and duplicate debug/release Rust suites;
- Red and Rush vendoring, builds, tests, and second copies;
- debug-image coverage and dedicated minimal images;
- second Lorry generations;
- duplicate fresh repositories and duplicate curl builds;
- separate native registry/curl campaigns; and
- driver-routing and image-layout tests for the deleted harness itself.

Focused Rust tests retain cold/warm/corrupt cache, interrupted/concurrent
publication, policy, admission, archive, redirect, sandbox, build-script,
native-tool, build/run/test, and reconciliation coverage. No test was ignored,
given a retry, or granted a longer timeout to meet the budget.

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

#### 2.2 Complete: reconcile intentional changes in ordinary `lorry vendor`

Cargo.toml should remain the only human-edited dependency declaration. The
normal direct-upgrade workflow should become:

```sh
# Edit the exact requirement in Cargo.toml.
lorry vendor
```

Ordinary vendoring resolves the edited manifest while retaining compatible
Cargo.lock preferences, acquires and verifies missing objects, requests
approval, publishes immutable objects, replaces Cargo.lock, and writes compact
admission last. Build, run, and test remain read-only and fail closed while the
manifest, lock, or commitment is stale.

When the visible inputs still reproduce the committed review, approval uses a
semantic graph/evidence/capability diff. A manifest edit destroys the previous
direct semantics because format 2 retains only their commitment; in that case
vendoring displays the previous hash and complete verified candidate instead.
This keeps `Cargo.toml` as the only human-edited declaration without expanding
compact state or trusting a retained review artifact. Reconciliation rejects
`--accept-all` and requires one interactive approval.

The transaction should rely on reconstructible state rather than copying the
old graph into another project file. A crash after object publication is safe;
a missing or stale final admission marker is detectable and a later identical
`lorry vendor` run can reconstruct the candidate. The final CLI for selecting a
transitive-only update must be reviewed before implementation.

#### 2.3 Remove the trusted upgrade core

Status: complete.

Once ordinary vendoring owns reconciliation, delete manifest source-span
editing and the fixed Cargo.toml/Cargo.lock/admission three-file journal from
the trusted upgrade path. Any remaining convenience command should feed the
same vendor reconciliation implementation rather than maintain a second
resolver, review, acquisition, and commit workflow.

Ordinary vendoring now owns direct manifest and externally changed lockfile
reconciliation. The retained transitive-only selector feeds that same path.
The source-span editor, fixed three-file journal, recovery flow, and transaction
guards have been removed.

### 3. Closure criteria

This roadmap is complete when:

- the complete `tests/test-all.sh` suite finishes within its 30-minute budget;
- `lorry review` provides stable offline review artifacts and change displays
  pair related removals/additions;
- ordinary `lorry vendor` safely reconciles intentional manifest changes;
- the separate manifest-editing upgrade transaction has been removed, with the
  transitive selector reduced to a thin input to reconciliation.

Each implementation step remains a separate small patch and runs
`tests/test-all.sh`. Any change to update CLI, transaction semantics, or
OS-packaging trust boundaries requires review before code changes. Cargo
comparisons and the release VM are validation infrastructure; they are not
Lorry runtime features.
