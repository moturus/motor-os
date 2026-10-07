# Review: delete the single-package build path?

Date: 2026-10-07. Measured code: `78a0b867` (later commits change only docs).

## Question

Lorry still has two build paths. The shared workspace path can build
everything. The older narrow path still handles `build` and `run` of one
package with no build script, no feature flags, and no binaries that have
`required-features`. Can we delete the narrow path?

## What the narrow path buys

Both paths first open the dependency source and verify admission. After
that, the narrow path checks a "fresh root profile" record. The record holds
a digest of the build inputs. If the digest matches the last build, Lorry
replays the result and stops. It does not prepare the dependency graph or
check each unit.

The shared path has no such record. It prepares the graph and checks every
unit on every run, even when nothing changed.

## Measurements

The test builds Lorry itself: 138 dependency packages, 170 dependency
units. Every run is warm and nothing changed between runs. Each number is the
median of 7 runs. A prototype binary took the shared path when
`LORRY_FORCE_SHARED` was set and was otherwise identical to the branch head.

| Command | Host fast | Host shared | Motor fast | Motor shared |
| --- | --- | --- | --- | --- |
| `build --release` | 2.2 s | 3.2 s | 6.8 s | 10.2 s |
| `run --release -- --version` | 2.2 s | 3.1 s | 6.9 s | 10.3 s |
| `check` | 3.2 s | 3.1 s | 10.5 s | 10.5 s |

Motor ran the release dev image with 8 CPUs and 8 GiB. The Motor numbers
include a 15 ms ssh round trip. A cold `build --release` on Motor took 200 s.

`check` costs the same on both paths because the narrow path has no fast
path for `check`.

A host trace shows where the time goes:

- Both paths: 0.5 s to open the dependency source and 1.6 s to verify
  admission. That is all of the fast path.
- Shared path only: 0.6 s to set up the dependency build cache and 0.3 s to
  check 170 units.

## Findings

1. Deleting the narrow path now would make warm `build` and `run` 45-50%
   slower: 1 s on the host and 3.4 s on Motor. That is too much.
2. The saving comes only from the fresh-profile record, not from the narrow
   graph code. Without the record, both paths cost the same, as `check`
   shows.
3. Today `check`, `test`, and any build with a build script, features, or
   several members never get the fast path. On Motor they pay the full
   10.5 s even when nothing changed.
4. Admission verification is the largest cost on both paths (1.6 s of 2.2 s
   on the host). It is a separate follow-up and is not part of this
   question.

## Recommendation

Do not delete the narrow path yet. Do it in two steps:

1. Give the shared path the same fresh-profile record. The digest must also
   cover the selected members, the feature requests, the target selection,
   and every selected member's manifest and source. Add contract tests that
   change each of these and expect a rebuild.
2. Then delete the narrow path and the `shared` predicate in
   `src/engine.rs`. `--use-cargo-registry` also uses the narrow prepare code
   (`src/cargo_registry.rs`), so step 2 must move it first.

Step 1 also speeds up `check`, `test`, and multi-member builds. On Motor,
those warm runs should drop from about 10.5 s to about 7 s.

## Effort and risk

- Step 1: about 150-250 lines plus the contract tests, 1-2 days.
- Step 2: removes roughly 300 lines plus the tests that only exercise the
  narrow path.
- Risk: if the digest misses an input, Lorry reuses stale artifacts. The
  step 1 tests must cover every input in the digest.
