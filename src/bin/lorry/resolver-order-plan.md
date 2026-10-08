# Plan: resolve dependencies in Cargo's order

Status: proposed, not started.

## Problem

Since a5cbfa08, Lorry tries the versions of one dependency in Cargo's order.
It still picks the next dependency to resolve in a different order. Cargo
takes the dependency with the fewest candidates first. Lorry takes them first
in, first out.

This matters only when the resolver must backtrack. Then the two tools can
write different locks. Example, checked with Motor Cargo 1.99:

- `a` has versions 1.0.0, 1.1.0 and 1.2.0; `a` 1.1.0 and 1.2.0 need
  `s = "=1.0.0"`.
- `b` has versions 1.0.0 and 1.1.0; `b` 1.1.0 needs `s = "=1.1.0"`.
- The root needs `a = "1"` and `b = "1"`.

Cargo resolves `b` first (two candidates) and locks a 1.0.0, b 1.1.0 and
s 1.1.0. Lorry resolves `a` first and locks a 1.2.0, b 1.0.0 and s 1.0.0.

## What Cargo does

From `core/resolver` in cargo 0.87.1:

1. Selecting a package makes a group of its dependencies. The group is sorted
   by candidate count, smallest first. Ties keep the package's own order.
2. A path package's own order is: `[dependencies]`, `[dev-dependencies]`,
   `[build-dependencies]`, then each `[target.X]` table sorted by X, with
   dependencies, build-dependencies and dev-dependencies. Names inside a table
   are sorted. A registry package keeps its index order.
3. The next dependency comes from the group whose next dependency has the
   fewest candidates. Ties go to the older group.
4. The count is the number of versions that match the requirement when the
   group is made.

Lorry keeps document order and puts build-dependencies before
dev-dependencies, so even its ties differ today.

## Changes

1. Order a path package's dependencies as Cargo does (`src/manifest.rs`).
2. Replace the resolver's event queue with Cargo-style groups
   (`src/resolver.rs`, `src/resolver/search.rs`).
3. Load index entries and count candidates when a group is made, not when
   its dependency is reached. `vendor` then fetches an entry when the parent
   is selected, as Cargo does.
4. Add a Cargo oracle for the example above, and one for ties across
   tables and target tables.

Two patches, about 250 lines with tests. Exact locked builds and admission
do not change: each dependency there has a single allowed version.

## Differences that remain

- Lorry resolves host and target feature contexts separately, so one
  package can make more than one group. The extra groups normally select
  packages that are already chosen. If one of them causes backtracking, the
  result can still differ from Cargo's.
- Lorry fetches a crate's sparse index only when no cached version matches.
  Cargo refreshes it. With an existing lock, both prefer the locked versions.
