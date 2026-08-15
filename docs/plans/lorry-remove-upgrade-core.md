# Remove Lorry's trusted upgrade core

Status: implemented.

## Goal

Remove the manifest source-span editor and the fixed
`Cargo.toml`/`Cargo.lock`/admission journal now that ordinary `lorry vendor`
owns dependency reconciliation. Keep one resolver, acquisition, approval,
publication, and state-last commit path.

The change must preserve Lorry's ability to select a transitive update without
requiring Cargo at runtime.

## Recommended CLI

- Direct dependency update: edit its requirement in `Cargo.toml`, then run
  `lorry vendor`.
- Transitive-only update: retain
  `lorry vendor upgrade NAME[@OLD_VERSION] --to VERSION`, but restrict it to a
  locked transitive crates.io package. It becomes a thin selector passed to
  ordinary vendor reconciliation and never edits `Cargo.toml`.
- Remove `lorry vendor upgrade --from-cargo-lock`; ordinary `lorry vendor`
  already performs that operation.
- Continue to reject `--accept-all` for any dependency change.

Keeping the transitive selector avoids making Cargo an operational dependency.
Removing the whole `upgrade` command would leave no Lorry-native way to move a
transitive lock entry, while retaining direct-dependency rewriting would keep
the duplicate human-intent editor that this step is intended to remove.

## Commit and interruption model

The thin selector uses the same ordinary-vendor transaction:

1. reconstruct the committed review from the visible manifest and lock when
   possible;
2. resolve with all compatible lock preferences retained except the selected
   transitive identity;
3. acquire and verify missing immutable objects;
4. obtain interactive approval through the common review path;
5. publish repository objects;
6. atomically replace `Cargo.lock` when it changed; and
7. atomically write compact admission last as the commit marker.

No project-file journal is required. Before the lockfile replacement, the
visible project is unchanged and the selector can be rerun. After lockfile
replacement but before compact state, ordinary `lorry vendor` detects stale
admission and reconstructs the same visible candidate. Published repository
objects are immutable and safe to leave behind after interruption.

The old transaction path becomes inert data after the cutover. Lorry will no
longer read, resume, or block on it. Any partially installed visible files are
still governed by lock/admission reconstruction and fail closed until ordinary
vendoring succeeds.

## Implementation patches

1. Move the shared semantic change display and approval prompt out of the old
   transaction implementation without changing behavior. Add focused golden
   tests for paired semantic changes and baselineless reports.
2. Pass an optional transitive selection through ordinary vendor
   reconciliation. Route the retained package form through that path, reject a
   direct selection with guidance to edit `Cargo.toml`, and cover unchanged,
   approved, declined, noninteractive, ambiguous, and policy-denied cases.
3. Remove `--from-cargo-lock`, manifest rewriting, journal staging/recovery,
   transaction guards, and their obsolete tests. Update CLI help, diagnostics,
   `README.md`, `design.md`, `spec.md`, `step-8-review.md`, and
   `make-it-faster.md` in the same cutover patch.

Each implementation patch will use `src/bin/lorry/tests/test-all.sh`. No
repository-wide OS test is required unless a patch grows beyond Lorry-owned
code.

## Acceptance criteria

- Direct dependencies can be changed only through visible `Cargo.toml` edits
  followed by ordinary vendoring.
- The retained selector changes only the requested transitive identity and
  packages forced to move by dependency constraints.
- All dependency changes use the common review, repository publication,
  lockfile replacement, and compact-state-last implementation.
- Build, run, test, and review continue to fail closed on stale visible state.
- No code reads or writes `.lorry/transactions/dependency-upgrade-v1`.
- The patch series is a net code reduction with no new warnings.
