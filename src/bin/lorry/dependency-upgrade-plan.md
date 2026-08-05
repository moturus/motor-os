# Lorry dependency admission and upgrade plan

Status: **implemented locally; awaiting final verification and review**

## Objective

Keep `Cargo.toml` as the only project dependency file that humans edit while
retaining exact, reviewed, reproducible dependency admission. Cargo and Lorry
may generate `Cargo.lock`. Lorry owns all additional portable project state
below `.lorry/` and changes it only through explicit commands.

The primary workflow is:

```text
lorry vendor upgrade libc --to 0.2.187
```

The same command must reconcile a version already changed in `Cargo.toml`, a
compatible version already selected by `cargo update` in `Cargo.lock`, or an
unchanged exact direct pin that Lorry is asked to rewrite. It must not silently
approve a Cargo-produced graph.

## User-visible model

- `Cargo.toml` is the sole human-authored dependency intent.
- `Cargo.lock` is the Cargo-compatible resolved graph. Cargo or Lorry may
  generate it.
- `.lorry/dependencies-v1.toml` is deterministic, checked-in, machine-owned
  admission state. It is evidence about a graph, not a second resolver input.
- Host-specific repository, compiler, linker, runner, curl, CA, and native-tool
  paths remain installation configuration. They must not enter portable
  project state.
- Ordinary path dependency source edits do not require an upgrade. Registry
  objects and required patched sources do.

Build, run, and test never modify Cargo.lock or `.lorry/`. If Cargo.toml,
Cargo.lock, and the admitted state disagree, they fail before source lookup or
compilation and show the exact old/new package identities. A one-package
change recommends the complete `lorry vendor upgrade NAME --to VERSION`
command. A wider graph change recommends reviewing the summarized graph with
`lorry vendor upgrade --from-cargo-lock`.

## Portable state format

`.lorry/dependencies-v1.toml` has `format-version = 1`, exact keys, bounded
TOML input, deterministic ordering, and no timestamps, usernames, physical
repository paths, or other host observations. It contains:

- a canonical semantic fingerprint of all Cargo.lock package nodes and edges;
- the exact registry identities recorded by Cargo.lock, including inactive
  nodes, so formatting-only Cargo.lock changes do not invalidate state;
- the target triples whose selected closures were admitted;
- exact admitted package source identity, checksum or required-patch source
  digest, license, source-tree digest, and build-script presence;
- the build-script and native-tool capabilities explicitly approved for each
  admitted identity; and
- the Lorry state schema and source-tree format versions.

The complete locked registry list and the selected admitted list are distinct.
An inactive Cargo.lock node may be recorded without claiming its source was
admitted. A build for a target not covered by the state fails and recommends
vendoring that target.

State entries become exact synthetic allow rules during policy evaluation.
They can satisfy default-deny policy but cannot override any matching explicit
deny, system constraint, resource limit, required patch, or native-tool
restriction. Prepared sources must reproduce every admitted evidence field.

Projects without portable state retain the existing configuration-policy path
as a compatibility mode. The next successful `lorry vendor` writes state.
This avoids requiring changes to existing packages outside `src/bin/lorry` in
this increment. The Lorry package itself and all new upgrade fixtures will
carry portable state, exercising the new path in normal self-builds.

## Command surface

```text
lorry [+toolchain] [GLOBAL] vendor [--accept-all]
lorry [+toolchain] [GLOBAL] vendor upgrade PACKAGE --to VERSION
lorry [+toolchain] [GLOBAL] vendor upgrade --from-cargo-lock
```

`VERSION` is one complete semantic version, not a range. `PACKAGE` initially
accepts a direct dependency alias or an unambiguous locked package name.
`NAME@OLD_VERSION` disambiguates multiple locked versions.

For one direct crates.io dependency, `--to` rewrites only its `version` value,
preserving surrounding Cargo.toml spelling and formatting. It supports root
and target-conditioned dependency tables, renamed dependencies, and string or
table forms. It rejects path, Git, alternative-registry, ambiguous, workspace,
and inherited dependencies.

For a transitive package, Cargo.toml is unchanged and the selected version must
satisfy every active requirement. `--from-cargo-lock` adopts no version intent;
it independently resolves and verifies the Cargo-selected graph, then presents
the full difference from `.lorry/dependencies-v1.toml`.

Resolution unlocks only the named old package and packages forced to move by
its requirements. Existing compatible lock preferences remain authoritative,
so unrelated packages do not drift.

## Review and admission

Upgrade mode privately resolves and stages candidates while enforcing:

- explicit policy denies and system constraints;
- HTTPS, index, archive, checksum, extraction, source-tree, and resource
  integrity;
- package-count, depth, byte, file, and transaction limits; and
- required-patch identity and provenance.

Default-deny absence is deferred only inside the explicit upgrade transaction
so evidence can be inspected. Before any project file changes, Lorry prints a
deterministic summary of direct requirements, locked graph additions/removals,
checksums, licenses, source digests, build scripts, and native-tool roles.

An upgrade of an already admitted package proposes its previous capability set
but does not silently carry it forward. One interactive confirmation approves
the displayed package and capability changes. A newly introduced native-tool
role cannot be inferred and requires an existing administrator grant; the
upgrade otherwise fails with an actionable diagnostic. `--accept-all` keeps
its current meaning for ordinary package approval and must not silently grant
new build-script or native-tool capability during an upgrade.

## Transaction and recovery

Repository objects remain immutable and may be published before project state;
an unused verified object is harmless. Cargo.toml, Cargo.lock, and portable
state cannot be replaced atomically as one filesystem object, so upgrade uses
a bounded journal below `.lorry/transactions/`:

1. validate that no unfinished transaction exists;
2. record original file identities and privately stage every replacement;
3. fsync staged files and the journal;
4. publish immutable repository objects;
5. replace Cargo.toml when needed, then Cargo.lock;
6. replace `.lorry/dependencies-v1.toml` last as the commit marker; and
7. remove the journal and fsync `.lorry/`.

Build/run/test fail closed while a journal exists. Rerunning the identical
upgrade verifies original/current/staged identities and completes it; it does
not retry acquisition or conceal a failure. Conflicting external edits stop
with recovery instructions.

## Bootstrap state

The Stage-2 seed currently duplicates lock identities and contains stale graph
membership: `libc 0.2.186` is in Lorry's Cargo.lock but is marked only as a
curl-graph object. This increment replaces hand-maintained registry closure
with generated bootstrap state under `src/bin/lorry/.lorry/`.

The canonical bootstrap state names its lock-graph inputs and preserves the
separately reviewed seeded-Git provenance. Registry identities, checksums,
licenses, build-script flags, graph membership, and counts are regenerated
from the lock graphs plus verified repository evidence. Tests recompute those
facts instead of hard-coding package-name sets or counts.

`bootstrap/stage2-seed.toml` remains a generated compatibility output because
`src/bin/curl/build-motor.sh` currently consumes that path and this task may
not edit files outside `src/bin/lorry`. Upgrade rewrites the canonical hidden
state and compatibility output together in the same journal. A test requires
them to represent the same closure. Neither is human-edited.

Exact dependency versions are removed from normative prose. `spec.md` names
Cargo.toml, Cargo.lock, and `.lorry` state as the machine-readable authorities.

## Incremental implementation

Each implementation patch should remain approximately 100–300 lines including
tests where practical.

1. Specify the command, state schema, mismatch behavior, policy precedence,
   transaction contract, and compatibility mode in `spec.md`; rewrite the
   human workflow in `README.md`.
2. Add canonical state parsing/rendering, lock-graph fingerprinting, exact-key
   validation, and malformed/duplicate/resource-limit tests.
3. Add state-versus-lock and state-versus-evidence comparison with precise
   one-package and multi-package diagnostics.
4. Merge admitted state into policy evaluation while proving explicit denies,
   limits, required patches, and native-tool restrictions still win.
5. Extend CLI parsing/help for `vendor upgrade`, exact versions, disambiguated
   package IDs, and `--from-cargo-lock`.
6. Add formatting-preserving direct dependency version rewriting and tests for
   string, table, renamed, target-conditioned, ambiguous, and rejected forms.
7. Add selective unlock/resolution and candidate review mode; prove unrelated
   locked versions are preserved and denied candidates cause no writes.
8. Add journaled manifest/lock/state commit and interruption/conflict recovery
   tests.
9. Make ordinary vendor emit portable state and upgrade adopt already updated
   Cargo.lock graphs after independent verification.
10. Generate the Lorry package's current state, generated bootstrap closure,
    and compatibility seed; remove hard-coded seed package/count expectations.
11. Add a deterministic Linux end-to-end fixture below
    `src/bin/lorry/tests/` covering manifest-first, Cargo-lock-first, rejection,
    approval, exact output, warm verification, unrelated-version preservation,
    and interruption.
12. Extend `src/bin/lorry/test-native.sh` with Motor-native state parsing,
    mismatch diagnostics, policy precedence, and an offline pre-populated
    Cargo-lock-first upgrade followed by a native build.
13. Add a Lorry-owned local matrix driver covering Linux-to-Linux,
    Linux-to-Motor, and Motor-to-Motor validation in one debug or release pass.
14. Create/update `design.md`, finish the human README and rigorous spec audit,
    and update the Stage-3 resume document to reflect the implemented slice.

Only `src/tests/full-test.sh` may be changed outside `src/bin/lorry`, and only
to invoke the new Lorry-owned Linux test if it is not already reached
transitively. No production source outside `src/bin/lorry` changes.

## Verification gate

During development, run focused unit and deterministic fixture tests after
each patch and format Rust changes with `cargo +nightly fmt`. Before review:

1. `cargo test --locked` and `cargo test --locked --release` in
   `src/bin/lorry`;
2. the new Linux dependency-upgrade contract in debug and release modes;
3. existing Stage-1, curl-contract, vendoring, cache, bundle, sandbox, seed,
   and self-build gates reached by the Lorry integration harness;
4. `src/bin/lorry/test-native.sh --full` and its release form, including the
   new offline native upgrade fixture;
5. the Lorry-owned local matrix driver three consecutive times in debug mode
   and three consecutive times in release mode; each pass covers
   Linux-to-Linux, Linux-to-Motor, and Motor-to-Motor builds and tests; and
6. a final warning check, diff audit, generated-state reproducibility check,
   and dirty-worktree review.

No commit is created. Test logs and failure evidence remain in the existing
Lorry target/evidence locations.

## Existing unrelated worktree state

The user-owned deletion of `src/bin/lorry/work-in-progress.md` remains
untouched. The already requested `package.default-run` Stage-2 rejection,
regression test, and Stage-3 `--bin` plan update remain separate pending
changes and will be included in verification without being rewritten as part
of dependency upgrade work.
