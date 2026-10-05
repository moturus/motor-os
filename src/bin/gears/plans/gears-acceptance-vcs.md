# Repository evidence for task acceptance

Status: proposed; needs the user's choice before phase 7 implementation.
This supplements [phase 7](gears-batteries.md), which records explicit user
acceptance alongside the check state, commit and uncommitted-change hash.

## Finding

Motor OS `gix log` prints abbreviated commit ids. Its `status` prints
human-readable paths, with lossy conversion for non-UTF-8 names. `diff`
supports worktree and staged changes, but a binary change reports that the
files differ without their contents; untracked contents are not included.
Hashing these reports cannot identify the complete accepted state. Different
binary edits can have the same report.

The current sources are `src/bin/gix/src/log.rs`, `status.rs`, `diff.rs`
and `main.rs`. These are interface limitations for this new use case, not
reported Gix defects.

## Recommended approach: a read-only Gix command

Add a command such as `gix snapshot` that emits versioned JSON with the full
HEAD commit id and a deterministic fingerprint of uncommitted changes.
Use the existing repository library in Gix to enumerate staged changes,
worktree changes and untracked files, honoring Git ignore rules. Include
file contents, paths and relevant modes, including binary files, symlinks
and staged contents that differ from the worktree. Preserve path bytes when
hashing; do not derive identity from display text. Include the fingerprint
algorithm and its version in the output.

Call this command from batteries on Motor OS and Linux. Linux installation
would therefore require Gix beside the other coding tools. An alternative
Linux adapter may use Git's machine-readable commands and the same
fingerprint rules; it needs parity tests rather than assumptions based on
the rendered diff. Decide that installation requirement before implementing
the consumer.

Advantages:

- Gix owns Git format handling, filters and repository semantics.
- Batteries keeps its existing small dependency set.
- Other consumers can use the same explicit repository evidence interface.
- A binary edit and a change to an untracked file produce different hashes,
  even if their displayed status remains unchanged.

Costs:

- This adds a public Gix command and tests beyond the batteries crate.
- Linux needs Gix installed or an independently validated Git adapter.
- The fingerprint contract must specify submodule and conflict handling;
  unsupported states must be reported explicitly.

Example output, with abbreviated illustrative values:

```json
{"version":1,"commit":"abc123…","changes_hash":"sha256:def456…"}
```

## Alternative: a repository library shared with batteries

Expose the same read-only inspection through the existing `motor-gix`
library, and add a path dependency from batteries. Use one implementation
and the same fingerprint contract on both platforms. No Gix executable is
required to accept a task.

Advantages:

- Both platforms use the same repository implementation and fingerprint.
- There is no subprocess or separate command installation requirement.
- The acceptance consumer receives typed results directly.

Costs:

- Batteries gains Gix's larger dependency graph and a direct coupling to
  its repository library. Binary size and native build cost need measurement.
- A new library interface and Gix tests are still needed.
- This is an additional dependency decision beyond the authorized YAML
  parser; it should be deliberate.

For either approach, a clean repository has the same empty-change hash;
an unborn repository has no HEAD commit yet. A missing repository or failed
inspection must be displayed and recorded as unavailable, never as a clean
tree or an invented hash. Explicit user acceptance remains distinct from a
passing check and from a claim that a skill caused success.

## Incremental implementation after the decision

1. Repository fingerprint and focused Gix regressions: clean, staged,
   unstaged, untracked, binary, modes, symlinks and ignored build output.
2. Versioned inspection interface and a portable native fixture.
3. Batteries acceptance record and `gears-batteries accept SESSION`.
4. `/accept`, the workspace-change hint and real-hook regression coverage.

Keep each patch small, format with the selected toolchain and gate Gix
changes with its component tests, batteries changes with the batteries gate,
and Gears changes with the Gears gate. Run the final developer-image gate
only in release mode. No OS, Lorry, boot-time or external repository code
changes are proposed.
