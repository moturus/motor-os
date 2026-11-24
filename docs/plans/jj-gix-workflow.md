# Remaining Jujutsu and gix work

## Jujutsu on Motor OS

Port jj for local authoring and publishing from the installed Motor
toolchain. The jj port belongs in a separate Jujutsu checkout. Share Git
operations with `src/bin/gix` through a Rust API. Changes to the gitoxide
fork and its revision must be reviewed separately from packaging here.

- Pin a compatible jj and gitoxide pair, use the Motor async and terminal
  dependencies, and audit cancellation and cleanup with `panic = "abort"`.
- Port jj's path, lock, temporary-file and working-copy operations. Preserve
  exclusive publication, executable modes, and Git symlink entries represented
  as regular files. Support colocated and non-colocated repositories. Use
  the editor for descriptions, hunk selection and conflict resolution.
- Replace the `git` subprocess calls for remote discovery, cloning, fetching,
  pruning and ref import/export. Keep revsets, bookmarks, tags and the
  operation log consistent if Git refs are published before a jj transaction
  can finish. Cover shallow fetches, pruning and remote default-branch
  changes. Report how to resume after an interrupted import.
- Connect `jj git push` to a typed transport and pack API. Apply jj's
  expected-old-target checks to each bookmark or tag. Update local tracking
  only for confirmed remote successes. Distinguish partial success, failed
  local bookkeeping and a lost remote response.
- Exercise editing, snapshotting, rebase, merge, split, squash, undo and
  interrupted operations in a guest. Check the exported objects with host
  Git. For remote workflows, use local HTTPS and SSH fixtures and verify
  that jj never invokes an installed Git binary or repository-provided helper.
- Package jj alongside gix. Decide how to support native jj builds through
  Lorry. Check cancellation, idle CPU, startup, memory use and temporary
  disk use on both loose and packed repositories.

## gix follow-ups

- A standalone `gix rebase REV` needs a local entry point to the replay and
  recovery machinery. Add guest-to-host fixture coverage of both ordinary
  pull and a diverged `pull --rebase` in `src/tests/cross-test.sh`.
- Remaining push features include default remote and branch selection,
  multiple refspecs, deletion and `--set-upstream`. Deletion requires the
  remote's `delete-refs` capability. Multiple updates need a result and lease
  check per ref, including a clear outcome when only some updates succeed.
- Decide separately on local-path clone, native garbage collection that
  preserves jj's operation store and `refs/jj/keep/`, sideband progress,
  `report-status-v2`, push options, atomic push, `git://`, SHA-256
  interoperability and the interactive scm-record selector.

The current command and transport contracts are in the [gix manual](../gix.md).
