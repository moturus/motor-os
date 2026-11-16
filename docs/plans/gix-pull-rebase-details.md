# gix pull --rebase: details

Companion to [gix-pull-rebase.md](gix-pull-rebase.md). The section numbers
match. Read the plan first; this file holds the evidence and the design
detail.

## 2. What Git does

Git 2.53.0 on the Linux host, 2026-11-15. Each case was a clone that had
local commits while the remote moved on. Output is shortened.

A dirty repository is refused before the fetch:

```text
error: cannot pull with rebase: You have unstaged changes.
```

A conflict in the second of four local commits:

```text
$ git pull --rebase
error: could not apply 6016933... local-conflict
hint: Resolve all conflicts manually, mark them as resolved with
hint: "git add/rm <conflicted_files>", then run "git rebase --continue".
hint: You can instead skip this commit: run "git rebase --skip".
hint: To abort and get back to the state before "git rebase", run "git rebase --abort".
```

At that point HEAD is detached at the first replayed commit, and `main`
still points at the original tip. The state is in `.git/rebase-merge`, 16
files, plus `REBASE_HEAD` and `ORIG_HEAD`.

The branch list and the markers, from a second run with one local commit:

```text
$ git branch
* (no branch, rebasing main)
  main
$ cat f
l1
<<<<<<< HEAD
UP
=======
MINE
>>>>>>> 536b8ee (local-conflict)
l3
```

`--continue` before the conflict is resolved:

```text
You must edit all merge conflicts and then
mark them as resolved using git add
```

After `git add` and `git rebase --continue`:

```text
Successfully rebased and updated refs/heads/main.
$ git log --format='%an|%cn %s'
Me|Me local-empty            <- was empty from the start: kept
Me|Me local-clean-2
Me|Me local-conflict
Other|Me local-clean-1       <- author kept, committer is the current user
Me|Me up2
$ git reflog main
c135338 main@{0}: rebase (finish): refs/heads/main onto f298a7f0...
6a94168 main@{1}: commit: local-empty
```

Other cases, all observed:

- A local commit whose change the upstream already has is dropped (`warning:
  skipped previously applied commit bc31089`).
- A local merge commit is left out. The commits of both its sides are
  replayed in the order of `git rev-list --topo-order --reverse`.
- `git rebase --skip` drops the conflicting commit and finishes.
- `git rebase --abort` returns to `refs/heads/main` at the original tip, with
  a clean repository.
- A resolution that leaves nothing staged makes `--continue` drop the commit
  silently.
- After the upstream was rewritten with a forced push, only the commits that
  were really local were replayed. The commit that the upstream had dropped
  was not.

## 4. Design

### 4.1 Replay in memory

Names used below: **O** is the original tip of the branch. **U** is the
upstream commit. **B** is the base, the merge base of O and U until step 7
makes it the fork point. **T** is the last replayed commit.

The commits to replay are those reachable from O but not from U or B,
without merge commits. The order is that of `git rev-list --topo-order`,
reversed. The list depends only on O, U and B, so it is computed again
whenever it is needed and is never stored.

Gix finds these commits with a walk of its own in `replay.rs`. The fork has
two walks, and neither fits:

- Its topological walk reads the whole history when there is no
  commit-graph, and gix does not use commit-graphs.
- Its walk with hidden tips can return upstream commits when commits have
  equal times. A replayed history has many such commits.

The walk in `replay.rs` visits commits newest first, from O and from U and
B. It stops by Git's rule: no commit of the branch is waiting, and every
waiting commit is older than all commits of the branch found so far. It
reads at most 65,536 commits. Like Git without a commit-graph, it trusts
that no commit is older than its parents.

Replaying commit C onto T is `Repository::merge_trees()` with the tree of
C's parent as the ancestor, the tree of T as ours, and the tree of C as
theirs. A root commit uses the empty tree as the ancestor. The marker labels
are Git's: `HEAD` and `<short id> (<subject>)`.

- No conflict, and the result differs from the tree of T: write a new commit
  with that tree, parent T, C's author and message, and the current user as
  committer.
- No conflict, and the result equals the tree of T: drop C and say so,
  unless C was empty from the start.
- A text conflict that `merge` can already show: stop at C.
- Any other conflict: pause before C (R4).

A replayed commit names the current user as committer. So a rebase needs a
configured identity, as a merge commit does. The check uses
`commit::identities()` on a repository handle that the fetch has not
touched, as `pull` does today.

### 4.2 and 4.3 Stopping, and the branch moves last

The rebase has five moves. Each one goes from a state the user can see to
another such state.

| Move | From | To | Files change |
| --- | --- | --- | --- |
| stop | start, or paused | stopped at C, or paused before C; HEAD detached at T | yes |
| continue | stopped at C, resolved | paused after C; HEAD at the new commit | no |
| skip | stopped at C | paused after C; HEAD stays at T | yes |
| abort | stopped or paused | HEAD back on the branch at O | yes |
| finish | start, or paused | branch at the new tip, HEAD on it | yes |

`rebase --continue` and `rebase --skip` do their own move and then replay
the remaining commits, which ends in another stop or in the finish.

New code in `head_ref.rs`:

- Detach HEAD at a commit, or move a detached HEAD.
- Finish: one reference transaction that moves the branch from O to the new
  tip and attaches HEAD to it. A rebase that never stopped uses today's
  `advance_attached()` instead.

Abort uses today's `attach()`, because the branch never left O.

Reflog lines: `rebase (pick): <subject>` for a stop, `rebase (continue):
<subject>` for a resolution, `rebase (abort): returning to
refs/heads/main`, and Git's two `rebase (finish)` lines.

### 4.4 State and recovery

The record keeps its present fields. For a rebase they mean:

| Field | Meaning for `kind=rebase` |
| --- | --- |
| `original-ref`, `original-id` | HEAD before the move in progress |
| `target-ref` | The branch being rebased |
| `target-commit` | HEAD after the move in progress |
| `result-tree` | The tree the move installs |
| `intended-commit` | The resolution commit while `--continue` publishes it |

New fields, written only for a rebase:

| Field | Meaning |
| --- | --- |
| `rebase-original` | O |
| `rebase-onto` | U |
| `rebase-base` | B |
| `rebase-next` | The commit the rebase stopped at or paused before, or `-` |
| `rebase-move` | While incomplete: `stop`, `skip`, `abort` or `finish` |

A rebase record has `version=2`. Records of the other kinds stay at
`version=1` and are byte for byte what they are today. An older gix that
finds a rebase record refuses to change the repository, which is the safe
answer.

States: `incomplete` (a move was interrupted), `ready` (stopped at a
conflict), `publishing` (a resolution commit is being published), and one
new state, `paused`.

What `gix recover` does with an interrupted move:

| Move | HEAD has not moved yet | HEAD has moved |
| --- | --- | --- |
| stop | Put the files back. The rebase is paused, or not started if this was the first move. | Mark it stopped. |
| continue | Stopped at the conflict again. The staged resolution is kept. | Paused after the commit. |
| skip | Finish the skip. | (HEAD does not move.) |
| abort | Finish the abort. | Clean up. |
| finish | Put the files back. The rebase is paused. | Clean up. The rebase is done. |

Putting files back uses `transition::prepare_restore()` and
`install_restore()`, which exist. The `continue` row is the scheme that a
merge commit uses today.

What other commands do while a rebase is stopped or paused:

- `status`, `diff`, `log`, `branch`, `remote`: work. `status` prints the
  operation line it prints for a merge. `branch` prints Git's `(no branch,
  rebasing main)`.
- `add`: works while stopped at a conflict.
- `commit`, `restore`, `unstage`: refuse (R2, R3).
- `switch`, `checkout`, `merge`, `pull`, `fetch`, `branch create`, `tag
  create`: refuse, by the rule that already covers unfinished operations.
- `push`: unchanged. It does not take the mutation guard today.

## 5. Steps

**Step 1, replay.** A new module that takes O, U, B and a starting point and
returns either the new tip or the commit it stopped at. It writes objects
only. Tests in `native_port.rs` build small histories and check the trees,
authors and order. Covers a dropped commit, a kept empty commit and a
flattened merge.

**Step 2, clean rebase.** `pull --rebase` and the two settings. Up to date
and fast-forward stay as they are. For diverged branches: replay, then
install through `merge::install()` with a fast-forward preparation whose
target is the new tip. On a conflict the command fails and names the commit.
Nothing has changed, because step 1 only wrote objects. The `Reconcile`
enum in `pull.rs` loses its "gix cannot rebase" error here.

**Step 3, record and HEAD.** The version 2 record with encode, parse and
validation tests. The detach and finish publications in `head_ref.rs`. The
`status` and `branch` lines. The guard admits the new states for the three
rebase subcommands only.

**Step 4, stop and abort.** Install a conflict as the Divergent arm of
`merge::install()` does, then detach HEAD. `rebase --abort`. Recovery rows
`stop` and `abort`, with a new injected failure for each.

**Step 5, continue and skip.** The resolution commit with the original
author and message. The dropped commit when nothing is staged. The replay of
the rest. Recovery rows `continue`, `skip` and `finish`.

**Step 6, the rest.** The pause for conflicts gix cannot show. The refusals
of `commit`, `restore` and `unstage`. `docs/gix.md`: the Pulling section, a
new Rebasing section, the command table, "When something goes wrong" and
"What gix does not do".

**Step 7, fork point.** Collect the commits in the reflog of the tracking
branch. Take the merge bases of O against all of them with
`merge_bases_many()`. If there is exactly one and it is one of the reflog
commits, it becomes B. Otherwise B stays the merge base of O and U. This is
Git's rule. The fork point is read before the fetch, as Git does.

## 6. Tests

The twin-clone test in `tests/support/https.rs`:

1. Clone the fixture remote twice, once with gix over HTTPS and once with
   host Git from the bare repository.
2. Make the same local commits in both, with fixed author dates.
3. Advance the remote.
4. Run `gix pull --rebase` in one and `git pull --rebase` in the other.
5. Compare `git log --format='%an|%ae|%s|%T'` of the two results.

The conflict case compares the stopped state too: the conflicted file, byte
for byte with `core.abbrev` fixed, the commit HEAD is detached at, and the
unmoved branch. Then both sides resolve the same way and continue, and the
logs are compared again.

Every test that needs "no identity" passes empty `user.name` and
`user.email`, because a Motor machine may have `/user/cfg/gix.config`.

Gate, if Q2 is accepted: from `src/bin/gix`, in debug and in release, three
times each:

```sh
cargo test --locked --offline --features native-test-support --lib --test native-port --test cli
cargo test --locked --offline --test https-server
```

Plus `cargo fmt --check` and clippy for Linux and for the Motor target.

## 7. Questions

**Q1.** The files Git keeps in `.git/rebase-merge` for the run in section 2:
`author-script`, `done`, `drop_redundant_commits`, `end`, `git-rebase-todo`,
`git-rebase-todo.backup`, `head-name`, `interactive`, `message`, `msgnum`,
`no-reschedule-failed-exec`, `onto`, `orig-head`, `patch`, `rewritten-list`
and `stopped-sha`. Git reads them back with its own parsers, including a
shell-quoted author script. Gix already treats `rebase-merge` as foreign
state and refuses to change a repository that has it.

**R6, more exactly.** Git moves HEAD once per replayed commit, so its HEAD
reflog has one line per commit. Gix moves HEAD once per stop.

**R8, more exactly.** The limit of 65,536 covers every commit the rebase
reads: those it replays, and those it visits to find them.

**More differences, no decision needed.** Found while writing step 1.

- Git drops a commit that the upstream already has by comparing patches
  before the replay, and prints `skipped previously applied commit`. Gix
  finds it after the replay, when the result adds nothing. The history is
  the same, with one exception: if the upstream applied the change and later
  undid it, Git still drops the commit and gix applies it again.
- A replayed commit keeps its message bytes and its `encoding` header. Git
  converts the message to UTF-8.
- A replayed commit has no signature and no other extra header. Git drops
  them too.
- The merge of each replay reads `.gitattributes` from the index. Until the
  first stop that is the index of your branch, not of the upstream. Git
  reads the attributes of the commit it is replaying onto.

**Messages and reflogs, as Git 2.53 writes them.** Checked for step 2.

- Nothing to do: `Already up to date.` when the upstream is your commit,
  and `Current branch main is up to date.` when your branch is ahead.
- A fast-forward: `Updating OLD..NEW` and `Fast-forward`, reflog `pull
  --rebase: Fast-forward`.
- A rebase: `Successfully rebased and updated refs/heads/main.`, branch
  reflog `pull --rebase (finish): refs/heads/main onto <U>`. The words
  before the bracket are the command that ran, so a later `rebase
  --continue` writes `rebase (finish)`.
- A dropped commit: `dropping <id> <subject> -- patch contents already
  upstream`.
