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

While a rebase is stopped, HEAD is detached and the record is in one of
these states:

| State | Files and index | What comes next |
| --- | --- | --- |
| `paused` | The commit of HEAD, clean | `rebase --continue` replays the next commit |
| `ready` | The conflict of the next commit | Resolve, `add`, `rebase --continue` |
| `publishing` | Your resolution | Gix is moving HEAD to the resolution commit |
| `incomplete` | Half written | `gix recover`, or `rebase --abort` |

The rebase moves between these states in six steps:

| Step | What it does | Files change |
| --- | --- | --- |
| advance | Moves the files and HEAD to the last replayed commit. Ends `paused`. | yes |
| show | Writes the conflict of the next commit into the files and the index. Ends `ready`. | yes |
| skip | Puts the files back to the commit of HEAD. Ends `paused`, one commit further. | yes |
| abort | Puts the files back to O and attaches HEAD to the branch. Ends the rebase. | yes |
| continue | Commits your resolution and moves HEAD to it. Ends `paused`, one commit further. | no |
| finish | Moves the branch to the commit of HEAD and attaches HEAD. Ends the rebase. | no |

A stop is an advance followed by a show. `rebase --continue` and `rebase
--skip` do their own step and then replay the remaining commits, which ends
in another stop or in the finish. A rebase that never stops does not use
these steps: it moves the branch with today's fast-forward code.

New code in `head_ref.rs`:

- `detach()` points HEAD at a commit, from a branch or from another commit.
- `move_branch()` moves a branch that HEAD is not on.

The finish is `move_branch()` and then today's `attach()`. If it is
interrupted between the two, `rebase --continue` does the second.

Reflog lines: `rebase (pick): <subject>` for an advance, `rebase (continue):
<subject>` for a resolution, `rebase (abort): returning to refs/heads/main`,
and Git's two `rebase (finish)` lines.

One reflog line differs from Git. When HEAD leaves the branch, its line has
no old commit id. The fork's reference transaction can record one only for a
HEAD that is already detached. Changing that would mean changing the fork.

### 4.4 State and recovery

The record keeps its present fields. For a rebase they mean:

| Field | Meaning for `kind=rebase` |
| --- | --- |
| `original-ref`, `original-id` | HEAD before the step in progress |
| `target-ref` | The branch being rebased |
| `target-commit` | The commit HEAD is detached at after the step |
| `result-tree` | The tree the step installs |
| `intended-commit` | The resolution commit while `--continue` publishes it |

Between steps, `original-id` and `target-commit` name the same commit.

New fields, written only for a rebase:

| Field | Meaning |
| --- | --- |
| `rebase-original` | O |
| `rebase-onto` | U |
| `rebase-base` | B |
| `rebase-next` | The commit to replay next, or `-` when none is left. While `ready` it is the commit whose conflict is shown. |
| `rebase-step` | While `incomplete`: `pause` or `abort`. Otherwise `-`. |

A rebase record has `version=2`. Records of the other kinds stay at
`version=1` and are byte for byte what they are today. An older gix that
finds a rebase record refuses to change the repository, which is the safe
answer.

The steps advance, show and skip are all recorded as `pause`, because their
recovery is the same. What `gix recover` does:

| `rebase-step` | Recovery |
| --- | --- |
| `pause` | Puts the files to `target-commit`, moves HEAD there if it has not moved yet, and leaves the rebase `paused`. |
| `abort` | Finishes the abort. |

Recovery always goes forward. So the record does not have to remember where
the rebase was before the step. `rebase --abort` also works on an
interrupted rebase, so there is always a way back to the branch.

A `publishing` record is repaired by `rebase --continue`, not by `gix
recover`. If HEAD has moved, the rebase is `paused` after the commit. If
not, it is `ready` again and the staged resolution is kept. This is the
scheme that a merge commit uses today.

Putting files to a commit uses `transition::prepare_restore()` and
`install_restore()`, which exist. They get one new argument: the tree to
restore.

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
validation tests. `detach()` and `move_branch()` in `head_ref.rs`. The
`status` and `branch` lines. The guard admits a rebase record for the three
rebase subcommands only. Until step 4, `gix recover` refuses a rebase
record, and nothing writes one.

**Step 4, stop and abort.** The steps advance and show, and `rebase
--abort`. Recovery of `pause` and `abort`, with an injected failure for
each.

**Step 5, continue and skip.** The resolution commit with the original
author and message. The dropped commit when nothing is staged. The skip. The
replay of the rest, and the finish. Repair of a `publishing` record.

**Step 6, the rest.** The pause for conflicts gix cannot show, which steps 4
and 5 already built, gets its test. `commit` refuses with its own message
since step 4; `restore` and `unstage` refuse by the rule for unfinished
operations. `docs/gix.md`: the Pulling section, a new Rebasing section, the
command table, "When something goes wrong" and "What gix does not do".

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
