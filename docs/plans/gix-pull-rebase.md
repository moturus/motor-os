# gix pull --rebase

Plan, 2026-11-15. Reviewed 2026-11-16: Q1, Q2 and Q3 were answered yes.
Steps 0 to 6 are committed. The design as built differs from section 4 in
small ways; the details file has the current description.
Follows `AGENTS.md`: 100–300-line patches with tests, one commit per step.
All changes stay in `src/bin/gix` and `docs`. Nothing changes in the gitoxide
fork, moto-rt, std or `src/sys`.

Evidence and per-step detail are in
[gix-pull-rebase-details.md](gix-pull-rebase-details.md), under the same
section numbers.

## 1. Problem

`gix pull` now exists as a local, uncommitted change. It fast-forwards or
merges. Gix has no rebase, so `pull.rebase = true` only fast-forwards and
stops when the branches have diverged.

The goal is that `gix pull --rebase` does what `git pull --rebase` does.

## 2. What Git does

Checked with Git 2.53. The transcripts are in the details file.

1. Git refuses to start unless the repository is clean.
2. It fetches.
3. It lists your commits that the upstream does not have, oldest first.
   Merge commits are left out, so a local merge is flattened.
4. It moves HEAD off the branch and onto the upstream commit. It replays
   each of your commits there. Author and message are kept. You become the
   committer.
5. A commit that adds nothing after the replay is dropped. A commit that was
   empty from the start is kept.
6. On a conflict Git stops. The files have conflict markers. HEAD stays at
   the last replayed commit. The branch itself has not moved.
7. `rebase --continue` commits your resolution and goes on. `rebase --skip`
   drops the commit and goes on. `rebase --abort` puts everything back.
8. At the end the branch moves once, to the new tip, and HEAD is back on it.
   Git prints `Successfully rebased and updated refs/heads/main.`
9. If the upstream was rewritten, Git uses the reflog of `origin/main` to
   find where your work really starts. Commits that the upstream dropped are
   not replayed.

## 3. Scope

In scope:

- `gix pull --rebase [REMOTE [BRANCH]]`, and the settings `pull.rebase =
  true` and `branch.NAME.rebase = true`.
- `gix rebase --continue`, `gix rebase --skip` and `gix rebase --abort`.
- `gix status` and `gix branch` say that a rebase is in progress.
- `gix recover` repairs a rebase that was interrupted in any step.
- Everything in section 2.

Out of scope: interactive rebase, `--rebase=merges`, autostash, an editor
for commit messages, hooks, and rebase state that Git can read (Q1).

## 4. Design

### 4.1 Replay in memory

Gix replays the commits in memory first. Each replay is one three-way tree
merge, which the fork already provides. New commits are written to the
object database only. No file, index entry or reference changes.

If every commit applies, gix then moves the files and the branch once. That
step is the fast-forward code that exists today.

Git rewrites the files once per commit. Gix rewrites them once per stop.
The result is the same. An interrupted run leaves less behind.

### 4.2 Stopping

When a commit conflicts, gix installs the state that section 2 describes:
markers in the files, a conflicted index, and HEAD detached at the last
replayed commit. This reuses the code that installs a conflicted merge.

A stopped rebase is in one of two states:

- **Stopped at a conflict.** Resolve, `gix add`, then `rebase --continue`.
- **Paused.** The repository is clean, and `rebase --continue` goes on. Gix
  pauses when it cannot show a conflict (see R4), and after `gix recover`.

### 4.3 The branch moves last

As in Git, the branch keeps pointing at your original commits until the
rebase is complete. If a rebase is abandoned or its state is damaged, no
commit is lost and the branch is still correct.

### 4.4 State and recovery

The rebase is recorded in the existing `.git/gix-operation` file as a new
kind, `rebase`, with five more fields and one more state, `paused`. Records
of the existing kinds do not change.

Every step that writes files is recorded first, as switch and merge do
today. `gix recover` then finishes the step and leaves the rebase paused.
A resolution you have staged is never discarded by `recover`.

## 5. Steps

Each step is one patch with its tests. About 1,500 to 2,000 lines in total.

| # | Patch | What works afterwards |
| --- | --- | --- |
| 0 | Commit the current `gix pull` work | Needs your go-ahead (Q3). |
| 1 | List the commits and replay them in memory | Nothing visible. Tested against host Git. |
| 2 | `pull --rebase` when every commit applies | Clean rebases work. On a conflict gix stops and has changed nothing. |
| 3 | The rebase record, moving a detached HEAD, `status` and `branch` output | Nothing visible. |
| 4 | Stop at a conflict, `rebase --abort`, recovery of both | You can see the conflict and back out. |
| 5 | `rebase --continue` and `rebase --skip`, recovery of both | The full flow of section 2. |
| 6 | Conflicts gix cannot show, rules for other commands, `docs/gix.md` | The feature is complete and documented. |
| 7 | Fork point from the reflog (item 9 of section 2) | A rewritten upstream is handled as in Git. |

Step 2 is a usable stopping point if the later steps need discussion.

## 6. Tests

- `tests/cli.rs`, on Linux and Motor: clean rebase, conflict then continue,
  skip, abort, a dropped commit, a flattened merge.
- `tests/support/https.rs`, on Linux: the same rebase is run by gix and by
  host Git in twin clones. Authors, messages and trees of the results must
  be equal.
- `tests/native_port.rs`: a failure is injected in each step, then `gix
  recover` must repair it.

## 7. Questions

Decided on 2026-11-16:

- **Q1. Rebase state that Git cannot read: yes.** Gix keeps the state in its
  own record. Git cannot continue a rebase that gix stopped, and gix cannot
  continue Git's. This matches today's rule: let gix finish before you use
  Git. The alternative was to write Git's `.git/rebase-merge` directory.
  That is 16 files with exact formats, and a mistake there can lose work.
- **Q2. Gate: yes.** Each patch is gated with the gix Cargo tests on Linux,
  debug and release, three times each. `full-test.sh` is being reworked in
  another session. The Motor run of `tests/cli.rs` follows once, when the
  gate is usable.
- **Q3. Commits: yes.** The `gix pull` work is committed first, then one
  commit per step.

Routine. Nobody objected in the review, so they stand:

- **R1.** `rebase --continue` keeps the original message. Git opens an
  editor.
- **R2.** `gix commit` refuses while a rebase is stopped. Use `rebase
  --continue`. Git allows both.
- **R3.** `restore` and `unstage` refuse while a rebase is stopped, as they
  do during a merge.
- **R4.** Gix can show only text conflicts, as in `merge`. For any other
  conflict the rebase pauses before that commit. You can skip the commit or
  abort.
- **R5.** `pull.rebase = merges`, `pull.rebase = interactive` and autostash
  are refused with a clear message.
- **R6.** HEAD's reflog gets one line per stop, not one per commit. The
  branch reflog gets Git's single `rebase (finish)` line.
- **R7.** `ORIG_HEAD` and `REBASE_HEAD` are not written.
- **R8.** One rebase reads at most 65,536 commits, the bound that push
  already has.

Can wait:

- **W1.** `gix rebase REV` as a command of its own. It would be small after
  step 5.
- **W2.** Step 7 can ship later than the rest.
- **W3.** A guest-side check of `pull` and `pull --rebase` in
  `cross-test.sh`.
