# gix as the Git tool on Motor OS

Plan, v05, revised 2026-09-14 after reviewing v04 against the source.
Q1–Q7 remain resolved. This revision separates the operation lock from
the record, uses three recovery states, fixes index-cache preservation
and merge-state cleanup, and simplifies complete pack object selection.
Overlapping failure tests are consolidated. D8 and D9 retain the policies
accepted on 2026-09-12. Implementation was subsequently approved. M1's
native dependency port and host/Motor repository fixture are committed;
the port baseline `dc2c61b9e8acce852db121eaed5d87548dd755d8` was published
on `gix-moturus-cli` and verified on 2026-09-15. The subsequent pack-input
repair is recorded in section 7. Repository opening,
configuration sanitization, `log` and read-only `status` pass the host and
Motor component fixtures. Status rejects affected external or required
filters. The shared cancellation flag and Motor handler are implemented;
the host/Motor fixture checks cancellation through status. Live terminal
interruption and child cleanup will be checked with the HTTPS fixture.
Transports, resource limits and image integration remain M1 work.

## 1. Goal and decisions

Ship `/devtools/bin/gix` in the developer image: clone and fetch, inspect,
stage, commit, branch and tag, switch, merge, and publish. Start with
anonymous HTTPS clone/fetch; add SSH clone/fetch/push later. Use Git's
object, index, ref, reflog and merge-state formats. Completed repositories
can move between Motor and host Git; finish or repair an interrupted
operation before changing tools. There is no `git` executable or alias and
no promise of Git's command-line output.

The pinned CLI is plumbing: staging, commit authoring, worktree transitions
and push are new orchestration work. Its libraries provide formats and
algorithms, not these workflows. Switch/merge publication and send-pack
remain the largest items.

Section 8 records the scope approvals, transport correction and recovery
discussion. Section 4 incorporates the approved recovery scope.

- **D1 Milestones.** Three developer-image milestones, with component tests
  per functional step and one integrated gate per milestone (section 6).
- **D2 Source.** Start from `moturus/gitoxide` revision
  `4604ac322369a2e429a805cf6e5b7267712283f1` (gix 0.86.0), on a new
  `gix-moturus-cli` branch. Lorry's pin is unchanged; no upstream rebase.
- **D3 Application (Q1).** A small `src/bin/gix` binary over those libraries,
  with typed internal results and a thin clap interface. Do not depend on
  `gitoxide-core` or port the entire plumbing CLI. Only required library
  and platform fixes live in the external fork.
- **D4 Transport (Q2, discussed and corrected).** Anonymous HTTPS
  clone/fetch first (M1), through fixed `/system/bin/curl` and the existing
  Lorry HTTP-adapter pattern. SSH clone/fetch/push follows in M3 through
  fixed `/user/bin/ssh`. Use `std::process::Command` for both executables.
  HTTPS authentication/push and local-path clone are deferred.
- **D5 Working tree.** Force `core.symlinks=false`: link target text is an
  ordinary file, with symlink mode preserved in the index. Executable
  entries get Motor read, write and execute permission so they stay
  editable; other files get read and write. Status uses Git's
  `core.checkStat=minimal` rule with `core.trustctime=false`: gix's stat
  options with `check_stat`, `use_nsec` and `trust_ctime` off compare
  mtime seconds and size, plus the racy-git timestamp rule. Motor
  metadata already reaches gix-index's non-Unix path with mtime, creation
  time and size, and neither the ctime nor the inode fields written by
  host Git force a full rehash.
- **D6 Trust.** One explicit configuration policy for every command. No
  installed-Git discovery, helpers, hooks, external filters, diff/merge
  drivers, signing tools or executable overrides run from configuration or
  environment. Motor's ownership check returning `Ok(true)` is not trust.
- **D7 Panic and cancellation.** Explicit `panic = "abort"` in both
  application profiles overrides the [selected target's unwind default](../toolchain.md#rust-runtime-and-native-formatting).
  Errors and Ctrl+C use returns and RAII; forced death and aborting panics
  do not run destructors. gix's `interrupt` feature stays off because it
  pulls `signal-hook`; the application owns the interrupt flag and sets it
  from a thread that registers with `ctrl_c_register_handler()` and then
  blocks in `ctrl_c_wait()`. No automatic retry or crash-resume promise.
- **D8 (accepted) No object deletion.** No gc or repacking of repository
  storage; loose objects accumulate and are measured. Outgoing transfer
  packs are allowed. Maintenance is separate backlog work.
- **D9 (accepted) Merge policy.** Fast-forward when possible, otherwise
  create a merge commit. Text conflicts produce markers, index stages 1–3,
  `MERGE_HEAD` and `MERGE_MSG`; `add` then `commit` completes the merge.
  `merge --abort` explicitly discards merge work and restores the original
  HEAD tree and index, under section 4's preservation rules. Use gix's
  engine with recursive merge-base handling; no strategy selector, rerere
  or octopus. Switch and merge refuse to overwrite local modifications.
- **D10 Push (Q3).** SHA-1, one explicit source/destination ref, create or
  fast-forward unless an exact lease permits replacement. Require
  `report-status`. No default-selection emulation, multi-ref push, deletion
  or upstream bookkeeping initially; fetch refreshes remote-tracking refs.
- **D11 Distribution (Q1).** An ordinary developer application using the
  selected assembly linker, following the existing Lorry Makefile rule.
  No new toolchain producer, assembly schema or source-management framework.
  Rust, LLVM and Lorry pins do not move; no boot-time work is added.
- **D12 Clean tree.** Starting switch or merge requires index = HEAD and a
  clean tracked worktree. Preflight untracked and ignored files, including
  directory descendants, before replacement or deletion. Aborting a ready
  merge explicitly discards merge work and is exempt from the clean-tree
  condition. An interrupted transition is identified by its operation
  record (D13), never inferred from files matching old or target contents.
- **D13 Recovery (Q4, discussed and approved; mechanism revised through
  v05).** Explicit recovery on Motor for interrupted switch, merge and
  abort, using a separate operation record with three states and one
  idempotent restore routine shared by `merge --abort` and `recover`
  (section 4). Every mutator holds an exclusive advisory lock on one
  persistent lock file through completion; the record can be atomically
  replaced without losing that lock. Process death releases the advisory
  lock. Restore rebuilds the whole index from the original tree and
  cleanup removes owned merge state before the record. Retain D9's
  discard policy and D12's clean start. No per-file backup/replay journal,
  automatic retry, or guarantee of recovery from arbitrary corruption or
  power loss. Reflogs are still written; the read-only `reflog` command
  and `ORIG_HEAD` move to the backlog because no first-release command
  rewrites history and abort restores the recorded original HEAD.

## 2. First-release command surface (Q3, with Q4 recovery additions)

Global options: `-r REPOSITORY`, `-c key=value`, `--config-paths`, help and
deterministic version information. Paths are literal worktree-relative paths; support
`--` for names starting with a dash. No pathspec language initially.

| Command | Contract |
| --- | --- |
| `init [DIR]` | Ordinary worktree repository; `init.defaultBranch` or `main`. |
| `clone URL DIR` | Ordinary full clone into a new directory; record `origin`. HTTPS in M1, SSH added in M3. |
| `fetch [REMOTE]` | Configured remote, default `origin`; update tracking refs, never the worktree or checked-out branch. |
| `status`, `log` | Plain inspection; status reports staged/unstaged/untracked/conflicted paths and pending operations without repairing them. |
| `diff [--staged] [PATH…]` | Worktree versus index, or index versus HEAD; unified text diff, binary summary. |
| `add PATH…`, `add -A` | Stage additions, modifications and deletions; honor ignores and replace conflict stages with stage 0. |
| `restore PATH…` | Explicitly discard selected tracked worktree changes using the index; refuse conflicted paths. |
| `unstage PATH…` | Restore selected index entries from HEAD, or remove them for unborn HEAD; leave worktree files intact; refuse during a merge. |
| `commit -m MSG` | Commit the index; reject unresolved stages and ordinary empty commits. |
| `branch list`; `branch create NAME [REV]` | List branches or create one without overwriting an existing ref. |
| `tag list`; `tag create NAME [REV]` | List tags or create a lightweight tag without replacement. |
| `switch BRANCH` | Existing local branch, clean tree required. |
| `merge REV`, `merge --abort` | D9, supported conflicts and publication rules in section 4. |
| `recover` | Restore the recorded original state of an interrupted switch, merge or abort, or finish the cleanup of one whose ref update already published; report the action taken. |
| `push REMOTE SOURCE:DESTINATION` | One explicit ref update; details in section 5. |

`fetch` followed by `merge origin/BRANCH` replaces pull. Configuration files
or explicit `-c` settings supply identity and remotes; no config editor is
needed. Shell deletion followed by `add` stages removal, and branch creation
followed by switch replaces `switch -c`. No first-release command rewrites
history, so reset modes and reflog inspection are not needed; `branch
create NAME OID` retains any commit whose ID is known.

Deferred: bare init/clone, `rm --cached`, branch deletion, annotated tags,
detached-HEAD authoring, amend, general reset/restore options, `reflog`
inspection and `ORIG_HEAD`, blame and other plumbing commands, rebase,
stash, cherry-pick, submodule operations, LFS, signing and interactive
selection. Unsupported options fail explicitly.

## 3. Source baseline and API corrections

Reviewed on 2026-09-14 against the tree, with a Motor-target `cargo check`
of the pinned fork (below); no runtime test was performed.

| Source | Identity / integration |
| --- | --- |
| Motor OS | `290bb9e3889d95686a6be368adfd4d949947acb1` |
| Toolchain | `motor-1.99.0-beta-f47d5bb-dev.2-669057dcd9e729bc97418edb8b926b9e7526202a217dfc8dd9dd8dda561ca4e4`, from [rust-toolchain.toml](../../rust-toolchain.toml) |
| Gitoxide fork | [Pinned revision](https://github.com/moturus/gitoxide/tree/4604ac322369a2e429a805cf6e5b7267712283f1): gix 0.86.0, gitoxide 0.56.0 |
| Application integration | [Makefile](../../Makefile), [Lorry Cargo configuration](../../src/bin/lorry/.cargo/config.toml), [developer manifest](../../src/imager/motor-os-dev.yaml) |
| Transport references | [Lorry HTTP adapter](../../src/bin/lorry/src/git/http.rs) and [curl TLS tests](../../src/bin/curl/tests/https.rs) for M1; [host SSH server](../../src/tests/test-ssh-client-host.sh) for M3 |

Source paths below are relative to the pinned fork:

| Source | Finding that constrains implementation |
| --- | --- |
| `gitoxide-core/Cargo.toml` | Unconditional worktree/merge/credentials/interrupt features, `open` and `tempfile`; avoid this CLI dependency closure. |
| `gix-index/src/file/write.rs`, `gix-index/src/write.rs` | `File::write()` locks late and preserves stale tree-cache data. `Extensions::None` removes only optional extensions; entry flags still select v2/v3. |
| `gix-index/src/entry/stat.rs`, `gix-status/src/index_as_worktree/function.rs` | Retained stat caches must be checked against the old index timestamp before publishing a new index. The serializer does not invalidate racy entries for the caller. |
| `gix-worktree-state/src/checkout/entry.rs` | Checkout truncates files before writing; overwrite can recursively delete colliding directories. Check outcome errors/collisions and interruption even on `Ok`. |
| `gix/src/repository/merge.rs`, `gix/src/merge.rs` | `merge_commits()` internally builds configured filter/driver caches. Outcomes include resolved conflicts; `is_unresolved()` and `index_changed_after_applying_conflicts()` already exist. |
| `gix/src/status` | Use the lower-level tree/index and index/worktree comparisons with a no-op submodule callback. The high-level adapter can reopen the parent outside the sanitized snapshot. Do not publish index-cache updates during read-only status. |
| `gix/src/open/repository.rs`, `gix-odb/src/store_impls/dynamic/mod.rs` | The pinned replacement-ref configuration boolean is inverted. Use the direct `repo.objects.ignore_replacements = true` control before object access; reapply it to newly opened or converted handles. A local replacement-ref diagnostic confirmed this avoids the unrelated defect without a fork change. |
| `gix-ref/src/store/file/transaction/commit.rs` | Ref transactions can publish partially; ordinary symbolic HEAD edits skip switch's reflog. Reflogs require an identity. |
| `gix/src/repository/{identity,object}.rs` | Generic reflog identity fallback exists; `new_commit()` writes a commit object without updating refs. |
| `gix-transport/src/client/blocking_io/{ssh/program_kind,file,request}.rs` | SSH adds unsupported `SendEnv` except in V1. Child drop kills/reaps without returning successful completion. `into_parts()` exposes a raw pack writer. |
| `gix-pack/src/data/output` | Full-object `Entry::from_data()` and `FromEntriesIter` exist. `count::objects()` with `TreeAdditionsComparedToAncestor` clears its change collector before each parent and pushes after the loop while the shared seen-set persists, so an object new against the first parent of a merge commit is dropped; `iter_from_counts()` has one mode, which copies pack deltas, and can emit invalid sentinels for missing objects. Neither is used for push. |
| `gix-diff/src/tree/function.rs` | Tree diffs report changed entries, not the root tree object. An empty left-hand tree enumerates all descendants with the same collector. |

**Preexisting defect, Q7 (discussed and approved for repair):**
`gix-index/src/file/init.rs::File::at()`
subtracts the checksum length and slices before checking the input length.
A successfully mapped nonempty index shorter than its checksum can panic.
Include the narrow length-check fix and one truncated-index regression in
the same edit that replaces that reader's mmap during M1. This remains a
source diagnosis; no source fix or runtime reproducer was made.

### Motor-target check of the pinned fork (2026-09-14)

A scratch package depending on the fork's `gix` with the features this
plan needs was checked for `x86_64-unknown-motor` with the selected
toolchain: `sha1`, `index`, `worktree-mutation`, `status`, `merge`,
`revision`, `blob-diff`, `dirwalk`, `excludes`, `attributes` and
`blocking-network-client`, plus `gix-features/io-pipe` and
`gix-transport/http-client` as in Lorry.

| Step | Result |
| --- | --- |
| Fresh `Cargo.lock` | Fails to resolve: `gix-protocol` needs `bisync ^0.3.0` and both 0.3.x releases are yanked on crates.io. Lorry builds only because its lockfile pins the cached 0.3.0. |
| Lorry's lockfile seeded | Two crates fail: `filetime` (Unix `libc`) and `io-close`. |
| Both shimmed through `[patch.crates-io]` | One error: `executable_bit_change` is undefined for non-Unix, non-Windows targets in `gix-worktree-state/src/checkout/entry.rs`. |
| One `#[cfg(not(unix))]` line added | Zero errors, four unused-variable warnings. |

The check identifies the compile blockers; it proves neither linking nor
runtime behavior, which M1 step 2 must show on Motor. The known port
work: seed the application lockfile from Lorry's (bumping `bisync` on the
fork branch is the fallback); a Motor `filetime` shim wired like
`gix-motor-tempfile` and an `io-close` shim; the one cfg line;
owned-buffer reads where `memmap2` compiles as a stub that fails at
runtime, namely `gix-index` `File::at()`, `gix-commitgraph` file loading
and `gix-ref` packed-refs above the mmap threshold (`gix-pack` and
`gix-odb` are already done in the fork); Motor executable-bit set and
probe through `moto_rt::fs`; and Motor `gix-fs` capabilities. Validate
lengths before checksumming/decoding. Motor std already exposes rename,
metadata, permissions and advisory file locks; sys-io's lock manager
releases a process's locks when its connection drops, so a lock never
outlives its owner. Symlinks, hard links and file-time setting remain
unsupported. Native Ctrl+C APIs already exist. No core OS changes are
assumed.

## 4. Local correctness contract

### Repository, configuration and paths

Support one ordinary worktree with a full SHA-1 object database, loose or
packed objects, and the files ref backend. Reject linked worktrees, sparse
checkout/index, shallow/promisor repositories, unsupported mandatory index
extensions and intent-to-add/skip-worktree/assume-unchanged entries before
mutation. Refuse
foreign merge/rebase/cherry-pick state. Disable replacement-object/graft
interpretation. Reading a packed repository does not require repacking it.

The D6 trust policy is this one list, enforced at repository open and
again before each mutation; sections 5 and 6 refer to it:

- Disable installed-Git discovery before opening a repository.
- One precedence for explicit user configuration, supported environment,
  repository data and `-c` overrides, with `-c` final for supported
  settings; document the actual gix precedence and report the
  configuration paths. The initial load order is XDG configuration,
  `~/.gitconfig` with includes in place, repository-local configuration,
  repeated `-c` values, then fixed filesystem policy. Initially only `HOME`
  and `XDG_CONFIG_HOME` may select environment-backed configuration paths;
  mapped environment overrides and environment configuration are denied.
  Reject unselected index/worktree path overrides. Configuration cannot
  override filesystem limitations, process policy, lock behavior or limits.
- Strip executable settings from the in-memory configuration consumed by
  library helpers: `core.sshCommand`, `GIT_SSH_COMMAND`, `GIT_SSH`,
  askpass, credential helpers, external diff/textconv, filter and
  merge-driver commands. `merge_commits()` builds its own filter and
  driver caches from that configuration, so sanitize before calling it.
- Inspect attributes before mutation: refuse affected external filters and
  unknown named/default merge drivers instead of silently applying a
  different transformation; retain required-filter information for that
  preflight. Permit built-in text, binary and union drivers under the
  conflict policy below.

All paths must remain within the selected worktree and outside repository
metadata. Validate target tree names and file/directory collisions before
any writes. Include ignored files and untracked descendants when deciding
whether a directory can be removed; never delegate their deletion to
checkout's recursive overwrite behavior. Preserve gitlink entries and never
descend into or delete a submodule worktree. Add must not stage deletion
merely because a gitlink directory is absent; initially refuse transitions
that require changing a gitlink path.

### Index, objects and identities

Use one persistent, empty `.git/gix-operation-lock` file, created if absent,
opened without truncation and never replaced or removed. Every mutator, including
`recover`, first takes its exclusive advisory lock with `File::try_lock`,
then `index.lock`, then any ref locks, failing immediately on contention.
Hold the advisory lock through completion and cleanup, including after
index publication. Read the operation record under that lock; if present,
only actions permitted by its state may proceed. Read-only inspection
does not create the lock file. New repositories use exclusive creation.

The lock file is separate from the atomically replaced record: Motor's
[lock manager](../../src/sys/sys-io/src/runtime/fs/lock_manager.rs) keys
locks by entry ID, and [rename](../../src/sys/lib/motor-fs/src/txn.rs)
replaces the destination entry. A lock on the old record would not protect
its replacement. The persistent file's existence never means busy; process
death releases the advisory lock without deleting the file. Keep Git's
normal index/ref locks and expected-old-value ref checks. Their individual
file publication does not provide a repository transaction, and forced
death can leave those lockfiles behind; never remove another writer's
Git lockfile. [Git lockfile contract](https://git-scm.com/docs/api-lockfile)

Acquire `index.lock` before reading an index that will be changed; mutate
in memory, sort entries, write through that lock with `Extensions::None`
and a checksum, then publish. Keep ordinary host v2/v3/v4 index reading
where supported; newly written ordinary entries produce v2. Do not invent
a cache extension or custom index format.

Before every index publication, invalidate any retained stat cache that
is potentially racy against the old index timestamp, using D5's stat
options. A same-size edit within the cached mtime second must still be
detected after an unrelated path is staged and the index timestamp
advances. The serializer does not do this automatically. Recovery simply
rebuilds all entries with empty stat caches; accept a subsequent rehash
instead of special cache-preservation logic. [Racy Git](https://git-scm.com/docs/racy-git)

Stage regular files through the built-in `convert_to_git()` pipeline and
`write_blob()`. Existing symlink entries keep their mode and raw target
text, without regular-file filters. Preserve executable modes. Process
already-tracked ignored files; diagnose explicitly selected ignored or
unmatched paths. Resolve conflicts by replacing stages 1–3 with stage 0,
or removing the entries when the selected file was deleted.

Build commit trees from `repo.empty_tree().edit()` and all stage-0 entries,
so deletions cannot survive from an old tree. Reject unresolved stages.
Use `new_commit()` to obtain the exact object ID before ref publication,
then a ref transaction with reflogs; do not create the commit twice.
Ordinary commits have HEAD as parent, or no parent for an unborn branch.

Validate real author and committer identity before any authoring mutation,
including non-fast-forward merge. As discussed and approved in Q5, use
gix's existing generic committer fallback for non-authoring reflog writes
(clone/fetch/branch/switch/recovery), only when configured identity is missing.
Never use that fallback for an authored commit. Supply switch's old/new
HEAD reflog entry explicitly.
Ref/reflog publication can fail partially: report the actual state, rather
than claiming every error left refs unchanged.

### Worktree transitions and recovery (Q4, discussed and approved)

Switch, merge, abort and recovery share one tree/index installation
helper and one restore routine. An interrupted operation is identified by
its operation record: status reports it read-only, unrelated mutation
refuses until it is repaired, and repair never requires moving the
repository to a host.

For a new switch or merge, resolve names and revisions to fixed IDs under
`index.lock`. Preflight cleanliness, path collisions, attributes,
identities and supported conflicts before writing anything; preflight
changes no worktree, index, ref or merge state, though objects written
during computation may remain. Use the target tree/index for checkout
attribute lookup, not a partly updated worktree. Compute changed/new/deleted
paths once and check out only that subset, preserving unchanged files.
Check errors, collisions and the interrupt flag before publishing the
index or changing a ref. Do not treat partially written files, target-only
untracked files, or an index ahead of HEAD as clean.

The operation record is one small file under `.git`, separate from the
persistent lock file. Create it exclusively before the first worktree
write and rewrite it atomically on state changes while holding the
operation lock. Fields: state (incomplete, ready or publishing), kind
(switch, fast-forward or merge), original HEAD attachment and ID, target
ref (the branch to attach for switch; the branch being advanced for
fast-forward and merge), target commit, result tree (the target commit's
tree for switch and fast-forward, the merge result for merge), and the intended commit ID
while publishing. There are no per-file backups or replay steps. Ordinary
commits need no record; a commit that completes a ready merge moves the
existing one through publishing.

| State | Meaning and permitted actions |
| --- | --- |
| No record | Idle. All commands; nothing to recover. |
| Incomplete | Installation, abort or recovery may have left the worktree partial and the index old or new. Status diagnoses; `recover` acts; every other mutation refuses. `MERGE_HEAD` carries no meaning here. |
| Ready | A merge is installed: result worktree and index, `MERGE_HEAD` and `MERGE_MSG`. Allow add, inspection, commit or abort. `recover` refuses; HEAD anywhere but the recorded original makes the record invalid, which `recover` and `commit` report. |
| Publishing | A merge commit with the recorded intended ID is being published. Status diagnoses; only `recover` acts. |

Publication order for switch and fast-forward: record (incomplete),
worktree subset, index, ref (HEAD's attachment for switch, the branch for
fast-forward), record removal. For a merge: record (incomplete), worktree
subset, index with stages, `MERGE_HEAD` and `MERGE_MSG`, record (ready).
Committing a ready merge: record (publishing, intended ID), ref
transaction, removal of `MERGE_HEAD` and `MERGE_MSG`, record removal.
Abort: record (incomplete), restore, removal of merge state, record removal.
Published ref updates are preserved; a cleanup failure leaves the record
visible. The same incomplete state covers installation, abort and recovery
because all three use the same recovery action.

Use `merge_base` for ancestor/fast-forward cases and `merge_commits()` for
divergence, including recursive merge bases; reject unrelated histories.
Inspect unresolved conflicts, not every entry in `Outcome::conflicts`.
Initially support same-path regular-text conflicts only; other unresolved
kinds fail before worktree changes. Build an index from the result tree,
then apply stages with `index_changed_after_applying_conflicts()`. Conflict
marker blobs must not remain as stage-0 entries. Clean merges use the same
ready-state checks and commit machinery.

Committing a ready merge requires HEAD to equal the recorded original and
`MERGE_HEAD` the recorded target; the parents are those two commits, and an
unchanged resolved tree is valid only here. Never infer readiness from
`MERGE_HEAD` alone, and never clear it because it is an ancestor of HEAD.

Restore is one idempotent routine. Its restore set is every path in the
difference between the original tree and the result tree, plus every path
whose current index entry differs from the original tree. For those
paths it reinstalls the original tree's content or deletes what the
original lacks; it then rebuilds the whole index from the original tree
with empty stat caches and finally reattaches the original HEAD. It
explicitly discards merge work and staged changes, preserves unrelated
untracked and ignored files and unstaged edits to tracked paths outside
the restore set, refuses obstructing directory
contents, and never moves the destination branch. Repeating it over a
half-restored tree is safe, so no repair checkpoint is recorded.
`merge --abort` moves the record to incomplete, runs restore, then cleanup.
An interrupted abort is therefore an ordinary incomplete record.

Abort and recovery share idempotent cleanup with merge commit: remove
`MERGE_HEAD` and `MERGE_MSG` owned by a merge record, then remove the
operation record last. Missing merge files are already clean; any other
cleanup error leaves the record for explicit recovery. This also covers
interruption before a merge becomes ready. The persistent lock file stays.
`recover` takes the operation lock and Git's locks in the same order as
other mutators and acts from the record alone, with no target revision or
force mode:

- Incomplete, with the ref already showing the result (HEAD
  attached to the target ref for switch, the target ref at the target
  commit for fast-forward): verify the index has no conflict stages and
  matches the result tree for the restore set, remove the record, and
  preserve the published update and its reflog entries; never replay it.
- Incomplete, with HEAD still at the recorded original: run restore, then
  cleanup, removing owned merge files before the record.
- Publishing, with the target ref at the intended commit: run cleanup,
  preserving reflog entries.
- Publishing, with the target ref still at the original: the commit did
  not publish; move the record back to ready with the intended ID
  cleared, keeping staged resolutions, so the user can commit or abort.
- Anything else, invalid record contents, or missing/corrupt recorded
  objects: refuse with a precise diagnosis and leave the record.

An idle repository has nothing to recover; nothing repairs automatically
on open. A failed restore or cleanup leaves the record for an explicit
later invocation after its cause is addressed. Check exact IDs and ref names,
not ancestry or a newly resolved branch name. Recovery uses the same
trust, path and resource policies as normal commands. Ordinary index-only
edits retain their existing lockfile publication.

Return-based cancellation stops work, kills/reaps children, releases owned
locks and exits 130, while reporting incomplete state. Forced termination
can leave Git lockfiles behind. Document manual lock removal only after
verifying no writer remains; `recover` never deletes another writer's
Git lockfile. Explain the incomplete operation and the explicit on-Motor
recovery action in the failure diagnostic. No automatic retry, universal
IO-error rollback or power-loss durability is promised. Complete or
repair gix-owned operations before host authoring.

The operation lock and Git's locks coordinate gix writers, not arbitrary
editors or host Git. Users must not concurrently edit a transitioning
worktree. Recheck observed state before destructive writes and report
detected changes; do not promise snapshot isolation against arbitrary
external writes.

## 5. HTTPS acquisition first; SSH and single-ref push later

### M1: anonymous HTTPS clone/fetch

Adapt the [Lorry HTTP adapter](../../src/bin/lorry/src/git/http.rs) and
[curl invocation](../../src/bin/lorry/src/curl.rs) patterns to gix's blocking
HTTP interface. Use fixed `/system/bin/curl`, explicit response metadata,
CA/hostname verification, bounded same-origin redirects and no downgrade.
Use system trust by default; an explicit `-c http.sslCAInfo=PATH` may select
a CA bundle, including the fixture's CA. Repository configuration must
not replace trust roots or disable verification.
Validate HTTP status and Git content type before parsing a pack response.
Bound request/response buffers and temporary files; propagate worker and
child errors and make cancellation unblock IO and reap the child.

Support anonymous smart HTTPS only: no embedded credentials, prompts,
tokens or plain HTTP fallback, and the D6 list in section 4 covers
helpers, overrides and ambient `http.*` settings. Validate URLs after
rewriting and on each redirect. Reuse the existing transport pattern
without changing curl or refactoring Lorry into a shared framework, and
copy only what this subset needs: the `Http` adapter in `http.rs`, the
curl argument construction, write-out trailer parsing and bounded
stdout/stderr capture from `curl.rs`, and HTTPS URL parsing with a
same-origin check from `redirect.rs`. Leave behind Lorry's automatic
timeout retries (`retry_timeouts()`), which contradict the no-retry rule,
its cross-site trust store and terminal prompt (`TrustPolicy`), which
same-origin redirects never need, and its crates.io download and stderr
spill-file paths. Record the resulting line count in the step 3 patch
report; a shared Lorry library is not needed for this subset.

### M3: SSH clone/fetch/push

Use one SSH adapter for upload-pack and receive-pack. Fix the executable
and invocation kind, disallow a local shell, and use Motor's supported
arguments: identity/port as needed, `StrictHostKeyChecking=yes`,
`BatchMode=yes`, no PTY and no `SendEnv`. Motor's ssh, built from
`src/bin/russhd`, accepts `StrictHostKeyChecking=yes` or `accept-new`,
`BatchMode=yes`, `-i` and `-p`, and rejects unknown `-o` keys, which is
why the transport's V1 mode is required: any other version adds
`SendEnv`. Use existing SSH key/known-host setup; unknown hosts fail
explicitly.
Validate host/user arguments and quote the remote repository path with the
existing gix quoting helper. Acquisition accepts HTTPS and, from M3, SSH;
push initially accepts SSH only. Reject local/file, plain HTTP and other
unsupported schemes after URL rewriting too; never fall back to a local
`git-upload-pack`.

Keep binary stdin/stdout separate from a continuously drained, bounded
stderr stream. Explicitly close request input at completion, inspect child
exit status and reap it. An interrupt flag alone cannot wake a blocked pipe:
cancellation must terminate the child and unblock workers. Use one bounded
SSH lifecycle for acquisition and publication; no automatic retry.

Command: `gix [-r PATH] push [--dry-run]
[--force-with-lease=DESTINATION:OID] REMOTE SOURCE:DESTINATION`.
SOURCE is a local ref, HEAD or full object ID. DESTINATION must be fully
qualified under `refs/heads/` or `refs/tags/`. REMOTE is a configured name
or SSH URL; honor its push-direction URL, rejecting multiple destinations.
No implicit branch selection, wildcard, leading `+`, empty source,
`--force`, delete or upstream configuration.

Branches need commit objects. Allow creation and provable fast-forward;
replacing an existing tag or rewriting a branch needs a lease matching the
advertised old ID (empty OID means expected absence). If the old commit is
unavailable locally, require fetch or a lease. Check a supplied lease even
for a no-op. No-op and dry-run send no update or pack and change no local
state; dry-run still performs discovery and policy validation.

The [Git pack protocol](https://git-scm.com/docs/pack-protocol) requires an
old/new/ref command, capabilities on its first packet, a flush, and raw PACK
bytes for create/update, even when the object count is zero. Require
`report-status` and parse `unpack`, the one expected ref result and final
flush. A missing, duplicate, unexpected or malformed result is not success;
SSH exit status alone is insufficient.

Use `handshake(..., Service::ReceivePack, ...)`, packet-line helpers and
`RequestWriter::into_parts()`. Handle empty advertisements and `.have`
pseudo-refs without treating them as writable refs. Unsupported advertised
capabilities are simply not requested; sideband, atomic, report-status-v2
and push-options are deferred.

Select the outgoing objects explicitly; do not use `count::objects()`
(section 3). Peel tag chains, include each tag object, then handle the
final target by type:

- Commit: walk all parents, with known remote commit ancestry hidden
  through `with_hidden()`, not the timestamp-sensitive `with_boundary()`.
  Include every selected commit object and its root tree explicitly.
  For each selected commit, use `gix_diff::tree` to compare its first
  parent's tree to its own tree, using an empty left-hand tree for a
  parentless commit. Collect added/modified descendant trees and blobs
  into one application-owned seen-set. Comparing only the first parent
  suffices because that parent's contents are supplied by either the
  remote or the all-parent commit walk; merge-resolution blobs are still
  selected. Do not restrict the commit walk itself to first parents.
- Tree: include the root tree and collect all descendant trees/blobs
  with the same diff collector against an empty tree.
- Blob: include that object.

Deduplicate all emitted objects and skip gitlink targets. Tree-diff
callbacks do not emit the compared root tree. Unknown remote objects
cannot justify omission. Safe redundant objects are allowed; a
representative incremental push must avoid resending the entire history.
Generate a serial, non-thin pack of full objects with
`Entry::from_data()` and `FromEntriesIter`, with exact counts and errors
for missing or corrupt objects. No delta reuse, `ofs-delta` negotiation,
parallel workers or custom pack encoder initially. Finish the bounded
temporary pack before sending a ref update; selection/encoding failures
then stay local. Measure the bandwidth cost using the approach approved in
Q6 before claiming support for large repositories. Account for ID sets,
decoded objects and any whole-pack buffers used by the owned-buffer
backend.

Report local rejection, confirmed remote rejection, confirmed acceptance
or unknown outcome distinctly. A dropped/malformed report after sending
the update is unknown and is never retried. A valid acceptance followed by
a child-completion error must retain the fact that the remote accepted.
Push does not change tracking refs/configuration; a later fetch does.
This removes partial multi-ref results and accepted-but-bookkeeping-failed
states from the initial client.

## 6. Implementation steps, packaging and tests

Implement 100–300-line patches where practical, with meaningful tests for
each behavior. Gate completed functional steps, rather than requiring a
full runtime matrix for preparatory edits. Q1–Q7 are resolved and
implementation is approved.

### M1 — small application, local inspection and HTTPS acquisition

1. Create the external authoring checkout; record its starting revision.
   Add the application and only required library features. Seed the
   application lockfile from Lorry's, because a fresh resolution fails on
   the yanked releases (section 3); bumping `bisync` on the fork branch is
   the fallback.
   Inventory target dependencies separately from host build tools;
   provision dependencies once, then check/build with `--locked --offline`.
   The first patch repeats section 3's Motor check and records it.
2. Port per section 3: the `filetime` and `io-close` shims, the checkout
   cfg line, the three owned-buffer reads with the Q7 length check and its
   truncated-index regression, Motor executable-bit set/probe and `gix-fs`
   capabilities. Plain CLI IO with `std::io::IsTerminal`; no TUI, pager or
   progress thread. Cancellation per D7. Link and run the actual Motor
   binary with the selected linker. Add a `strlen` export only if linking
   requires it; the native bootstrap and repository fixture linked without one.
3. Implement the common repository policy and HTTPS adapter. Add status/log,
   clone into an exclusively created directory, and fetch. Mark an incomplete
   clone so later authoring refuses it; report its owned partial destination
   without removing preexisting files or claiming checkout succeeded.
4. Add the host HTTPS smart-Git fixture: a rustls server built from curl's
   TLS test code and test CA, driving `git upload-pack --stateless-rpc` for
   a fixed repository, bound to loopback in host mode and to `192.168.4.1`
   in guest mode with a server certificate naming that address, since the
   existing curl certificates cover only loopback names. Nothing existing
   serves this: Lorry's Git tests use a fake curl on the host, and curl's
   tests serve canned responses.
5. Add a normal Makefile application target with the selected linker and
   keyed object directory, and only `/devtools/bin/gix` in the developer
   manifest's `input_files`. Use existing licence/static-file conventions.
   No new assembly component or `test-toolchain-gix.sh`. Reuse applicable
   ELF validation for the linked and stripped binary.

Gate: installed binary inspects loose/packed fixtures and performs HTTPS
clone/second fetch against the step-4 fixture with its test CA; host Git
validates copied repositories.

### M2 — local authoring and working-tree operations

1. Add init, staging, diff and write-tree/commit using the shared index and
   ref helpers; add lightweight branch/tag creation.
2. Add the narrow restore/unstage operations, then switch and merge through
   one transition helper and the approved Q4 recovery model.
3. Add text-conflict resolution and abort through the shared restore
   routine, with explicit HEAD reflogs; retain the accepted discard policy.
4. Add `recover` over the same restore routine and transition-failure
   fixtures. Document explicit repair, failure during repair, and manual
   removal of a Git lockfile left by a dead process after verifying no
   writer remains; never remove the persistent operation-lock file.

Gate: init/add/diff/commit/branch/switch/merge/conflict/resolve/abort and
discard/unstage/recover workflows pass in the VM. Check blob/tree IDs,
parents, index stages, HEAD attachment, reflogs and preserved local files
at selected boundaries; complete a Motor → host Git → Motor round-trip
between finished or explicitly recovered operations.

### M3 — SSH acquisition and single-ref publication

Add the SSH adapter and clone/fetch support, then the strict pack producer,
single-ref protocol and small push command from section 5. Keep object
selection/encoding testable without SSH.

Gate: SSH clone/fetch, initial and incremental push to host receive-pack,
rejection and leased replacement, and publication of a tag. Host Git checks
the received content and pack validity; exercise the shared guest SSH
lifecycle once.

### Test budget and integration

Use `src/tests/test-gix.sh` as the component entry point, with a host mode
and a guest mode that can use the already running test VM. Run both modes
from `full-test.sh` under `FULL_TEST_VERIFY_DEV_SOURCES=1`, the host mode
where the rust-analyzer size checks run and the guest mode after SSH is
available, so the main-image gate never compiles the gix closure while
`full-test-dev.sh` still reaches every gix test. No separate test
framework or implicit network fetch.

| Keep | Bound the cost |
| --- | --- |
| Host command/index/ref/protocol tests | Table-driven cases, missing-identity preflight and a broken-pipe check. Extend the index fixture with controlled timestamps: a same-size, same-second edit must remain visible after unrelated staging and after recovery. No exhaustive Git CLI/output compatibility suite. |
| Interruption and recovery | Shared-helper failpoints for partial writes, new/deleted paths, index-before-ref and merge-installed-before-ready; verify owned merge files are removed before the record. Use one published-merge cleanup-failure case. In one lifecycle, stage a path outside the merge, interrupt abort, interrupt recovery, then finish recovery. In one live-operation fixture, `add` and `recover` must refuse on the held operation lock after record replacement and index publication. Keep one death case with a stale Git lockfile and one unexpected-ref case. No command/phase cross-product or second fault framework. |
| Motor filesystem behavior | One lifecycle fixture for same-size edits, executable permissions, symlink text, UTF-8 names and unchanged gitlinks; no every-mode/every-command product. |
| User-data preservation | Dirty tree, ignored/untracked directory obstruction, rejected non-text conflict, stale tree cache and a targeted write/permission failure. |
| HTTPS adapter correctness (M1) | The step-4 clone/second-fetch fixture plus focused adapter rejection cases for invalid response metadata/status, redirects/downgrades and TLS verification policy; reuse curl's TLS tests for curl itself. |
| SSH/protocol correctness | Host malformed/truncated reports, unpack/ref rejection and leases/no-op/empty pack. The incremental merge fixture checks commit/root-tree completeness and a resolution blob absent from both parents, using `index-pack --strict` in a receiver containing only the advertised baseline. Include tree/blob tag targets in the host selection table. Guest happy path, rejection and bounded stderr/cancellation; no duplicate transport matrix. |
| Trust policy | Sentinels at actual application entry points for filters, merge drivers and command overrides. |
| Git interoperability | Exact content/stage checks at selected checkpoints; copy back and full fsck at scenario completion or a relevant failure checkpoint, not after every command. |
| Resource limits (Q6, approach approved) | Boundary tests on the enforcing helpers and one representative larger packed history; no benchmark matrix per command. |

Fixtures use fixed identities/times and isolated configuration/temp paths.
Host-only servers bind loopback; guest-to-host fixtures use the existing
isolated VM network (including `192.168.4.1`). Regular tests never use the
public Internet. Reuse SSH/curl tests for those programs themselves.

Per patch, run relevant focused tests/checks, repository-selected
`cargo fmt`, clippy for affected code, shell syntax checks when applicable,
and `git diff --check`. Per functional step, run the affected guest fixture.
Per shippable milestone, run `full-test-dev.sh --release`; it already runs
the repository suite on the developer image, developer-source tests and
Lorry's suite. Do not immediately rerun the included gix tests separately.
Additional main-image gates are needed only when the affected integration
requires them. A `src/sys` change still requires prior discussion and three
debug plus three release `full-test.sh` runs before committing.

Developer-image validation stays release-only; touching Lorry does not
authorize a debug developer-image run. Diagnose preexisting failures and
preserve their evidence per `AGENTS.md`; no retries, increased timeouts,
ignored failures or weaker assertions.

Record the fork revision, lockfile and binary digests, feature/build
recipe, gate logs, stripped size, and relevant memory/temp-disk/transfer
measurements once per milestone. Limits must name their enforcement point
and bound decoded allocations as well as transport bytes; a check after
allocation does not enforce a memory limit. Avoid an extra benchmark or
build-identity subsystem.

## 7. External scope, completion and backlog

Application code, image/build integration, tests and documentation belong in
this repository. Library/platform edits belong in the separate authoring
checkout `/home/posk/motor-dev/gitoxide-motor-cli`, starting at D2. Name every
external crate/path changed in each patch report; do not author in Cargo
caches or managed toolchain checkouts. The new application is package
`motor-gix`, binary `gix`.

Use temporary local dependency overrides while reviewing uncommitted fork
changes, and record their source digest. Do not claim the old revision
identifies patched sources. A distributable dependency pin requires a
reviewed fork commit; committing/publishing it is a separately authorized
step. No Lorry, curl, SSH, kernel, std, moto-rt, mlibc or toolchain-source
edits are assumed. If necessary, diagnose and discuss them first.

Pack-input follow-up, discussed and approved on 2026-09-15: repaired in
Gitoxide `b4e6aeaa82be4183af466b7a99484c38322dd260`. In the external
checkout's `gix-pack/src/data/input/bytes_to_entries.rs`, the streaming
constructor now returns the existing unsupported-version error for version
3 instead of asserting. It handles an empty pack's mandatory trailer during
construction through the existing verifier, preserving each parsing mode.
The input tests and native pack-writer fixture cover rejection, valid empty
packs and temporary-file cleanup; focused host and Motor checks pass.
Object-count allocation bounds remain part of Q6; the decoded-object limit
does not bound pack metadata storage.

Implementation follow-up, discussed and approved on 2026-09-15: extend Motor
FS's own-role permission rule to allow `Rx` → `Rwx`, alongside `Rw` → `Rx`.
Retain higher-role ceilings and lower-role narrowing. The Gitoxide checkout
and executable probe can then use `Rw` → `Rx` → `Rwx` without a new creation
adapter. An interruption between those calls can leave an `Rx` output;
M2 recovery must restore write access or replace that owned output before
opening it for writing. Validate the OS change with three debug and three release
`full-test.sh` runs, plus `full-test-dev.sh --release`.

A milestone is complete when the installed application passes its gates;
cross-compilation alone is insufficient. Rollback restores the previous
application/dependency pin and developer image, without rewriting user
repositories or altering toolchain assembly selection.

Backlog items are separately reviewed: HTTPS authentication/push, local-path
clone, gc/repack, more conflict kinds, carrying changes across transitions,
deferred authoring/inspection commands including `reflog` and `ORIG_HEAD`,
push defaults/multiple refs/deletion, tracking configuration, delta
reuse/parallel packing, a fork fix with a regression test for the
`gix-pack` merge-commit counting defect (section 3), other protocols and
SHA-256. Native builds through Lorry are optional later work.

## 8. Discussion record

All seven questions were discussed and resolved on 2026-09-14, including
the subsequent approval of the proposed recovery scope. These outcomes
replace the earlier SSH-first and host-assisted-repair recommendations.

| Question | Discussed outcome |
| --- | --- |
| Q1 — Application/distribution | Approved: small `src/bin/gix` application over the pinned libraries, ordinary developer-image build integration. |
| Q2 — Transport | Corrected: **HTTPS first, SSH later**. Anonymous HTTPS clone/fetch is M1; SSH clone/fetch/push is M3. |
| Q3 — Commands | Approved: section 2's narrow surface, lightweight tags and explicit single-ref push, with its listed deferrals. D8/D9 remain accepted. |
| Q4 — Recovery | Approved after discussion: explicit recovery on Motor, a shared tree/index helper, a small operation record and extensions to existing failure tests. Retain the clean-start requirement and D9 discard policy; no general replay journal or power-loss guarantee. The subsequent review is incorporated in v05: a persistent advisory-lock file separate from the three-state record, the target ref and intended commit, a full index rebuild without retained stat caches, and owned merge-state cleanup before record removal. The approved v05 implementation scope defers the earlier proposal's read-only `reflog` command and `ORIG_HEAD`, as D13 describes. |
| Q5 — Reflog identity | Approved: existing generic committer fallback for non-authoring reflogs only; authored commits require configured identity. |
| Q6 — Limits | Approved: one small fixture and one representative development repository, with measured transport/allocation/count/disk limits. This approves the method; it supplies no numerical thresholds. Select and record the workload and limits during implementation. |
| Q7 — Existing index defect | Approved: narrow length check in the external `gix-index/src/file/init.rs` reader port and one truncated-index regression. No source fix in this document-only revision. |

### Recovery discussion

The approved scope provides recovery on Motor for the supported local
operations. Section 2 uses `recover` for repair of a recorded operation;
`branch create NAME OID` retains an earlier commit whose ID is known.
Reflogs continue to be written, but the approved first-release scope has
no command to inspect them.

Git's per-file lock publication and ordinary lock cleanup do not make an
entire worktree transition atomic. Its checkout can leave partial changes,
and forced termination can leave stale locks. This supports a bounded
explicit-repair design without a per-file replay journal.
[Lockfile contract](https://git-scm.com/docs/api-lockfile),
[checkout source](https://github.com/git/git/blob/master/unpack-trees.c).

Retaining the previously accepted D9 discard policy keeps abort simple.
Exact Git `reset --merge` preservation rules, general reset modes and
autostash are outside this scope. Git's `merge --abort` can preserve some
unstaged edits or refuse an unsafe reset; its hard-reset mode can overwrite
untracked obstructions. The gix contract explicitly discards merge work
while preserving unrelated untracked/ignored files. This is a deliberate
compatibility limit, not a claim of identical command behavior.
[Git merge](https://git-scm.com/docs/git-merge),
[Git reset](https://git-scm.com/docs/git-reset).

ORIG_HEAD and reflogs preserve useful commit references, but cannot restore
arbitrary overwritten uncommitted contents. Power-loss durability depends
on storage and fsync behavior and is separate work; no new Motor storage
guarantee is assumed. [Git reflog](https://git-scm.com/docs/git-reflog),
[Git fsync policy](https://github.com/git/git/blob/master/Documentation/config/core.adoc).

The v05 revision was reviewed, committed and approved for implementation,
including D13's `reflog`/`ORIG_HEAD` deferral. There are no remaining scope
questions from that review. Q6's workload and numerical limits remain an
implementation measurement task.
