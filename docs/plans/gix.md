# gix as the Git tool on Motor OS

Plan, v05, revised 2026-09-14 after reviewing v04 against the source.
Q1–Q7 remain resolved. This revision separates the operation lock from
the record, uses three recovery states, fixes index-cache preservation
and merge-state cleanup, and simplifies complete pack object selection.
Overlapping failure tests are consolidated. D8 and D9 retain the policies
accepted on 2026-09-12. Implementation was subsequently approved.

M1 is complete as of 2026-09-16: the developer image installs `gix` with
anonymous HTTPS clone/fetch and read-only status/log. Host/Motor component
gates, `full-test-dev.sh --release`, and the representative native HTTPS
clone pass. The M1 dependency pin is
`087dbd18e849a4275477572ec36a81385ff1e9b9`; section 7 records the repairs,
limits and measured results. M2 implementation is in progress: init, staging,
ordinary commit, branch/tag creation, unstage and restore are implemented and
component-tested. Diff and switch/merge/recovery remain; section 7 records progress.
Section 8 records the approved 8 MiB loose-ref
limit and directory-entry repair. The managed stdlib and approved socket
teardown repair passed three debug and three release main-image gates and the
complete release developer suite. The original developer-budget diagnosis,
its approved correction, and open implementation questions are recorded below.

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

Text diff processes one file pair at a time, with at most 16 MiB and 262,144
lines per side. Count lines exactly before allocating diff tokens. Oversized
text fails with an error naming the path and limit. Honor heuristic Myers or
Histogram; reject configured `minimal`, including named-driver settings,
before tokenization or that file's output. Binary classification precedes
text processing; forced text still receives both bounds. These limits and
errors were discussed and approved on 2026-09-17.

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
| Toolchain | `motor-1.99.0-beta-f47d5bb-dev.2-9c9208d2239aed04ea1b553c26a73b5876cf6b194468f82ecc196a98262dfce2`, from [rust-toolchain.toml](../../rust-toolchain.toml) |
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

At reviewed application commit `69a00937676642980283f106160557750a76dcc3`,
the HTTPS implementation is 1,718 lines including tests: `curl.rs` 417,
`curl_capture.rs` 294, `http_request.rs` 417, `http.rs` 444 and
`https_url.rs` 146. These files contain the fixed curl invocation, bounded
capture and Git-specific URL, response and transport policy.

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
so deletions cannot survive from an old tree. Reject unresolved stages, null
object IDs and overlapping file/directory paths before editing the tree.
Use `new_commit()` to obtain the exact object ID before ref publication,
then a ref transaction with reflogs; do not create the commit twice.
Ordinary commits have HEAD as parent, or no parent for an unborn branch.

Validate real author and committer identity before any authoring mutation,
including non-fast-forward merge. As discussed and approved in Q5, use
gix's existing generic committer fallback for non-authoring reflog writes
(clone/fetch/branch/switch/recovery), only when configured identity is missing.
Never use that fallback for an authored commit. Supply switch's old/new
HEAD reflog entry explicitly, including equal IDs when the attachment changes.
Use the approved opt-in `gix-ref` transaction API to check the old raw HEAD
target and append those IDs without changing or logging either branch.
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

The operation record is `.git/gix-operation`, separate from the
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

**M1 completion, 2026-09-16.** The Makefile builds gix offline with the
selected assembly linker and a keyed object directory, validates both ELF
artifacts with the existing helper, and installs only `/devtools/bin/gix`
through the developer manifest. Markdown and developer-image HTML document
the available commands, trust policy and incomplete-clone handling.
Host/Motor component gates, both target Clippy checks, formatting and
`src/tests/full-test-dev.sh --release` pass. The full suite exercised the
installed binary and completed its developer-source and Lorry phases.

The stripped executable is 5,949,888 bytes, SHA-256
`76fe8edcfb130596d3e94126861319049da51df9eb50b10f638691f78aab5f41`.
The lockfile SHA-256 is
`a305f2562ca2127551deb38624c0ea32c71ca1a02191cce55f3bea839ae28f68`.
The manifest records the exact feature set; release uses aborting panics,
fat LTO and one codegen unit. The copied installed binary matched the build.

The selected Motor OS history at `db5ce8e0` also passed a full native HTTPS
clone in a 1 GiB VM, using the same local server and explicit test CA.
It retained all 36,548 reachable objects; host Git checked refs, strict
fsck, pack validity, index contents and worktree contents/modes. Native
status was clean. Host-observed SSH-plus-clone time was 1,859 ms.
Three HTTP requests sent 412 body bytes and received 18,914,902 body bytes.
The resulting pack was 18,894,459 bytes, its pack index 1,024,416 bytes,
and its worktree index 178,976 bytes. Logical clone file contents totaled
37,779,761 bytes, including 17,667,957 worktree bytes. These are final file
sizes, not peak temporary-disk allocation; peak RSS was not measured.
The earlier pack-ingestion measurement below remains separately identified.
Logs, source identities, build recipe and measurements are under
`/tmp/motor-gix-m1-integration`.

**Thin-pack lookup defect, diagnosed and repaired on 2026-09-15:**
in `gix-pack/src/data/input/lookup_ref_delta_objects.rs`,
the former `try_find(...).ok()?` converted a failed thin-pack base lookup
into end-of-input. `EntriesToBytesIter` could then complete a shorter pack
successfully. A
hermetic diagnostic against `419b494a` verified a complete two-object input
becoming a successful one-object output, and a real object-store allocation
limit being swallowed as a successful empty pack. This affects Q6 and
fetch error handling. Reviewed external commit
`d3e2dd89b0ea3f30b5cf24d4d7327de944d9824c` now propagates the error
with base-object context in that iterator and
`gix-pack/src/data/input/types.rs`, plus one regression in the existing
bundle tests in `gix-pack/tests/pack/bundle.rs`, reached by
`src/tests/test-gix.sh`. The normal `Ok(None)` path for in-pack bases
remains. The original diagnostic now returns errors without leaving pack
files on both host and Motor; the component fixtures and compiler/Clippy
checks also pass. The user published the repair, and the declared remote
was verified at this revision on 2026-09-15.

Q6 native pack-buffer implementation, reviewed on 2026-09-15: external
commit `68c53270d9275ed76d4418a6186027b8f012eba2` changes
`gix-pack/src/lib.rs` and extracts `gix-pack/src/mmap.rs`. On Motor, each
pack/index/multi-index buffer is limited to 128 MiB and all live buffers
from that reader to 256 MiB. The reader requires a regular file, checks its
metadata length, reserves the aggregate allowance before a fallible exact
allocation, rejects short reads or growth, and releases the allowance after
the owned bytes are dropped. Non-Motor builds retain the existing mmap
behavior. Compact host tests cover file and aggregate boundaries, release,
short input and growth; focused host and Motor compiler checks pass. The
existing native repository fixture also passes with verified sources and a
clean VM shutdown. This patch is included in the published revision below.
The representative Motor OS history at `db5ce8e0` has 36,568 objects,
a roughly 19.5 MiB stored pack, and an 89,401,252-byte transfer without
deltas. These figures justify the initial buffer limits; decoded objects,
metadata/counts, other file readers and temporary disk still need bounds,
followed by native workload validation.

Q6 local reader patch, reviewed as external commit
`e2d6d57464c3b99428968ec7321ddcadf986011a`: added a small bounded regular-file
reader in external `gix-features/src/fs.rs`, tested through the existing
`gix-features/tests/features.rs` target and `tests/fs/mod.rs`. The Motor
paths of `gix-index/src/file/init.rs` and
`gix-ref/src/store/packed/buffer.rs` use it. Both owned input files have a
16 MiB ceiling; an index's existing allocation option may lower it.
The representative worktree index is 191,524 bytes and packed refs are
237 bytes. Read from the same opened file, check size before fallible
allocation, and reject short reads or growth. No dependency, global
budget or host mapping change was added. Host boundary/reader tests and
Motor checks pass. These readers also pass the integrated host/Motor
fixture at the current application pin and are included in the published
revision below.

Q6 pack-metadata patch, reviewed as external commit
`a75943823b7698c8375ac2887df46e97b5e67a70`: in external
`gix-pack/src/cache/delta/mod.rs` and `tree.rs`, limit a native delta tree
to 65,536 actual entries before adding roots or either kind of delta.
Initial reservations are clamped to that ceiling: a thin-pack iterator's upper
bound includes possible inserted bases, so the estimate alone must not
reject a pack that fits. Main item-vector reservations are fallible.
The count bounds the associated metadata, work queues and sorting storage
without a general allocation manager, and keeps valid delta depth within
the existing 16-bit representation. The representative history has 36,568
objects. One compact test uses a tiny private limit; non-Motor count policy
is unchanged. Focused tests, Motor checks, and the integrated host/Motor
fixture pass; this patch is included in the published revision below.

Q6 commit-graph patch, reviewed as external commit
`80bf4bd9c4d3f55d9d428aedb19ae7a478a0178b`: in external
`gix-commitgraph`, bound each
native graph file to 16 MiB, an opened graph's retained files to 32 MiB
and 256 files, and chain text to 32 KiB. Reuse the bounded reader by
declaring `gix-features` as a direct dependency; it is already an
unconditional transitive dependency through `gix-hash`, so no package or
feature closure is added. Scope: `gix-commitgraph/Cargo.toml`, the external
`Cargo.lock` (one dependency edge), `src/lib.rs`, `src/native.rs`,
`src/file/init.rs` and `src/init.rs`. Keep the existing host mapping and
normal graph parsing. One compact helper test covers the limits; the
existing repository fixture now contains a two-file graph chain. Host tests,
host/Motor checks and native integration pass; this patch is included in
the published revision below.

Q6 traversal allocation patch, reviewed as external commit
`30706245e9f815348a355cf5429786b8a202dbe3`: in external
`gix-pack/src/cache/delta/traverse/resolve.rs` and `mod.rs`, give each
native traversal a cumulative 512 MiB allowance for new decoded byte-buffer
allocations. Charge the requested new capacity before each fallible exact
reserve when a root, delta-instruction or result buffer must grow. Reusing
an existing capacity costs nothing; dropping a buffer does not refund the
allowance. This conservative bound avoids per-buffer ownership guards.
Serial and parallel workers share one private context for the individual
and cumulative limits; existing non-Motor reserve behavior and public
options remain unchanged. Use one small boundary test
plus existing traversal tests. The allowance is an initial value to check
against the representative native history, not a process-memory ceiling.
Pack buffers, metadata, graph/index/ref storage, and temporary disk have
separate limits. Host boundary/serial/parallel tests, Motor checks and the
native pack rewrite fixture pass. The representative native history also
passes after the duplicate-base repair below.

Q6 stream-inflation patch, reviewed as external commit
`063015ceca3a46f7ffb9d375076058683f40c61a`: in the external checkout's
`gix-pack/src/data/input/bytes_to_entries.rs`, reject native declared
decoded sizes above 16 MiB before inflation, and stop inflation after at
most the declared size plus one byte. A false small declaration then
returns the existing size-mismatch error without inflating the whole
payload. Keep normal hash/trailer parsing and non-Motor behavior. Use one
tiny host helper test and the existing input/bundle tests. Fetch uses
verification mode, so a limit error fails the operation. Focused tests and
host/Motor checks and the integrated component fixtures pass. This patch
is included in the published revision below.

Q6 temporary-pack patch, reviewed as external commit
`861980697e19e259ad40d4700857789ee4512f11`: in external `gix-pack/src/bundle/write/`,
change `mod.rs`, `types.rs` and add a private `limited_file.rs` helper.
Bound native temporary pack extent to 128 MiB, including inserted thin-pack
bases and the final trailer. Wrap the file inside the existing buffered
writer, track position through reads/writes/seeks, and reject excess writes
before they reach disk. Header rewrites do not consume extra allowance.
Retain existing buffering, flush-before-publication and owned-tempfile
cleanup; do not query file position or metadata on every write. Use tiny
boundary checks and one ordinary limit-failure cleanup check with existing
writer types. Non-Motor files keep their unbounded policy. Host tests, host/Motor
compiler and Clippy checks, and the native component fixture pass.

**Duplicate-base defect, discussed and complete repair approved on 2026-09-15:**
the representative native history probe at `86198069` read a valid
36,548-entry, 19,376,138-byte pack but returned 48,969 entries, failing its
unchanged count assertion. A separate host diagnostic found 12,421 duplicate
object IDs; Git rejected the output with “The same object … appears twice
in the pack.” A 75-byte, two-entry reduction reproduces the problem: a
REF delta references a base that is both in the incoming pack and already
in the destination object store; gix inserts another copy and reports
success with three entries. Host Git accepts the input and rejects the output.

The defect originated in external
`gix-pack/src/data/input/lookup_ref_delta_objects.rs`, whose eager base
insertion predates the Motor port. Production fetch reaches Bundle from
`gix/src/remote/connection/fetch/receive_pack.rs`, so it affects M1.
The user approved full repair after discussing a safeguard that would only
reject the invalid output. The original failing logs and binaries remain
under `/tmp/motor-gix-pack-limits-integration` and
`/tmp/motor-gix-history-count-diagnosis`.

The repair was reviewed and committed in four patches:
`f89c4266` (external-base traversal), `e5aed20e` (index preparation),
`4d288a75` (shared Bundle completion), and `087dbd18` (failure regressions
and API documentation). Resolve incoming objects first, using local bases
provisionally where needed; an unresolved intermediate may itself arrive as
a delta. Subtract incoming object IDs before appending missing bases.
Keep incoming entry bytes and offsets, then update the count, checksum and
index together. Complete input packs remain byte-identical. Restore mode
truncates to surviving entries before appending bases and rebuilding the
header and trailer.

A bounded iterative dependency walk with shared visitation state rejects
cycles that provisional local bases could otherwise hide. Append-time
lookups must still return the expected object ID; disappearance, changed
content and read failures leave no published output. The existing limits,
lookup error causes, cancellation and owned-file cleanup remain enforced.
Duplicate IDs are rejected before index publication.

All library changes are in the external authoring checkout
`/home/posk/motor-dev/gitoxide-motor-cli`. The exact paths, relative to
`gix-pack/src/`, are `cache/delta/traverse/{mod.rs,resolve.rs}`,
`cache/delta/tree.rs`, `index/mod.rs`,
`index/write/{mod.rs,error.rs,thin.rs}`,
`bundle/write/{mod.rs,types.rs,error.rs,limited_file.rs}`, and
`data/input/lookup_ref_delta_objects.rs`; tests are in
`gix-pack/tests/pack/bundle.rs`. The legacy public iterator remains for
source compatibility with its absent-base precondition documented.
Both synchronous and eager Bundle paths use the shared repair.

The main-repo `src/bin/gix/tests/native_port.rs` fixture adds one thin
chain with a local intermediate; `src/tests/test-gix.sh` checks its host
and copied-back native pack with Git. The first host run at `86198069`
failed on four objects instead of three, as expected for the defect.
At `087dbd18`, both release component gates pass, including this unchanged
regression. Six valid diagnostic cases produce the exact unique object
sets and pass host Git verification; self and two-object cycles fail with
empty output directories. The external Bundle group covers both entrypoints,
Restore truncation and append-time lookup failures.

The original native history probe now retains all 36,548 entries and the
exact 19,376,138 input bytes. Its 1,024,416-byte index passes host Git
verification. In one 1 GiB VM run, ingestion took 1,665 ms; post-ingestion
virtual memory was 12,365,824 bytes, which is not peak RSS. Host/Motor
all-target compiler and Clippy checks, formatting and shell checks pass.
The manifest and lockfile differ only in the fork revision.
Evidence is under `/tmp/motor-gix-duplicate-base-integration`; external
patch reviews and Git oracles are under `/tmp/motor-gix-duplicate-base-fix`.
This completes the repair and the representative pack-ingestion check.
The later complete M1 gate is recorded at the start of this section.

Application resource policy: `src/bin/gix/src/repository.rs` now supplies
the fixed 16 MiB object allocation setting and single-worker index/pack
settings before repository open, with common options/policy helpers for
clone reuse. `status.rs` explicitly selects one worker. The existing log
fixture supplies a conflicting `-c` allocation setting to check that fixed
policy wins. The native fixture now rewrites a real pack for host Git
verification as well as checking a two-file graph chain.

Application target-tree validation, reviewed on 2026-09-15:
`src/bin/gix/src/tree_index.rs` builds an index without writing the
worktree. It limits all visited entries, including directories, to 65,536;
cumulative full path bytes to 8 MiB; each source blob to 16 MiB; and
aggregate source blob bytes to 128 MiB. The last limit is not a bound on
filtered checkout output. It validates UTF-8 Motor paths (255-byte
components and absolute paths below 1024 bytes), duplicate names and
file/directory conflicts, object kinds and Git mode normalization before
checkout. Including SHA-1 v2 entry overhead, the maximum serialized index
is 12,976,160 bytes, below the Motor reader's 16 MiB ceiling; a compile-time
assertion preserves that relationship. Gitlinks remain index entries. Tree
buffers use the repository's fixed object-read bound. One compact boundary
test and the existing
host/Motor mode/index fixture pass, along with both target checks and
Clippy. Native evidence and source identities are in
`/tmp/motor-gix-tree-index-integration`.

Application mutation guard, reviewed on 2026-09-15:
`src/bin/gix/src/mutation.rs` takes the persistent advisory lock before
`index.lock`, validates the repository and freshly loaded index, and
publishes reconstructed indexes with a checksum and no extensions through
a 64 KiB buffer. It holds the advisory lock through index publication and
owned-lock cleanup, including rename failure. Ref lock timeouts are fixed
at zero. Unsupported operation markers, shallow/partial/promisor state
(including alternate object stores), sparse state and unsupported index
flags refuse mutation. Valid split indexes use gix's existing dissolution.
The shared host/Motor fixture verifies contention in a child process before
and after index publication, failed publication without deleting an
obstruction, foreign-lock preservation and selected policy refusals.
The first native failure injector assumed an empty directory could not be
replaced; Motor allows that. The corrected injector uses a nonempty
directory, which both filesystems reject. The original failure and source
diagnosis are preserved under `/tmp/motor-gix-mutation-integration`;
final passing evidence is under `/tmp/motor-gix-mutation-final`.

Application initial checkout, reviewed on 2026-09-15:
`checkout.rs` uses the bounded tree builder and checks filter attributes
from the target index before writing files. The existing filter preflight
is shared with status. Checkout uses one worker, no overwrites and no
symlink creation, reapplies replacement-object policy to its converted
object handle, and rejects errors, collisions or interruption before
returning a fresh index for guarded publication. The existing host/Motor
fixture passes with this helper; checks and Clippy pass. Evidence:
`/tmp/motor-gix-checkout-integration`.

Application HTTPS command policy, preparatory implementation on 2026-09-15:
`network.rs` selects system trust or the last explicit
`-c http.sslCAInfo=PATH`, fixes V2 and the 128 MiB response ceiling,
validates anonymous HTTPS URLs, and diagnoses rejected ref updates without
claiming that other refs stayed unchanged. The guarded `fetch.rs` helper
accepts configured remote names and checks mapped destinations before
receiving objects; only tracking refs and tags may change. The common
configuration now fixes `clone.rejectShallow=true`. Host library tests and
host/Motor Clippy pass. The subsequent CLI integration below establishes
end-to-end acquisition.

Local HTTPS fixture, preparatory implementation on 2026-09-15:
the host-only `https-server` test target serves a fixed local repository
through host Git's upload-pack with isolated configuration. It binds only
loopback or the VM test bridge and uses checked-in test certificates.
Response cases cover redirect, HTTP/media-type rejection, malformed Git
data and a stalled response for native cancellation. Host/Motor Clippy
and formatting pass; its TLS dependencies are absent from the Motor
production dependency closure. The subsequent CLI/test-runner integration
validates it at runtime. Preparatory evidence:
`/tmp/motor-gix-https-server-integration`.

Application acquisition, reviewed on 2026-09-15:
`clone URL DIR` and `fetch [REMOTE]` now use the common repository policy,
mutation guard and HTTPS adapter. Clone retains its owned partial directory
and marker on failure; status reports that marker. The component gate
passes on host and Motor: host Git validates cloned content/index/refs and
fetch invariance, while a native terminal interruption verifies exit 130,
connection closure and marker retention. Host refusal cases cover an
existing destination, external filters, unsafe fetch refspecs and invalid
HTTP/protocol responses. The copied-worktree oracle uses Git's content/mode
patch rather than its stat-only quiet result; both real edits and mode
changes were checked. The HTTP error expectation checks the status contract,
which includes curl diagnostics but not response-body text.
Original fixture failures, their diagnoses and final passing logs/source
identities are in `/tmp/motor-gix-acquisition-integration`.
The full developer-image gate selects the installed `/devtools/bin/gix`;
manual guest component runs upload the current component binary.

Clone policy integration, implementation follow-up on 2026-09-15:
the external checkout now provides the small
`PrepareFetch::repository_mut()` accessor introduced in reviewed commit
`419b494a869dc976caceb1dee108ce92dee1ae33`. It exposes the contained
repository before fetch so the application can validate paths, sanitize
configuration and set `objects.ignore_replacements` without duplicating
the library's clone/ref/HEAD orchestration, and returns `None` after a
successful fetch consumes that handle. The application uses reviewed commit
`087dbd18e849a4275477572ec36a81385ff1e9b9`. The user published it on
`gix-moturus-cli`; the declared remote was verified at this exact revision
on 2026-09-15. It includes all Q6 library patches and the duplicate-base
repair recorded above.

Pack-input follow-up, discussed and approved on 2026-09-15: repaired in
Gitoxide `b4e6aeaa82be4183af466b7a99484c38322dd260`. In the external
checkout's `gix-pack/src/data/input/bytes_to_entries.rs`, the streaming
constructor now returns the existing unsupported-version error for version
3 instead of asserting. It handles an empty pack's mandatory trailer during
construction through the existing verifier, preserving each parsing mode.
The input tests and native pack-writer fixture cover rejection, valid empty
packs and temporary-file cleanup; focused host and Motor checks pass.
The later Q6 metadata patch above supplies the separate entry-count bound;
the decoded-object limit alone does not bound pack metadata storage.

Implementation follow-up, discussed and approved on 2026-09-15: extend Motor
FS's own-role permission rule to allow `Rx` → `Rwx`, alongside `Rw` → `Rx`.
Retain higher-role ceilings and lower-role narrowing. The Gitoxide checkout
and executable probe can then use `Rw` → `Rx` → `Rwx` without a new creation
adapter. An interruption between those calls can leave an `Rx` output;
M2 recovery must restore write access or replace that owned output before
opening it for writing. Validate the OS change with three debug and three release
`full-test.sh` runs, plus `full-test-dev.sh --release`.

Retained-index publication (M2 foundation), reviewed on 2026-09-16:
`Guard::publish_edited_index()` edits the locked snapshot, sorts and validates
it, and invalidates racy stat caches against the original index timestamp
using D5's options. Fresh and retained publication share the buffered,
checksummed writer, which refuses output above the native reader's 16 MiB
limit before publishing it. Existing flags and conflict stages are retained.
The existing native fixture exercises edited publication, retained entries
and lock ownership on host and Motor. The deterministic equal-size edit
regression runs on the host because Motor has no file timestamp setter;
it confirms status still sees the edit after the index timestamp advances.
Host and Motor component gates and Clippy pass. Evidence:
`/tmp/motor-gix-m2-foundation`. The complete developer-image gate remains
the M2 milestone gate after the authoring workflows are implemented.

Local initialization (M2), reviewed on 2026-09-16:
`gix init [DIR]` now creates an ordinary SHA-1 repository in the specified
directory, or the current directory when omitted. It preserves existing
files and refuses an existing `.git`. The shared configuration policy
selects `init.defaultBranch` or `main`; validate and freeze that name
before creating files. Invalid names and prior cancellation leave no
destination behind. Host and Motor component gates cover initialization,
configured branches, preservation/refusal and the CLI; host/Motor Clippy
and formatting pass. Evidence: `/tmp/motor-gix-init-integration`.

Literal staging (M2), reviewed on 2026-09-16:
`gix add PATH…` and `gix add -A` now prepare additions, modifications,
deletions and regular-file conflict resolutions against one locked index.
Literal selection preserves overlapping explicit arguments for ignored-path
diagnostics, includes tracked ignored files, and never descends into gitlinks.
File/directory replacement removes obsolete index entries; a replacement
that would change a gitlink is refused. Source paths use the same Motor
and Gitoxide portability checks as checkout, including the existing
Windows-reserved-name/character rejection.

Enumeration retains at most 65,536 unique candidates and 8 MiB of path
bytes. The converter checks source metadata before allocation, bounds its
read, and limits both source and converted blob data to 16 MiB. It processes
one file at a time through built-in conversion, preserving executable and
indexed-symlink modes. Selected external/required filters are rejected before
blob writes. Only the complete prepared change set reaches the existing
checksummed, bounded index publisher; an error may leave harmless loose
objects, but never a partially published index.

Host and Motor component gates, including the leading-dash CLI case and
Git verification of the copied-back native repository, pass. The shared
lifecycle covers ignored selections, conflict stages, both file/directory
directions, gitlinks, filter refusal, executable/symlink modes and oversized
source rejection. The native fixture explicitly restores write permission
after copying an executable: Motor intentionally finalizes an RWX copy as
RX. No OS change was needed. Host/Motor Clippy, formatting and shell checks
also pass. Evidence and diagnosed failures: `/tmp/motor-gix-add-integration`.
`full-test-dev.sh --release` remains the M2 milestone gate after its remaining
commands and recovery workflows are complete.

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

M2 branch/tag commands are implemented in `3b63a839`. Listing streams sorted
short names without a mutation lock; creation uses the existing guard and
no-replacement ref transaction. Branches peel to commits and lightweight tags
retain the selected object after a header check. The shared native lifecycle,
CLI checks, and matching MD/HTML documentation cover the narrow interface.
Host/Motor component gates, formatting, strict Clippy and shell checks pass.
Evidence is in `/tmp/motor-gix-refs-bc78fc2a`.

M2 index-to-tree writer: the reviewed shared helper is applied. It preflights
all stages and ordinary leaf modes, then fills an empty-tree editor from the
validated index held by the mutation guard. Missing paths cannot survive from
an earlier tree; gitlinks remain opaque. One focused test covers the empty
index, nested paths, supported modes, absent gitlink targets and conflicts.
Host/Motor component gates, selected-toolchain formatting, strict Clippy
and shell checks pass. Evidence is in `/tmp/motor-gix-tree-writer-integration`.
No commit command is exposed by this slice.

M2 ordinary commit library: the reviewed implementation validates configured
author and committer identity before acquiring the mutation guard, writes one
commit from the held index, then advances attached local HEAD with an
expected-value ref transaction and reflogs. It rejects unresolved entries,
ordinary unchanged trees and detached HEAD; merge authoring follows with the
operation-record work. The shared native lifecycle covers initial/second commits,
identity preflight, deleted tree paths, reflogs and ref-lock failure cleanup.
Host/Motor component gates, selected-toolchain formatting, strict Clippy and
shell checks pass, with all tested source hashes matching. Evidence is in
`/tmp/motor-gix-commit-library-d77cc66c`; the library patch is `27087011`.
The reviewed CLI exposes `commit -m MSG`, with matching Markdown and developer
HTML documentation. Its host and Motor smoke runs both produce a repository
that passes host Git's history, tree and strict integrity checks. The component,
formatting, strict Clippy and shell gates pass with matching source hashes;
CLI validation is in `/tmp/motor-gix-commit-cli-27087011`.

M2 unstage library: the reviewed implementation restores selected index entries
from HEAD, or removes them on an unborn branch, through the existing mutation
guard and index publisher. Literal selection reads only HEAD and the index;
it rejects unmatched paths and an unselected file ancestor that would obstruct
a restored HEAD descendant. Worktree files remain intact, and unselected entry
caches are preserved subject to the publisher's existing racy-stat invalidation.
One shared native lifecycle covers both HEAD states, the file/directory corner
case, rejection without index changes, and a nonzero unselected stat cache.
Host/Motor component gates, formatting, strict Clippy and shell checks pass;
all tested source hashes match. The new fixture's initial API mismatch and
racy-cache setup assumption were corrected without changing production behavior
or weakening assertions. Original failures and final validation are preserved
in `/tmp/motor-gix-unstage-library-5d3bc82a`.
The library is committed as `fc914dd8`. The reviewed CLI now exposes
`unstage PATH…`, with matching Markdown and developer HTML documentation.
Its host and Motor smoke checks extend the existing init/add/commit lifecycle,
including a leading-dash path and host Git interoperability. All component,
formatting, strict Clippy and shell gates pass with matching source hashes;
CLI evidence is in `/tmp/motor-gix-unstage-cli-fc914dd8`.

M2 narrow restore library: the reviewed implementation borrows selected entries
from the locked index, preflights all paths/filters/blob limits before deletion,
and uses a full index copy for attribute lookup while skipping unselected output.
It replaces regular files or empty directories nonrecursively, rejects selected
conflicts and unsafe obstructions, and leaves the index and refs unchanged.
A shared native lifecycle verifies restoration, whole-selection preflight,
preserved local files, conflict refusal and lock cleanup. Host/Motor component
gates, formatting, strict Clippy and shell checks pass with matching source hashes.
The first host gate passed its tests but caught an unnecessary borrow in Clippy;
that was corrected. Review and validation are in
`/tmp/motor-gix-restore-library-5d8c23b1`.
The library is committed as `236d895d`. The reviewed CLI exposes
`restore PATH…` and documents its limits and repeatable recovery after an I/O
error or cancellation. The extended native lifecycle verifies executable and
link-text modes, empty-directory replacement and ancestor obstruction refusal.
Host/Motor CLI smoke checks and host Git verification pass, along with formatting,
strict Clippy and shell checks; all tested source hashes match. CLI evidence is
in `/tmp/motor-gix-restore-cli-236d895d`.

M2 operation-record reader: the reviewed 64 KiB bounded, versioned format
preserves raw validated reference bytes and checks record structure, including
state/kind consistency and the branch advanced by merge/fast-forward. Status
reports the recorded kind/state; ordinary mutation refuses pending or malformed
records and retained update locks. The shared native lifecycle covers exact
non-UTF-8 names, status, admission and malformed records. Host/Motor component
gates, formatting, strict Clippy and shell checks pass with matching source hashes.
Evidence is in `/tmp/motor-gix-operation-read-298b4010`. Live object/ref validation
belongs to the later transition/recovery commands.

M2 operation-record writer: the reviewed guard now creates, replaces and removes
records under an adjacent Git lock, comparing the expected record before updates.
Only the documented state transitions are allowed; operation identity is immutable.
Recovery admission accepts incomplete/publishing records and owned merge state,
while ordinary mutation and ready-merge recovery remain blocked. The shared native
lifecycle covers state changes, stale snapshots, retained locks, recovery admission
and process exclusion without a separate fixture. Host/Motor component gates,
formatting, strict Clippy and shell checks pass with matching source hashes.
Evidence is in `/tmp/motor-gix-operation-write-6ddf59c1`. Command-level recovery
and live object/ref checks remain part of the transition implementation.

M2 shared content conversion: the reviewed staging refactor exposes a short-lived
callback over bounded canonical Git bytes. Staging still writes the borrowed
slice directly, with unchanged source/conversion limits, checks and diagnostics.
This enables read-only diff loading and cleanliness hashing without duplicating
file handling or copying staging content. Existing host/Motor staging lifecycles,
all component gates, formatting and strict Clippy pass with matching source hashes.
Evidence is in `/tmp/motor-gix-shared-conversion-657e25b6`.

M2 tree-writer validation correction: review found that the application writer
introduced in `d77cc66c` relied on tree-editor behavior that permits replacing a
file ancestor and omitting null placeholders. A sorted index can still contain
`a`, `a.b`, and `a/c`; a stage-0 null ID also passed the earlier checks. Both
small regressions produced successful tree IDs before the fix. The writer now
checks ordering, rejects null IDs and checks every proper indexed ancestor
before invoking the editor, without an extra path collection. The existing
unit lifecycle covers both cases; host/Motor component gates, formatting and
strict Clippy pass with matching source hashes. No external code changed.
Original failures, review and gates are preserved in
`/tmp/motor-gix-tree-writer-validation-e6806cc3`.

M2 bounded diff inputs: the reviewed loader reads object and worktree inputs
one pair at a time, retaining one lazy conversion pipeline across the command.
That avoids rebuilding the index-backed attribute mapping for every path.
Object headers are checked before bounded reads; canonical worktree content uses
the shared callback, and indexed symlink text stays raw. Gitlinks remain opaque,
including missing worktree paths. The shared native lifecycle checks those
behaviors and unchanged index bytes. Host/Motor component gates, formatting,
strict Clippy and shell checks pass with matching source hashes. Evidence is in
`/tmp/motor-gix-diff-loader-b35b010f`. The renderer and approved text-diff policy
remain separate; no new limit or algorithm policy was applied.

M2 transition delta: the reviewed helper builds bounded original/target indexes,
checks held-index path/ID/mode/stage equivalence, and merges sorted entries into
one add/delete/modify list. It reserves the bounded union before inserting and
does not copy unchanged paths. Changed gitlinks are rejected; unchanged entries
remain opaque. The native lifecycle holds the mutation guard and checks the
delta, rejection paths, and unchanged HEAD/index/worktree. Host/Motor component
gates, formatting, strict Clippy and shell checks pass with matching source hashes.
Evidence is in `/tmp/motor-gix-transition-delta-cea65c30`. This data-only result
does not certify worktree cleanliness or collision safety; that preflight follows.

M2 transition collision preflight: changed-path ancestors and destination
contents are inspected without following symbolic links. Only known tracked
deletions permit file/directory replacement; ignored and untracked contents,
unrelated empty descendant directories, and nested repositories block it.
An empty exact target directory is permitted. Directory work storage is bounded
by admitted original deletion paths, and sorted prefix lookup includes the slash
so an intervening sibling cannot hide a descendant. The existing native lifecycle
covers those cases, including deletion-only ancestors, while retaining the guard
and unchanged HEAD/index/worktree. Host/Motor component gates, formatting and
strict Clippy pass with matching source hashes. Evidence is in
`/tmp/motor-gix-transition-collisions-cb2439cb`. Cleanliness validation follows.

M2 transition cleanliness preflight: preparation now validates filters across
both complete bounded indexes, checks collisions, and hashes canonical content
and mode for every original ordinary entry without writing objects. Checking
all target attributes also catches a new `.gitattributes` assigning a forbidden
filter to an otherwise unchanged file. Changed original paths retain observed
stats; callers keep the mutation guard and recheck state before destructive
writes. The existing native lifecycle checks target-only filter rejection,
unchanged-file dirtiness, saved stats, and no worktree/index/ref or hash-induced
object writes. Host/Motor component gates, formatting and strict Clippy pass
with matching source hashes. Evidence is in
`/tmp/motor-gix-transition-prepare-5a23f661`. Installation and ref publication
remain subsequent steps.

M2 transition installation: the reviewed helper requires the exact persisted
incomplete record and prepared result-tree ID before destructive writes. It
rechecks collisions and every changed source, repeats full no-follow/stat/mode
checks per deletion, and removes blocking directories in bounded postorder with
nonrecursive operations. Checkout recreates only changed destinations exclusively,
using the complete target index for attributes; unchanged files and unrelated
contents are preserved. Temporary selection flags are cleared and errors and
cancellation checked before returning the fresh index for guarded publication.
The existing native lifecycle covers stale-source refusal before earlier deletion,
file/directory replacements, executable output, an ignored sibling, unchanged
stat/content, retained HEAD/record and the exact published index. Parent and
independent source reviews found no blocker; host/Motor component gates, formatting
and strict Clippy pass with matching source hashes. Evidence is in
`/tmp/motor-gix-transition-install-2137cce8`. Command-level ref publication,
merge-state handling and recovery remain to be implemented.

M2 symbolic HEAD reflog dependency: the reviewed application pin now selects
`176e1568e94c3bf4bd5add4ec65aeba13b40d8f5`, including the opt-in checked symbolic
transaction API and the separate two-line test assertion cleanup. Versions and
features are unchanged. The existing host gate runs the new exact/equal-ID HEAD
lifecycle with all ref transaction tests. Host/Motor component gates, formatting,
strict Clippy and shell checks pass with matching source hashes. The application
HEAD helper follows separately. Evidence is in
`/tmp/motor-gix-symbolic-reflog-integration`.

M2 exact HEAD state: the reviewed read-only helper captures the raw HEAD
attachment and direct commit ID, including unborn and detached states. It
validates local branch names through the existing validator, rejects symbolic
branch targets and non-commit IDs, and compares both recorded fields without
peeling or ancestry inference. One isolated native lifecycle covers those states
and stale-state refusal. Host/Motor component gates, formatting, strict Clippy
and shell checks pass with matching source hashes. Ref publication remains the
next separate slice. Evidence is in `/tmp/motor-gix-head-capture-eb5d038f`.

M2 bounded text rendering: the reviewed renderer supplies exact byte-line counts
before interning, enforces the approved 262,144-line per-side limit and rejects
Minimal before that text pair's output. It streams three-context hunks and newline
markers to buffered output, preserving write errors and cancellation checks.
The shared loader remains the 16 MiB per-side prerequisite. Focused native
coverage checks exact Myers/Histogram output, the exact/one-over line boundary,
escaped limit diagnostics, Minimal refusal and cancellation without output.
Host/Motor component gates, formatting, strict Clippy and shell checks pass with
matching source hashes. Attribute/driver resolution and the diff command follow
separately. Evidence is in `/tmp/motor-gix-diff-renderer-e34572e6`.

M2 diff metadata: the reviewed resolver reuses Gitoxide's typed global and
named-driver configuration with attributes tied to the held index. It loads no
diff resources: the bounded loader remains the content reader. Bare `diff`
forces text, `-diff` forces binary, and named drivers can select either or
automatic NUL detection over the first 8,000 bytes per side. Minimal reaches the
text renderer's explicit refusal; binary resources need no text algorithm.
One existing native repository lifecycle covers these policies and unchanged
index bytes. Host/Motor component gates, formatting, strict Clippy and shell
checks pass with matching source hashes. Command selection/output integration
follows separately. Evidence is in `/tmp/motor-gix-diff-policy-405ea83a`.

M2 checked HEAD publication: the reviewed helper validates exact HEAD and
destination IDs again after acquiring the ref lock, then uses the approved
external API for one symbolic HEAD update and exact old/new reflog IDs. It
preserves branch refs/logs, the application's trusted ref-lock configuration,
generic non-author identity fallback, cancellation classification and actual-state
diagnostics for partial publication. The caller retains its mutation guard and
operation record. The native lifecycle verifies changed/equal-ID switches,
stale/moved refusal and guard lifetime. After correcting four explicit borrowed
name conversions in the draft, all host/Motor component gates, formatting,
strict Clippy and shell checks pass with matching source hashes. Original
compiler diagnostics and final validation are preserved in
`/tmp/motor-gix-head-attach-4cec3fec`. Switch/recovery command integration follows.

M2 text preparation: the renderer now prepares bounded tokens and the diff before
any file metadata is emitted, then streams the existing hunks through a separate
writer. This replaces the unpublished one-shot API without a wrapper or rendered
output buffer. Existing native output, line-boundary, Minimal and cancellation
coverage remains; no duplicate control-flow tests were added. Host/Motor component
gates, formatting, strict Clippy and shell checks pass with matching source hashes.
Evidence is in `/tmp/motor-gix-diff-prepared-aac171ba`.

M2 per-file diff output: the reviewed helper emits escaped labels, mode-only
metadata, unified text, binary summaries and opaque gitlink IDs. Raw symlink
pairs use the global text algorithm; regular-file attributes apply only to
regular pairs. Text preparation precedes each file's metadata, and equal-byte
mode changes need no text algorithm. The first native run exposed a new test's
incorrect abbreviated hunk-header expectation; source inspection confirmed
Gitoxide's explicit counts and only that expectation was corrected. All final
host/Motor component gates, formatting, strict Clippy and shell checks pass with
matching source hashes. Evidence, including the original failure, is in
`/tmp/motor-gix-diff-pair-46041664`. Command enumeration follows separately.

M2 checked switch library: the reviewed command preflights exact branch state,
identity, attributes, cleanliness and collisions under the mutation guard. It
creates the incomplete record before worktree writes, publishes the fresh index
and checked HEAD attachment, then removes the record last. Same-branch requests
still require a clean worktree but produce no ref update. One shared native
lifecycle covers success, ref/reflog preservation, the checked no-op and retained
recovery state when a foreign HEAD lock blocks publication. Host/Motor component
gates, formatting, strict Clippy and shell checks pass with matching source hashes.
Evidence is in `/tmp/motor-gix-switch-bd97dfb7`. CLI exposure waits for recovery.

M2 diff command library: the reviewed read-only entry point holds one index,
preflights selected paths, conflict stages and worktree filters before output,
and compares staged entries with a bounded HEAD snapshot in one sorted pass.
Unchanged staged IDs/modes skip blob loading; unselected scan steps remain
cancellable. One loader and resolver serve the run. The native lifecycle checks
unborn/staged/worktree behavior, literal selection, rejection before file output
and unchanged repository data. Host behavior passed initially; five new test
assertions then needed the equivalent `expect_err()` spelling for strict Clippy.
All final host/Motor component gates and formatting/shell checks pass with
matching source hashes. Evidence is in `/tmp/motor-gix-diff-run-89685401`.

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
questions from that review. Section 7 records Q6's selected workload,
implemented limits and pack-ingestion measurement; remaining command paths
still need their limits and workload validation during implementation.

### Implementation discussion — thin-pack lookup errors (2026-09-15)

Discussed and approved: repair the external iterator to propagate base-lookup
errors with their cause, add one focused regression to the normal component
gate, review the patch before committing, and update the dependency pin.
Then continue clone/fetch and resource-limit implementation.

### Resolved implementation discussion — atomic init (2026-09-16)

Source review of Gitoxide at `087dbd18` found that worktree initialization
checks whether `.git` exists, then uses `create_dir_all`. Two initializers
can pass that check and write into the same directory. A precheck in the
application has the same race. M1 clone exclusively creates its destination;
the issue matters for M2 init in an existing worktree directory.

Discussed and approved: in the external checkout
`/home/posk/motor-dev/gitoxide-motor-cli`, change `gix/src/create.rs`
to create missing worktree parents normally and reserve the final `.git`
with atomic `std::fs::create_dir`, retaining the existing error type for an
occupied path. Keep bare initialization unchanged. Extend the existing
`gix/tests/gix/init.rs` tests with a preexisting-file preservation case,
then run the existing init and clone/component gates before updating the
application pin. The application-only alternative would require bare
initialization followed by custom persistent-config rewriting and reopening;
the library fix is smaller and avoids that duplicated orchestration.

Applied and reviewed as external commit
`e121301a7245f354dbb9c5bc48c0d71786701ca3`. The regression fails on the
original implementation and passes with the repair; all 11 init tests and
12 focused clone/init tests pass, as do host and Motor checks with the
application's exact features and the fork's formatting check. Evidence is
in `/tmp/motor-gix-init-atomic-integration`. The standard component gate
now includes the existing `init::` test group. The application pin moves
to this exact commit; local validation imports it from the authoring
checkout, and publishing the external branch remains a user action.
Host and Motor application component gates, including HTTPS acquisition,
pass with this pin; host/Motor Clippy, formatting and shell checks also
pass. Integration evidence: `/tmp/motor-gix-m2-foundation`.

This repair changes only the two external files above. No Motor OS
filesystem or standard-library change is needed.

### Resolved implementation discussion — bounded loose references (2026-09-16)

Review of the next branch/tag step found a separate Gitoxide allocation gap
at external revision `e121301a`. Direct loose-ref lookup in
`gix-ref/src/store/file/find.rs` and loose/packed overlay iteration in
`gix-ref/src/store/file/overlay_iter.rs` both use unbounded `read_to_end`.
Lookup is also used by existing `log`, revision resolution and ref
transactions. Object allocation settings and the existing 16 MiB packed-ref
limit do not cover these reads. This affects Q6 on Motor; it is not a
Motor OS filesystem defect.

A controlled host diagnostic compared a 41-byte loose ref with an 8 MiB
padded version of the same ref. Both reached the same missing-object error;
peak RSS increased from 5,184 KiB to 13,056 KiB, and the syscall trace
confirmed the whole 8 MiB file was read. This is host evidence for the
target-independent read path, not a claim of a native runtime reproduction.
Source and evidence: `/tmp/motor-gix-refs-draft/notes/loose-ref-bound-diagnosis.md`
and `/tmp/motor-gix-refs-draft/evidence`. This demonstrates an unbounded
allocation, not an out-of-memory crash or a failure with ordinary refs.

Discussed and approved with an **8 MiB** ceiling rather than the initially
proposed 16 MiB. The repair is explicitly outside the main Motor OS repository, in
`/home/posk/motor-dev/gitoxide-motor-cli`: add one private shared loose-ref
reader in `gix-ref/src/store/file/loose/mod.rs`, then use it from the lookup
and overlay-iteration files above. On Motor, reuse the existing
`gix_features::fs::read_to_end_bounded` with an 8 MiB per-file ceiling.
It checks metadata before allocation, uses a fallible exact allocation,
and rejects short reads or growth. Preserve non-Motor behavior and existing
lookup/iteration error propagation. This per-file policy also applies to
multi-line pseudo refs such as `FETCH_HEAD`, which share the lookup path;
it is not a total process-memory limit. Native index and packed-ref
ceilings remain 16 MiB.

Keep validation small: reuse the existing bounded-reader boundary tests,
run existing ref lookup/iteration/transaction tests, and extend the shared
native fixture with exact-8-MiB success and one-byte-over rejection
covering lookup and unfiltered overlay listing.
Include that coverage in the normal gix component gate. Review the external
patch before committing it and updating the application pin. Forward
reflog reading is a separate deferred path; these commands do not use it.

An application precheck would duplicate the backend and race its actual
read, so it would not enforce the bound. No Motor OS or standard-library
change is proposed.

Applied and reviewed as external commit
`86589c55ea4daf62c8fbaf968bb0cdcecbf7b76f` in the three production files
above. The application pin and lockfile use this exact revision. Local
validation imports the commit from the authoring checkout; publishing the
external branch remains a user action.

The final native boundary fixture fails on the previous pin and passes on
this revision. Both the host and Motor gix component gates pass, including
32 reference-store tests, 40 transaction tests and the existing bounded-reader
test on the host, and exact-limit/one-byte-over lookup and listing on Motor.
Host/Motor Clippy, selected-toolchain formatting and shell checks pass.
Evidence is in `/tmp/motor-gix-loose-ref-integration`. The M2 completion
`full-test-dev.sh --release` gate remains due at the milestone boundary.

### Resolved implementation discussion — native directory-entry paths (2026-09-16)

The new native boundary fixture exposed a separate preexisting defect in
Rust's Motor port. `DirEntry::path()` in
`/home/posk/motor-dev/toolchain-src/rust/library/std/src/sys/fs/motor.rs`
unconditionally appends `/` to the parent string. Reading `refs/heads/`
therefore returns a child spelled `refs/heads//bounded`. Gitoxide's loose
iterator rejects that spelling as an invalid reference name. Its
`local_branches()` and `tags()` use slash-terminated prefixes, so they can
silently omit loose refs on Motor. Direct lookup and unfiltered iteration
find the same reference correctly.

A targeted native diagnostic confirmed the duplicated separator in
`std::fs::read_dir`, correct file types, and the difference between
unfiltered, full-name-prefixed and slash-terminated-prefix iteration.
Evidence, original failure and temporary instrumentation are retained in
`/tmp/motor-gix-loose-ref-integration/listing-diagnosis.md`. The final
size-limit fixture uses unfiltered overlay iteration to cover the same
bounded reader; it does not claim to validate or fix prefixed listing.

Discussed and approved: construct the entry path with
`Path::new(&self.parent_path).join(self.filename())`, cover slash-terminated
`read_dir` in the existing native filesystem test, and validate the affected
branch/tag traversal. This is ordinary path construction, not a change to
compiler or memory-layout behavior.

The source change was authored in the separate external checkout
`/home/posk/motor-dev/rust-motor-gix`, on branch
`motor-os-1.99.0-beta-f47d5bb`, based on
`d9b95d4a8f17021fc769a0685c5d943fa0ce797b`. The diagnosed
`toolchain-src/rust` directory is managed input and is updated only by the
normal producer, never edited by hand.
No runtime ABI change is needed: `rt.vdso` returns only the filename and
metadata, while std retains the original parent string and adds the slash.

Reviewed and committed in the external fork as
`b4eb29b6f00ae2190f565f56595d51403c8baf13`: replace the four concatenation
lines with the single `Path::join` expression above. No other Rust files
changed.

Keep regression coverage in the existing fixtures: 11 systest lines compare
exact directory-entry path bytes for ordinary and slash-terminated parents;
12 gix lines check slash-terminated branch and tag prefixes. Comparing raw
path bytes is necessary because `Path` equality normalizes duplicate
separators. Both regressions failed on the selected unfixed stdlib, with
`a/b//file` versus `a/b/file` and `prefixed ref missing`, respectively.

Candidate validation passed using Cargo `-Zbuild-std` and an isolated sysroot
pointing at the corrected fork: the full systest invocation reports
`ALL PASS`, and the native gix component gate passes. Candidate testing left
the selected compiler, installed prefix, and managed Rust source unchanged. Logs, build
commands, the original failures, and reviewed patches are retained in
`/tmp/motor-std-direntry-integration`. The same regression additions are
included in the managed cutover gates below.

The user published the fork commit; remote verification confirmed its exact
revision. The official `src/build-motor-os.sh` producer completed successfully.
`MOTOR_RUST_REV` and `rust-toolchain.toml` now select the published revision and
toolchain key `9c9208d2239aed04ea1b553c26a73b5876cf6b194468f82ecc196a98262dfce2`.
The cutover check, formatting, and strict Clippy for the changed packages pass.
The initial gate sequence passed one release and one debug `full-test.sh`
run, including the new path regression, then stopped on the listener-teardown
allocation defect diagnosed below. After the approved runtime repair, a new
complete sequence passed three debug and three release main-image runs.
The first release developer gate passed both gix component gates, but its
repository suite reached the overall 900-second deadline before completion.
Its diagnosis and the approved developer-only budget correction are recorded
below. The subsequent cold run of `full-test-dev.sh --release` passed the
repository suite, native source builds and complete Lorry product suite.
All tested source hashes matched at completion. Managed cutover is fully
validated; authoring candidates must not bypass publication/cutover checks.

### Resolved workflow discussion — Motor fork guidelines

Discussed and resolved: the user explicitly directed this work to follow
Motor OS guidelines, without the upstream Rust `AGENTS.md` requirements.
Continue the approved sub-agent implementation and parent-review workflow.

### Resolved implementation discussion — allocation during socket teardown (2026-09-16)

The second managed release gate failed in
`admission::test_aggregate_listener_exhaustion`: the child failed a 1,992-byte
allocation while dropping its held TCP listeners, then the parent reported
`flood child failed to exit cleanly`. This is a preexisting Motor runtime
defect, separate from the directory-entry fix and gix.

The preserved backtrace resolves to `SegQueue<DriverRecord>::push`,
`NetChannel::enqueue_teardown_messages`, `TcpListener` destruction, and
`posix_close`, reached from `subcommand::do_command`. Diagnostic release builds
with symbols have byte-identical `.text` sections to both failing binaries;
no pressure-test retry or temporary source instrumentation was needed.
A Crossbeam segment for this 56-byte record is exactly
`8 + 31 * 64 = 1,992` bytes. The shared teardown path also constructs message
`VecDeque`s, which can allocate while the memory floor is already reached.

Discussed and approved: make the shared driver teardown/control path allocation-free
once its operation is admitted. Reserve its required storage through a
fallible path before accepting the resource or operation, then transfer that
storage during cleanup. Cover TCP listeners, TCP streams and UDP sockets,
including pending-data ordering and cancellation/late-response cleanup;
preserve the existing staging fences and reservation lifetime. Increasing
queue capacity without guaranteed admission credits, waiting inside Drop,
changing the memory floor, or weakening the existing pressure test would not
fix the contract.

The user approved preallocating the storage needed for teardown before
resuming managed cutover and gix implementation. The reviewed runtime patch
is applied. It reserves queue capacity before socket admission, with twenty
credits per reservation: at most sixteen pending TCP data messages, close,
initial receive ACK, accept request, and late-response cleanup. Cancellation
releases its socket slot immediately; a weak credit retained by the RPC waiter
covers any eventual close. Queue growth is fallible at admission. The vDSO
pool propagates `OutOfMemory` after checking other existing channels.

The driver retains the final reservation until the close reaches sys-io and
preserves FIFO order and staging fences. Single-message records, a one-message
carry slot, and fixed-size socket snapshots remove the teardown storage
allocations. Existing exhaustion, cancellation, backpressure, UDP ordering,
and channel reclamation tests are unchanged. Selected-toolchain formatting
and strict runtime Clippy pass. Three debug and three release main-image
runs passed, including the original listener-exhaustion test. That test and
the cancellation/backpressure cases also passed in the first developer run
before its overall deadline expired. After the separately approved harness
correction, the complete cold release developer gate passed, including native
source builds and Lorry. The unchanged reviewed runtime patch is committed as
`be9da7c8`. Runtime source, review and validation evidence are in
`/tmp/motor-teardown-preallocation`.
Original failure evidence remains in
`/tmp/motor-std-direntry-integration/managed-gates/release-2.log` and
`/tmp/motor-std-direntry-integration/admission-diagnosis`.

### Resolved implementation discussion — developer-suite time budget (2026-09-16)

The release developer gate exited with status 124 after `full-test.sh`'s
900-second deadline. That deadline starts before image builds, host tests,
and guest-test preparation (`src/tests/full-test.sh:3`). The preserved log
records approximately 219 seconds of sequential host gix Cargo work and
90 seconds of later developer-only compilation, including 66 seconds for
the native gix binaries. Both gix component gates passed.

The main developer VM started about 640 seconds into the suite. Its system
tests continued reporting passes until about ten seconds before wrapper
completion, including listener exhaustion and socket teardown/cancellation.
The last completed test was `test_half_open_accounting`; the following
backlog-growth test normally waits for bounded sweep recovery. No test
assertion or new allocation failure was recorded before the overall timeout.
This supports exhaustion of the suite budget during normal progress; the
run does not establish that all remaining tests pass.

The failed run and console are preserved in
`/tmp/motor-teardown-preallocation/gates/developer-release.log` and
`/tmp/motor-teardown-preallocation/developer-timeout-diagnosis`.
All tested source/configuration hashes still match the reviewed inputs.
No test-local timeout was changed, and no warm-cache rerun was used to
dismiss the failure. A later pass alone would not resolve it.

An independent source/log review reached the same conclusion. Discussed and
approved: the user accepted a developer-only 1,500-second overall budget,
then completion of validation and resumption of gix implementation. The
reviewed two-line change uses `FULL_TEST_VERIFY_DEV_SOURCES=1` to select the
existing debug budget; ordinary release runs retain 900 seconds. This is
an explicit exception to `AGENTS.md` note (1), based on the diagnosis above.
Separating all build preparation from timed execution would require broader
restructuring.

The approved change is committed as `734f90b2`. With the generated gix
component cache cleared, `src/tests/full-test-dev.sh --release` passed on
2026-09-16, including the repository suite, native source builds and complete
Lorry product suite. All tested source hashes matched. The 1,500-second bound
applies to the repository phase; the separate source-build and Lorry bounds
are unchanged. The completed run and source checks are preserved in
`/tmp/motor-teardown-preallocation/developer-release-approved`. The original
failed run remains part of the validation record.

### Resolved implementation discussion — cancellation diagnostics (2026-09-16)

The resumed source review found an existing application reporting defect.
`src/bin/gix/src/main.rs` samples cancellation before returning a command's
result, so a late Ctrl+C can replace a real error, including a ref/reflog
publication error. `clone.rs:32` can report `clone did not complete` after
checkout, index publication and removal of the incomplete marker have all
succeeded. `fetch.rs:65` can skip the received outcome and its warning about
references that may already have changed. These are result/diagnostic losses;
exit 130 after a completed atomic edit alone does not establish a defect.

Discussed and approved: preserve existing errors and inspect fetch update
outcomes before any final cancellation check; attach the partial-state warning
to interrupted fetches; use the incomplete-clone diagnostic only for an actual
clone failure. Retain cancellation exit 130 and the documented possibility of
partial ref/reflog publication. Do not add a new success-wins-late-Ctrl+C policy,
rollback machinery, external crate changes, or a timing-sensitive race test.
Reuse the existing cancelled-clone fixture and compact result-handling coverage.

The user approved this application-only repair and continuation with gix.
The reviewed implementation uses one cancellation error with an optional source,
corrects result ordering in main, clone, fetch and init, and retains fetch's
partial-publication warning. Upstream generic interruption errors retain their
sources and cancellation classification, preserving exit 130. One compact
source-chain unit test and the unchanged native interrupted-clone fixture pass.
The complete host/Motor component gates, selected-toolchain formatting, strict
Clippy and shell checks pass; all tested source hashes match. Validation evidence
is in `/tmp/motor-gix-cancellation-fix`. Source reviews:
`/tmp/motor-gix-commit-design/review.md` and
`/tmp/motor-gix-commit-design/cancellation-normalization.md`.

A follow-up source review on 2026-09-17 found the same approved error-ordering
correction still needed inside `checkout::initial`: it checked cancellation
before consuming the checkout result and its errors/collisions. The small
completion consumes and normalizes those errors before the final success-only
cancellation check, retaining their diagnostics and exit 130. Existing error-chain
coverage and the interrupted-clone lifecycle pass, as do the full host/Motor
component gates, formatting and strict Clippy. Tested source hashes match;
evidence is in `/tmp/motor-gix-checkout-cancellation-completion`.

### Resolved implementation discussion — executable attribute files (2026-09-16)

The restore source review found a preexisting Gitoxide defect in
`gix-worktree/src/stack/state/mod.rs:139` at pin `86589c55`: index-backed
attribute/ignore lookup admits only `Mode::FILE` (100644), omitting valid
`Mode::FILE_EXECUTABLE` (100755) entries. Executable `.gitattributes` files
therefore disappear from `Source::IdMapping`. This affects the existing initial
checkout and its filter preflight, as well as planned restore/switch/merge work.
It is an external library defect; no Motor OS filesystem change is needed.

A small offline diagnostic using the current application library confirms the
impact. Two local repositories differ only in the indexed mode of
`.gitattributes`; both contain `file filter=blocked`. Host Git's cached attribute
lookup reports `blocked` for both. With `filter.blocked.required=true`, application
checkout correctly rejects the 100644 repository before writing worktree content, but
incorrectly succeeds for 100755. The diagnostic exits 1 for this mismatch.
No filter command is configured or executed. Source, fixture commands and
results are preserved in `/tmp/motor-gix-executable-attributes-diagnosis`.
No application or external source was modified for diagnosis.

Discussed and approved on 2026-09-17: repair the external authoring checkout
`/home/posk/motor-dev/gitoxide-motor-cli` by accepting both regular blob modes in
the shared predicate, add one focused attribute-mapping regression, and extend
the existing Motor/host application fixture to cover required-filter rejection
for executable `.gitattributes`. Parent review, focused fork tests, component
gates and an exact dependency-pin update follow the established workflow; the
user publishes the external commit. This corrects the shared `.gitignore` mode
handling too and avoids duplicating the library rule in application index copies.

The reviewed fix is committed externally as
`ddf4b6b7dab39328d6d045a7ca1ecc5bd9f03292`: one predicate change and one focused
test, 48 insertions and one deletion after formatting. The application now pins
that exact revision; package versions and dependency features are unchanged.
Both new regressions failed against the unfixed source: the mapping test omitted
executable entries, and the application fixture unexpectedly completed checkout.
With the repair, all 11 worktree tests and the complete host/Motor component
gates pass, including the specific required-filter error, unchanged index and
absence of worktree writes. Selected-toolchain formatting, strict host/Motor
Clippy and shell checks pass; all tested source hashes match. The new tests run
through the existing component script and developer-suite integration.

Review, original failures and final gates are preserved in
`/tmp/motor-gix-executable-attributes-integration`. The revision was imported
locally for offline validation; the user confirmed publishing it on 2026-09-17.

### Resolved implementation discussion — text-diff limits (2026-09-16)

Source review of the pinned diff library found that its token-count estimate
samples only the first 20 lines and can greatly overallocate even for a
21-line file. A small application `TokenSource` can supply an exact count;
no external crate change is needed. Count and check lines before interning,
retain the existing 16 MiB per-side byte limit, and process one file pair at
a time. The approved additional limit is 262,144 lines per side. These bounds
cover renderer working storage, not total process memory; measure the latter
through the approved Q6 workload, without another benchmark matrix.

Configured `diff.algorithm=minimal`, including named-driver settings, selects
an algorithm with quadratic worst-case work and no internal cancellation
hook. Ordinary heuristic Myers and Histogram remain available. Returning an
error for unsupported settings avoids silently changing the requested
algorithm. A file over the text-line limit must not be mislabeled binary.

Discussed and approved on 2026-09-17: use an explicit path-and-limit error for
oversized text and reject configured `minimal`, including named drivers.
The shared bounded loader is committed; renderer implementation follows this
policy, with focused boundary coverage and the existing Q6 measurement scope.
Source review: `/tmp/motor-gix-diff-design/review-current.md`.

### Resolved implementation discussion — symbolic HEAD reflogs (2026-09-17)

Source review of the active `ddf4b6b7` pin found an API limitation affecting
switch and HEAD restoration. A checked symbolic HEAD update skips its reflog;
the clone exception can only supply a null old ID. Duplicate HEAD edits are
rejected, while a dereferenced reflog-only edit also logs the current branch.
Those APIs cannot express D13's exact old/new HEAD entry while changing only
HEAD's attachment. The private reflog writer already supports the needed IDs.

Discussed and approved on 2026-09-17: add an opt-in method for committing one
prepared symbolic reference update with explicit previous/new reflog IDs, in
`/home/posk/motor-dev/gitoxide-motor-cli/gix-ref`. Keep existing callers and
storage policy unchanged, reuse the private append implementation, and preserve
its reflog-before-ref order and partial-publication errors. Explicit entries
must also be written when both IDs are equal but the branch attachment changes.
One focused lifecycle covers exact entries, unchanged branch refs/logs, and
stale or invalid edit refusal. The application continues to capture and check
exact branch IDs while holding its mutation guard; this adds no guarantee of
snapshot isolation against arbitrary external writers.

The approved scope includes focused validation, parent review and an exact
application pin update; the user publishes the external commit. Application
reflog storage would duplicate library logic, and imprecise HEAD or extra branch
entries would change the accepted contract. Implementation and validation
follow approval; the earlier proposal alone was not compiled or run.

The reviewed API is committed externally as
`176e1568e94c3bf4bd5add4ec65aeba13b40d8f5`, with 221 insertions and 10 deletions
across production code and one focused lifecycle. All 41 ref transaction tests,
the gix-ref unit tests, formatting and strict host/Motor Clippy pass. The first
Clippy run exposed two preexisting empty-input assertions rejected by the
selected toolchain. The equivalent two-line test-only cleanup was reviewed and
committed separately as `4b38e88e9`; the original failure is preserved.
The user confirmed publication of both external commits on 2026-09-17.
Application validation uses the exact published API revision. Evidence is in
`/tmp/motor-gix-symbolic-reflog-integration`.
Source review: `/tmp/motor-gix-head-ref-design/review.md`.
Source proposal and parent review: `/tmp/motor-gix-symbolic-reflog-api/`.
