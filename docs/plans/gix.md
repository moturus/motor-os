# gix as the Git tool on Motor OS

Plan, 2026-09-12, revised the same day after review of the M2 authoring
commands. A gix-only alternative to [jj-gix-workflow.md](jj-gix-workflow.md):
the same platform port, transports, push engine, packaging and gates, but
authoring comes from new porcelain subcommands added to the gix CLI instead
of a Jujutsu port. Follows the root `AGENTS.md`: 100–300-line patches with
tests, no commits unless asked, external source edits called out in every
patch report. No code has changed.

## 1. Goal

Ship `/devtools/bin/gix` in the developer image as a basic Git client: clone
and fetch, inspect, stage, commit, branch and tag, switch, merge, and publish
over SSH. Repository state on disk stays Git-compatible (index, refs, reflogs,
merge state), so host Git reads Motor-created repositories unchanged. There is
no `git` executable or alias and no promise of Git's command-line output.

The pinned gix CLI is a plumbing tool. Half of the required commands do not
exist in it and are new work over library APIs that do exist:

| Command | In the pinned CLI | Library support to build on |
| --- | --- | --- |
| `gix init [--bare] [DIR]` | absent | `gix::init`, `gix::init_bare` |
| `gix clone`, `gix fetch`, `gix remote refs` | present | needs the Motor HTTPS and SSH transports |
| `gix status`, `log`, `blame`, `cat`, `tree`, `revision` | present | needs the platform port |
| `gix diff [--staged]` | only object-level `diff tree` and `diff file` | `gix-status` index/worktree comparison, `gix-diff` `UnifiedDiff` |
| `gix add`, `gix rm` | absent | `filter_pipeline().convert_to_git()`, `write_blob`, `gix-index` `dangerously_push_entry`/`sort_entries`/`remove_entries`, `gix-dir` walk with excludes |
| `gix commit -m` | only `verify`, `sign`, `describe` | `Repository::commit`, tree `Editor` for write-tree, `author()`/`committer()` |
| `gix branch create/delete` | only `list` | `edit_reference` |
| `gix tag create` | only `list` | `Repository::tag`, `tag_reference` |
| `gix switch` | absent | `index_from_tree`, `gix-worktree-state::checkout`, `edit_reference` |
| `gix merge REV`, `--abort` | only object-level `merge tree/file/commit` | `merge_base`, `merge_commits`, `Outcome::conflicts`, tree `Editor::write` |
| `gix push` | absent, upstream too | new send-pack engine over existing handshake, pack and packet-line APIs |

`git pull` is documented as `gix fetch` then `gix merge`. Out of scope for
M1–M3: rebase, stash, cherry-pick, `restore`/`reset`, interactive hunk
selection, `--amend`, Git linked worktrees, submodule operations (gitlink
entries are preserved), LFS, credential helpers, hooks, external filters,
merge drivers and signing, proxies, `ein`, `tix` and the SQLite corpus tools.
A required filter fails before checkout writes anything. Excluded commands
return an actionable error; they never panic or silently skip.

## 2. Decisions

D8 and D9 were accepted on 2026-09-12. The others are proposed; review
confirms or changes them before implementation.

- **D1 Milestones.** Three shippable milestones (section 4), each ending in
  an assembly candidate that passes its gates. M4 is a backlog of separately
  reviewed extensions; none is required for completion.
- **D2 Source.** Stay on the fork's pinned revision
  `4604ac322369a2e429a805cf6e5b7267712283f1` (gix 0.86.0) on a new
  `gix-moturus-cli` branch of `moturus/gitoxide`. Without jj there is no
  version requirement to meet; an upstream rebase is an M4 option. Lorry's
  pin is unchanged.
- **D3 Porcelain.** New subcommands live in the fork's `gitoxide-core` and
  `src/plumbing`, implemented over `gix` library APIs. They write Git's
  formats (index v2, packed and loose refs with reflogs, `MERGE_HEAD` and
  `MERGE_MSG`) and never shell out. Output is gix's own; Git-style porcelain
  text is not a goal.
- **D4 Transports.** HTTPS through the existing `/system/bin/curl` child and
  SSH through `/user/bin/ssh`, both via `std::process::Command` with explicit
  arguments. Token HTTPS passes the secret through the child environment with
  curl's `--variable %NAME` and `--expand-header`; argv, URLs and logs never
  carry it. Local-path clone is an in-process copy transport, not a spawned
  `git-upload-pack`.
- **D5 Working tree.** `core.symlinks=false`: link target text as an ordinary
  file, symlink mode kept in the index. The executable bit maps to
  `moto_rt::fs` permissions and files stay editable. Status uses conservative
  invalidation, not invented inode or ctime semantics.
- **D6 Trust.** No helper, filter, hook, signing tool, merge driver or
  installed-Git discovery executes from configuration. The merge platform is
  built with an empty driver list, so no `merge.<name>.driver` command can
  run; a conflicting path whose `merge` attribute names a driver other than
  the built-in text, binary or union ones aborts the merge before the working
  tree changes. The fork's `gix-sec` ownership check returning `Ok(true)` on
  Motor is not treated as trust to execute anything.
- **D7 Panic.** An explicit `panic = "abort"` profile overrides the
  [Motor target's unwind default](../toolchain.md#rust-runtime-and-native-formatting).
  Errors and cancellation use ordinary returns and RAII.
- **D8 (accepted 2026-09-12) No object deletion.** gix never deletes or
  repacks objects; loose objects accumulate and are measured. Repack and gc
  are M4.
- **D9 (accepted 2026-09-12) Merge policy.** `gix merge REV` fast-forwards
  when possible, otherwise writes a merge commit. On conflicts it writes
  conflict markers into the working tree, stage 1–3 index entries,
  `MERGE_HEAD` and `MERGE_MSG`, and stops; `gix add` then `gix commit`
  completes it; `gix merge --abort` restores HEAD's tree and index. Only the
  default recursive strategy; no rerere, no octopus. `gix switch` and
  `gix merge` refuse to overwrite local modifications.
- **D10 Push policy.** SHA-1 repositories. Create and fast-forward by default;
  rewriting needs an explicit per-ref lease. Every update carries the old and
  new IDs so the server also detects races. `report-status` is required;
  tracking advances only on a confirmed result; an unknown outcome is never
  retried automatically.
- **D11 Distribution.** A managed assembly component with a sourced producer
  helper, following `src/toolchain-rust-analyzer.sh`, installed only in the
  developer image. Rust and LLVM pins do not move.
- **D12 Clean-tree precondition.** `gix switch` and `gix merge` require a
  clean tracked index and working tree and no untracked file at a path the
  target would write; `gix status` names what to commit or discard first.
  This is how D9's "refuse to overwrite" is implemented, and it makes
  `--abort` exact: there are no pre-merge changes to preserve. Carrying local
  changes across a switch or merge is M4.

## 3. Verified baseline (2026-09-12)

| Source | Identity |
| --- | --- |
| Motor OS | `be8dd555`, branch `frusa`; toolchain `1.99.0-beta-f47d5bb-motor.dev.1` |
| Motor gitoxide fork | `4604ac322369a2e429a805cf6e5b7267712283f1`: gix 0.86.0, gitoxide 0.56.0, gitoxide-core 0.60.0 |
| Upstream gitoxide | `766543702cbf39d1c466de58fcefaed78c91af75` |

Facts the plan relies on, checked in source:

- The fork's CLI (`-p gitoxide --bin gix`, needs `pretty-cli`) has `branch
  list`, `tag list`, `commit verify/sign/describe`, `merge tree/file/commit`
  as object operations with ours/theirs/union resolution, `diff tree/file`
  between objects, `status`, `log`, `blame`, `fetch`, `clone`, `remote`,
  `index`, `worktree`, `env`, `config`, `fsck`. It has no `init`, `add`,
  `rm`, worktree `diff`, worktree `merge`, `switch`, branch or tag creation,
  or `push`.
- Upstream `crate-status.md` lists as unfinished: add with ignore handling,
  tree from index, checkout/switch/restore/reset orchestration, merge
  workflow orchestration with `MERGE_HEAD`, push and send-pack plumbing.
- The library has `init`, `filter_pipeline()` with `convert_to_git`,
  `write_blob`, `commit(reference, message, tree, parents)`,
  `author`/`committer`, `edit_reference(s)`, `tag`, `tag_reference`,
  `index_from_tree`, `merge_base`, `merge_commits`/`merge_trees` with an
  `Outcome` listing `conflicts` by kind and a tree `Editor` with
  `upsert`/`remove`/`write`, `status`, `dirwalk`, `gix-diff` `UnifiedDiff`,
  `handshake()` with a `Service` parameter, `RequestWriter::into_parts()`
  and pack writers. `gix-index` has `dangerously_push_entry`,
  `sort_entries`, `remove_entries`, `Stat::from_fs`, `write_to` and a
  `write::Extensions::None` option; `gix-worktree-state` has `checkout` from
  an index.
- Three API traps the M2 contract answers: `File::write()` takes `index.lock`
  only at publication and writes the tree-cache extension unchanged, so a
  mutated index would publish a stale cache; `checkout()` returns `Ok` after
  an interrupt and reports per-path `errors` and `collisions` in its
  outcome; the blob merge platform launches configured `merge.<name>.driver`
  commands and falls back to the built-in text driver when a named driver is
  not configured.
- Fork platform gaps: `gix-sec` ownership is `Ok(true)` on Motor; `gix-fs`
  has no Motor `Capabilities` default and its non-Unix executable probe
  returns false; `gix-index` loading still uses `memmap2` and `filetime`;
  `gix/src/lib.rs` exports a Motor `strlen`; `gitoxide-core` unconditionally
  enables worktree, status, interrupt and credentials features and uses
  `open::that` and `tempfile`. The SSH launcher adds `-o SendEnv=GIT_PROTOCOL`
  unless the protocol is V1.
- Motor std: symlink, hard link and `set_times` are unsupported; file locks,
  metadata, rename and permissions work. `moto_rt` provides
  `ctrl_c_register_handler`/`ctrl_c_wait`, `set_perm`/`set_file_perm` and
  `FileAttr::entry_id`. The base target sets `PanicStrategy::Abort`.
- Motor curl accepts `--header`, `--data-binary @-`, `--cacert`, `--proto`,
  `--location`, `--max-time`, `--write-out`, `--variable %NAME` and
  `--expand-header`; no `--user`, `-K` or netrc. Motor ssh rejects unknown
  `-o` keys and supports `StrictHostKeyChecking`, `BatchMode`, `-i`, `-p`;
  russhd's client separates stderr, sends EOF and returns the exit status.
- A host experiment pushed with Git 2.53 through the host-built Motor `ssh`
  to `russhd` running host `git-receive-pack`: initial 8 MiB push,
  fast-forward, annotated tag, stale-lease rejection, leased rewrite, delete,
  mixed hook rejection and `git fsck --strict` passed. It proves the
  transport, not a native client.

## 4. Milestones

Every step is a group of 100–300-line patches with tests. Fork edits are
external (section 7). A step's gate passes before the next step starts; a
successful `cargo check` is never evidence of runtime support.

### M1 — CLI port: local repositories and anonymous HTTPS

1. **Baseline and oracle.** Create the branch (D2), record revision and tree
   digest. Build the pinned Linux `gix` as the behavioural oracle and capture
   help for every acceptance command (`gix -r PATH`). Inventory target
   dependencies separately from host build scripts and proc macros; provision
   once, then build `--locked --offline`. Record the first
   `cargo check --target x86_64-unknown-motor -p gitoxide --bin gix
   --no-default-features --features pretty-cli,sha1` diagnostics.
2. **CLI shell.** A `motor-cli` feature recipe (`small` pulls the line
   renderer and crossterm, `max` pulls libcurl, OpenSSL and the TUI). Keep
   clap and plain stderr progress; replace `terminal_size`, `is-terminal` and
   `crosstermion` with `std::io::IsTerminal` or gate a command with its
   dependency (`open::that`, `tempfile`). Deterministic version identity
   instead of `build.rs` `git describe`. `panic = "abort"` profile (D7).
   Stream stdout; test broken pipes.
3. **Filesystem and worktree.** Motor `Capabilities` defaults and a real
   executable-bit probe in `gix-fs`; replace `memmap2`/`filetime` in
   `gix-index` and every commit-graph or status path the CLI reaches with the
   fork's owned-buffer pattern, fallible allocation and checked lengths; map
   `100644`/`100755` to `moto_rt::fs` permissions and verify execution and
   editability; conservative status cache (same-size rapid edits,
   permission-only changes, host-imported index); `core.symlinks=false`
   checkout (D5); gitlinks stay gitlinks. Extend `gix-motor-tempfile` only as
   core needs: exclusive creation, private permissions, same-filesystem
   rename, no check-then-overwrite. Keep Git `.lock` files; never remove
   another process's lock; keep previous refs readable after a failed fetch.
   Reject unrepresentable names before writing; keep traversal and `.git`
   injection protections; test malicious trees and colliding names.
4. **Configuration, processes, cancellation.** One repository-open policy: no
   installed-Git probing (`gitoxide-core/src/repository/clone.rs` enables
   `git_binary`), no helper, filter, hook, merge driver or signing execution
   (D6), with sentinel executables covering the existing object-level merge
   commands too. Precedence `-c`, repository data, explicit user
   configuration, supported environment; the user configuration path follows
   Motor's home conventions and is reported by `gix env`. Replace
   `signal-hook` with `moto_rt::process::ctrl_c_*` driving gix's interrupt
   flag without consuming stdin; cancellation stops transfer, pack and
   checkout work, kills and reaps children, releases this process's locks and
   exits 130. First link with the assembly linker: raw and stripped ELF are
   `DYN` with no interpreter, `NEEDED`, TLS segment, executable stack or
   unresolved symbols; reconcile the `strlen` export with the linked runtime.
5. **HTTPS transport.** A Motor backend in `gix-transport`'s blocking HTTP
   module behind a feature, selected by `gitoxide-core` for clone, fetch and
   remote-ref listing alike. `Http` over the curl child: bounded pipes and
   staging, typed response metadata, CA `/system/cfg/ssl/ca-certificates.crt`
   with an explicit override for fixtures, hostname verification, same-origin
   redirects with a hop limit and no downgrade, 401/403/404 recognised before
   the pack parser, no userinfo or proxies. Bound bytes, disk, duration and
   decompressed memory; record the first measured limits here. No retries.
6. **Fixtures, packaging, gates.** `src/tests/test-gix.sh` with fixed
   identities and timestamps, isolated HOME/XDG/temp, loopback-only servers,
   host Git as the oracle (`upload-pack --stateless-rpc` behind the existing
   curl TLS fixture, `git fsck` on repositories copied back). Package per
   section 6, wire the gates, measure.

Gate: the installed `gix` inspects, clones and fetches deterministic fixtures
in the VM without any Git executable; hostile-configuration sentinels never
run; Ctrl+C is clean; the assembly rebuilds reproducibly.

### M2 — porcelain: init, add, diff, commit, branch, tag, switch, merge

Each command is one step: a `gitoxide-core` function with typed results, a
thin clap subcommand, host tests against the oracle, and a guest fixture
whose repository is copied back to the host. Fixtures compare content, not
just validity: staged blob IDs, tree IDs, conflict stages, untouched local
files and the state after each interruption point are checked against host
Git. Only `commit` and annotated `tag` need `user.name`/`user.email`.

Common contract:

- **Index protocol.** Acquire `index.lock` through `gix_lock` (fail
  immediately) before reading the index; mutate in memory; `write_to` the
  lock with `Extensions::None`, so a stale tree cache is never published;
  commit the lock. A held lock is reported and never removed.
- **Staging content.** Working files go through
  `filter_pipeline().convert_to_git()` (built-in end-of-line and ident
  conversions; external drivers are refused per D6), then `write_blob`.
  Entries use `Stat::from_fs` on Motor metadata and the D5 mode rules.
- **Publication order.** Objects first (orphans are harmless), then the
  index, then refs through gix ref transactions with reflogs, then merge
  state files. Every interruption point leaves a state the next command
  recognises, as listed per command below. A checkout outcome with `errors`,
  `collisions` or a raised interrupt flag stops the command before HEAD or
  the index is published, and the error is reported.
- **Working-tree transitions** (switch, fast-forward, merge result, abort)
  start from a clean tracked tree (D12), so the transition is the diff of
  two trees: delete paths absent from the target (a path changing between
  file and directory is deleted first), write changed and new entries with
  `gix-worktree-state::checkout` on that subset, build the index with
  `index_from_tree` carrying stat data over for unchanged entries. A tracked
  file equal to either the old or the target version counts as clean, so an
  interrupted transition is completed by running the same command again.
- **Concurrency.** Two gix processes on one repository serialise on
  `index.lock` and ref locks; the loser fails immediately.

1. **`gix init [--bare] [DIR]`** over `gix::init`; default branch from
   `init.defaultBranch` or `main`.
2. **`gix add [-A] PATH…` and `gix rm [--cached] PATH…`.** `add` stages
   additions, modifications and deletions under each PATH (`-A` is the whole
   tree); ignored files are skipped unless already tracked; a conflicted
   path's stage 1–3 entries are replaced by stage 0 of the working file, or
   removed if the file is gone. `rm` removes from index and working tree,
   `--cached` from the index only; both refuse when the working file differs
   from the index or the index differs from HEAD, unless `--force`.
   Interruption leaves either the old or the new index.
3. **`gix diff [--staged] [--name-only] [PATH…]`.** Working tree versus
   index, or index versus HEAD with `--staged`, as unified diffs through
   `gix-status` and `UnifiedDiff`; binary files are reported, not dumped.
4. **Write-tree and `gix commit -m MSG [--allow-empty]`.** Build the tree
   from the index with the tree `Editor` (`upsert` per entry, `write`);
   refuse a conflicted index; refuse a tree equal to HEAD's unless
   `--allow-empty` or a merge is pending; parents are HEAD plus `MERGE_HEAD`
   when present. Order: trees, commit object, `Repository::commit` (updates
   HEAD's branch and reflog; detached HEAD supported), then remove
   `MERGE_HEAD` and `MERGE_MSG`. A `MERGE_HEAD` that is already an ancestor of
   HEAD is stale and is cleared by the next `status`, `commit` or `merge`.
   Author and committer come from `author()`/`committer()` with a
   deterministic time override for tests.
5. **`gix branch create|delete` and `gix tag create`** over `edit_reference`
   and `tag`/`tag_reference`; lightweight and annotated tags; refuse deleting
   the checked-out branch or overwriting an existing ref without `--force`.
6. **`gix switch [-c] BRANCH` and `--detach REV`.** D12 precondition, then
   the tree transition above. Order: `index.lock`, working tree, commit the
   index, move HEAD with `edit_reference`. Recovery: run the same switch
   again.
7. **`gix merge REV` and `gix merge --abort`** per D9 and D12. With
   `merge_base`: REV an ancestor of HEAD reports "already up to date" and
   changes nothing; HEAD an ancestor of REV fast-forwards the current branch
   through the tree transition; otherwise `merge_commits`. Supported
   conflicts are content conflicts of regular text files, materialised as
   marker files with stage 1–3 entries; any other conflict kind in
   `Outcome::conflicts` (binary, mode or symlink, modify/delete, rename,
   file/directory, submodule) refuses the merge before the working tree
   changes and names the paths. Order: `MERGE_HEAD` and `MERGE_MSG`,
   `index.lock`, working tree, commit the index, then for a clean merge the
   commit with two parents and removal of the merge state. Recovery: an
   interrupted merge is finished by `gix commit` (a resolved tree equal to
   HEAD is allowed) or discarded by `gix merge --abort`, which restores HEAD's
   tree and index through the same transition, treating tracked files as
   disposable, and is itself re-runnable.
8. **Safety fixtures.** Process death after each publication step of `add`,
   `commit`, `switch`, `merge` and `--abort`, followed by the documented
   recovery command; two concurrent gix processes; a concurrent host-side
   edit; a full disk; a read-only repository; symlink text and executable
   modes through every command; a host-imported index with a populated tree
   cache, then host `git write-tree` after gix staging; a repository authored
   on Motor, continued with host Git and continued again on Motor.

Gate: an init/add/diff/commit/branch/switch/merge/conflict/resolve scenario
passes in the VM, and host Git reports the same staged blobs, trees, stages,
status, log and fsck results on the copied repository after every step and
after every recovery.

### M3 — SSH: adapter, push engine, `gix push`, SSH fetch

Each step first passes a host slice against loopback host Git through the
host-built Motor `ssh` and `russhd`, then the same slice in the VM.

1. **SSH adapter** in the fork's `gix-transport` ssh module: the Motor
   argument set (`-i`, `-p`, `-o StrictHostKeyChecking=…`, `-o BatchMode=yes`,
   no PTY), protocol V1 so `SendEnv` is never passed, a quoted remote path,
   bidirectional binary pipes with a stderr drain, cancellation, and child
   completion with exit status. Serves upload-pack (SSH fetch and clone) and
   receive-pack.
2. **Strict pack producer.** The exact outgoing object set from gix traversal
   and `gix-pack` output (`Entry::from_data`, `iter_from_counts`,
   `FromEntriesIter`): non-thin, base objects where no delta can be reused,
   `ofs-delta` only if advertised. Verified with host `index-pack` and `fsck`.
3. **Single-ref protocol.** Command list with capabilities, flush, raw PACK
   bytes through `into_parts()`, `report-status` parsing, create/update/delete,
   leases, the empty-pack and all-delete cases.
4. **`gix push` command** per section 5.
5. **Gates.** `test-gix.sh` gains SSH clone and fetch plus push to empty and
   populated receivers: creation, fast-forward, rejected rewrite, exact and
   stale leases, a concurrent remote change, tags, deletion, no-op, dry-run,
   partial hook rejection, tracking and `--set-upstream`; truncated or
   malformed reports, failed unpack, large stderr, broken pipes,
   cancellation, dropped response and local bookkeeping failure remain
   distinguishable. Prove an incremental push sends no object reachable from
   the remote's advertised refs; record transfer size, CPU, memory and
   temporary disk.

Gate: the installed `gix` clones over SSH and publishes to a host
receive-pack from the VM with accurate per-ref results, and every M1 and M2
gate still passes.

### M4 — backlog, each item separately reviewed

Token HTTPS (D4 mechanism, origin-bound, redaction fixtures); local-path
clone; repack and gc; carrying local changes across switch and merge;
non-text conflict kinds; `--amend`, `restore` and `reset`; rebase, stash and
cherry-pick; interactive hunk selection; sideband and report-status-v2;
push-options and atomic push; HTTPS push; `git://` with a local daemon
fixture only; SHA-256 with an interoperability fixture; an upstream gitoxide
rebase; native builds through Lorry.

## 5. Push engine and `gix push`

The fork owns discovery, object selection, pack production, SSH IO and remote
status behind a typed API of Git ref names and object IDs; CLI selection,
policy and output sit in `gitoxide-core` and `src/plumbing`. Push URLs and URL
rewriting resolve through gix's push direction; more than one push
destination is rejected before publication.

Wire rules:

- Legacy V1 handshake through `gix_protocol::handshake(…, Service::ReceivePack, …)`;
  `.have` pseudo-refs are audited separately from publishable refs.
- Client capabilities: `report-status` (required) and `ofs-delta` when
  advertised. `delete-refs` is a server capability checked before deletions.
  Sideband, report-status-v2, push-options and atomic are M4; requesting them
  fails before any mutation.
- An all-delete request sends no pack; any create or update sends one even
  with zero objects.
- Object selection walks outgoing tips, tag targets, trees and blobs, hiding
  ancestry known to be remote with `with_hidden()` (`with_boundary()` has
  different semantics); tree and blob exclusion is accounted separately;
  unknown remote tips are not assumed present. Objects the remote already
  has may be sent; objects it needs may not be missing. Replacement objects
  are disabled, gitlink targets skipped, shallow and promisor repositories
  rejected. Missing or corrupt objects are errors, never the pack pipeline's
  invalid-entry sentinel.
- Memory: object-ID sets, per-object compression buffers and worker queues
  are bounded and measured; streaming does not make memory constant.
- Outcomes are distinguished: local rejection, remote rejection, partial
  success, accepted with failed local bookkeeping, and unknown (dropped
  connection). Duplicate, missing or unexpected status entries are errors.
  SSH exit status alone never means success.

Command contract: `gix [-r PATH] push [--dry-run] [--delete] [--set-upstream]
[--force-with-lease=<ref>:<oid>]… [REMOTE] [REFSPEC…]`. REMOTE is a
configured name or an SSH URL. Defaults follow `push.default=simple`, with
`current`, `upstream` and `nothing` handled and other modes rejected; a
detached HEAD needs an explicit refspec.

| Invocation | Behaviour |
| --- | --- |
| `gix push` / `gix push origin` | Current branch by the supported defaults |
| `gix push origin main` | Same-name branch |
| `gix push origin main:review` | Explicit destination; several refspecs and fully qualified refs accepted |
| `gix push origin refs/tags/v1:refs/tags/v1` | Exact tag object; replacing a different existing tag needs a lease |
| `gix push --delete origin topic` | Delete; fully qualified tag refs and empty-source refspecs accepted |
| `gix push --force-with-lease=refs/heads/topic:<OID> origin topic` | Rewrite only if the remote still has OID; an empty OID means expected absence |
| `gix push --dry-run origin main:review` | Resolve and show; no commands, pack or local change |
| `gix push --set-upstream origin topic` | Record tracking only after confirmed success |

Branch destinations need commits. If the remote's old commit is not local and
ancestry cannot be proved, require a fetch or a lease. Per-ref results go to
stdout, progress and errors to stderr; success only when every ref succeeds or
is verified unnecessary. `--force`, `+refspec` and mirror, matching or wildcard
selection are rejected. Direct URL pushes never invent a remote name.

## 6. Packaging, tests and gates

- `src/toolchain-versions.sh` gains `GIX_REPOSITORY/REF/REV`, validated in
  `src/toolchain-lib.sh`; the REV is the identity and the REF a fetch hint.
  Assembly inputs also carry the lockfile digest, feature recipe and profile.
- `src/toolchain-gix.sh`, sourced by `src/build-motor-os.sh` like the
  rust-analyzer helper: `toolchain_managed_checkout`, a keyed target
  directory, an explicit dependency fetch, then a `--locked --offline` build
  of `-p gitoxide --bin gix` with the assembly linker; host build scripts and
  proc macros stay on the host target. Version metadata is deterministic and
  runs no guest Git.
- Stage only the executable, licences and a short version/feature/limits
  record under `gix/devtools`. `src/toolchain-assembly.sh` gains the key
  fields and a content-tree digest; bump the assembly key schema so an older
  assembly cannot be reused. Add `gix` to `assembly_dirs` and
  `gix/devtools/bin/gix` to `assembly_required_executables` in
  `motor-os-dev.yaml`; base and main manifests are unchanged.
- The host contract `src/tests/test-toolchain-gix.sh` (source selection,
  exact revision, flags, staging, permissions, tamper detection, key
  invalidation) joins the toolchain list in `full-test.sh`. The guest driver
  `test-gix.sh` runs from the `FULL_TEST_VERIFY_DEV_SOURCES=1` branch after
  SSH is up, with a mode for an already running VM. Regular tests never reach
  the public network.
- Fixture matrix: loose and packed repositories; worktree changes (modes,
  UTF-8 names, same-length edits, symlink text, gitlinks); every porcelain
  command and recovery path against the host oracle; remote acquisition
  (empty remote, bare and worktree clone, selection, shallow, second fetch,
  destination collision, dirty worktree preserved); SSH publication and every
  push failure mode; TLS and protocol errors (bad CA, wrong host, redirect
  loop, 401/404, malformed advertisement, truncated pack, stopped peer);
  limits and lifecycle (just below and above limits, full or read-only disk,
  existing lock); trust sentinels including merge drivers; terminal and pipe
  IO with no leaked children.
- Measurements per milestone: startup, status, diff, log, add and commit,
  switch, merge, clone/fetch, initial and incremental push transfer size,
  peak memory, temporary disk, idle CPU and stripped size, on a small loose
  and a larger packed history. Enable gix's `parallel` feature only after
  serial commands work and the whole-pack buffer cost is measured; audit any
  `parking_lot` backend for idle spinning.
- Per patch: focused host tests, Motor check/link, the relevant guest
  fixture, repository-selected `cargo fmt`, clippy, shell syntax and
  `git diff --check`. Per milestone: `test-toolchain-gix.sh`,
  `test-gix.sh --release`, `full-test.sh`, `full-test.sh --release`,
  `full-test-dev.sh --release`. Developer-image runs stay release-only; ask
  before adding a debug run if a patch touches `src/bin/lorry`. Any `src/sys`
  change is discussed first and passes three debug and three release
  `full-test.sh` runs; std and moto-rt changes are vetted separately. No
  retries, longer timeouts or weakened assertions; preexisting failures are
  diagnosed per `AGENTS.md`.

## 7. External scope, ledger and completion

Product edits happen in `/home/posk/motor-dev/gitoxide-motor-cli` (the D2
branch: root manifest, `src/plumbing`, `gitoxide-core`, `gix-fs`, `gix-index`,
`gix-worktree*`, `gix-status`, `gix-pack`, `gix-transport`, `gix-protocol`,
`gix-motor-tempfile`, tests) and are named in every patch report. Never
author in Cargo caches or managed checkouts. This repository receives
assembly integration, the image manifest, tests and docs. No kernel, std,
moto-rt, mlibc, Lorry or curl change is assumed; if one becomes necessary,
stop and discuss.

Keep a ledger per milestone: fork revision and tree digest, lock digest,
feature recipe, build command, binary digest, gate logs and measured limits.
A milestone is complete when the installed binary passes its gates from the
developer image; a cross-compile alone is not completion. Old assemblies
stay; rollback restores the previous input tuple, schema, manifest and
selection pin together and never rewrites user repositories. Publishing the
fork revision is a separate, explicitly authorised step after the local
patches are reviewed.

## 8. Relation to the combined plan

Removed relative to [jj-gix-workflow.md](jj-gix-workflow.md): the jj platform
port, the Tokio/ctrlc/crossterm alignment, the gix 0.87.1 rebase, jj's
operation store, import/export and reconciliation, jj-side GC and the
cross-tool workflow gate. Added: the eight porcelain commands of M2, which
the upstream CLI does not have. Unchanged: the M1 platform port, the
transports, the send-pack engine, packaging and gates. The largest single
items are the send-pack client and the switch/merge orchestration.

Implementation starts after this plan is reviewed.
