# gix and Jujutsu on Motor OS

Plan, 2026-09-11. Supersedes the separate gix, jj and push plans. Follows the
root `AGENTS.md`: 100–300-line patches with tests, no commits unless asked,
external source edits called out in every patch report. No code has changed.

## 1. Goal

Ship `/devtools/bin/gix` and `/devtools/bin/jj` in the developer image so a
Motor developer can acquire a repository, inspect history, author and rewrite
commits, manage bookmarks and tags, merge and resolve conflicts, fetch, recover
from mistakes, and publish over SSH. gix is the repository plumbing and the
Git-ref publisher; jj is the authoring workflow. Neither installs a `git`
executable or alias, parses the other's output, or promises compatibility with
programs that run `git`.

| Workflow | Provided by |
| --- | --- |
| Acquire | `jj git clone`, `gix clone`/`fetch`: anonymous HTTPS (M1/M2), SSH (M3); token HTTPS and local paths (M4). |
| Inspect | jj log/diff/show/file, revsets, templates; gix object, ref, index and pack inspection, status, blame. |
| Author | jj snapshot, commit/describe/new/edit, bookmarks, tags, ignores, executable files, restore. |
| Integrate | Fetch, then an explicit rebase or merge; conflicts, split/squash/revert/abandon. |
| Interoperate | Colocated and non-colocated repositories; Git import/export; host Git reads Motor-created objects unchanged. |
| Recover | Operation log, undo/restore, recovery after an interrupted operation. |
| Publish | `gix push` and `jj git push` over SSH through one shared engine, with per-ref results. |

Out of scope for every milestone: Git linked worktrees, submodule operations
(gitlink entries are preserved, never fetched or expanded), LFS, credential
helpers, hooks, external filters and signing, proxies, Watchman, the built-in
pager, `ein`, `tix` and the SQLite corpus tools. A required filter fails before
checkout writes anything. Excluded commands return an actionable error; they
never panic or silently skip.

## 2. Decisions

Proposed 2026-09-11; review confirms or changes them before implementation.

- **D1 Milestones.** Four shippable milestones (section 4), each ending in an
  assembly candidate that passes its gates. Later milestones extend earlier
  ones; nothing already shipped is redefined.
- **D2 One fork revision.** Rebase the Motor port commit
  `4604ac322369a2e429a805cf6e5b7267712283f1` ("A minimal port to Motor OS",
  gix 0.86.0) onto the upstream commit for gix 0.87.1, jj's requirement, on a
  new `gix-moturus-cli` branch of `moturus/gitoxide`. All gix and jj work uses
  that one revision from the first patch. Lorry's pin is unchanged.
- **D3 Architecture.** jj's Git subprocess boundary (`lib/src/git_subprocess.rs`)
  is replaced on Motor by direct gix library calls; upstream subprocess
  behaviour stays on other platforms. `gix push` and `jj git push` call one
  send-pack engine in the fork. No C Git port, libgit2, or Git CLI emulation.
- **D4 Transports.** HTTPS through the existing `/system/bin/curl` child and
  SSH through `/user/bin/ssh`, both via `std::process::Command` with explicit
  arguments, never shell strings. Token HTTPS passes the secret through the
  child environment with curl's `--variable %NAME` and `--expand-header`;
  argv, URLs and logs never carry it. Local-path clone is an in-process copy
  transport, not a spawned `git-upload-pack`.
- **D5 Working tree.** `core.symlinks=false`: link target text as an ordinary
  file, symlink mode kept in the index. The executable bit maps to `moto_rt::fs`
  permissions and files stay editable. Status uses conservative invalidation,
  not invented inode or ctime semantics.
- **D6 Trust.** No helper, filter, hook, signing tool or installed-Git
  discovery executes from configuration. The fork's `gix-sec` ownership check
  returning `Ok(true)` on Motor is not treated as trust to execute anything.
- **D7 Panic.** Both binaries build with an explicit `panic = "abort"` profile,
  overriding the [Motor target's unwind default](../toolchain.md#rust-runtime-and-native-formatting).
  Errors and cancellation use ordinary returns and RAII; jj's `catch_unwind`
  uses are audited.
- **D8 GC.** `jj util gc` and gix repacking return an unsupported error until
  M4. Native garbage collection gets its own plan; push does not depend on it.
- **D9 Interactive selection.** Descriptions, conflicts and hunk selection use
  an external editor (Red or Helix) first; the crossterm/scm-record selector is M4.
- **D10 Push policy.** SHA-1 repositories. gix creates and fast-forwards by
  default and needs an explicit per-ref lease to rewrite; jj keeps its guarded
  rewrite with expected old targets. Both send old and new IDs so the server
  also detects races. `report-status` is required; tracking advances only on a
  confirmed result; an unknown outcome is never retried automatically.
- **D11 Distribution.** Each tool is a managed assembly component with a
  sourced producer helper, following `src/toolchain-rust-analyzer.sh`, installed
  only in the developer image. Rust and LLVM pins do not move.

## 3. Verified baseline (2026-09-11)

| Source | Identity |
| --- | --- |
| Motor OS | `be8dd555`, branch `frusa`; toolchain `1.99.0-beta-f47d5bb-motor.dev.1` |
| Motor gitoxide fork | `4604ac322369a2e429a805cf6e5b7267712283f1`: gix 0.86.0, gitoxide 0.56.0, gitoxide-core 0.60.0 |
| Upstream gitoxide | `766543702cbf39d1c466de58fcefaed78c91af75` |
| Upstream jj | `a4a61b3916f2a46eb3fb9f49b4e9021f26fdc893`, 0.45.1: gix 0.87.1, Rust 1.89, Tokio 1.52.3, crossterm 0.29, ctrlc 3.5.2, tempfile 3.27.0, mimalloc |

Facts the plan relies on, checked in source:

- jj spawns `git` for fetch, push (`--porcelain --no-verify`, per-ref
  `--force-with-lease`), branch pruning, `remote show` default-branch lookup
  and worktrees; `GitBackend::gc()` runs `git gc`. There is no in-process
  fallback.
- gitoxide has no send-pack client: `crate-status.md` lists push, send-pack
  plumbing and report-status unchecked, and `gix/src/push.rs` holds only the
  `push.default` enum. Fetch, `handshake()` with a `Service` parameter,
  legacy ref parsing, packet-line IO, `RequestWriter::into_parts()`, object
  traversal and pack writing exist.
- The fork's SSH launcher adds `-o SendEnv=GIT_PROTOCOL` unless the protocol
  is V1. Motor's ssh rejects any unknown `-o` key and supports
  `StrictHostKeyChecking`, `BatchMode`, `-i` and `-p`. russhd's client
  separates stderr, sends EOF and returns the remote exit status; its
  `client_protocol` test proves large output is drained while stdin blocks.
- In the fork: `gix-sec` ownership is `Ok(true)` on Motor; `gix-fs` has no
  Motor `Capabilities` default and its non-Unix executable probe returns
  false; `gix-index` loading still uses `memmap2` and `filetime`;
  `gix/src/lib.rs` exports a Motor `strlen`; `gix-motor-tempfile` and a clone
  transport factory exist; `gitoxide-core` unconditionally enables worktree,
  status, interrupt and credentials features and uses `open::that` and
  `tempfile`. `src/gix.rs` needs the `pretty-cli` feature.
- Motor std: symlink, hard link and `set_times` are unsupported; file locks,
  metadata, rename and permissions work. `moto_rt` provides
  `ctrl_c_register_handler`/`ctrl_c_wait`, `set_perm`/`set_file_perm` and
  `FileAttr::entry_id`. The base target sets `PanicStrategy::Abort`.
- Motor curl accepts `--header`, `--data-binary @-` (body from stdin),
  `--cacert`, `--proto`, `--location`, `--max-time`, `--write-out`,
  `--variable %NAME` and `--expand-header`; it has no `--user`, `-K` or netrc.
  Lorry's `src/bin/lorry/src/git/http.rs` implements gix's blocking `Http`
  trait on it and is coupled to Lorry policy, so it is a reference, not a
  shared library.
- `src/imager/motor-os-dev.yaml` lists assembly roots in `assembly_dirs` and
  `assembly_required_executables`; `full-test.sh` runs guest developer checks
  under `FULL_TEST_VERIFY_DEV_SOURCES=1` and asserts the main image has no
  `/devtools`.
- A host experiment pushed with Git 2.53 through the host-built Motor `ssh`
  to the host-built `russhd` running host `git-receive-pack`: an 8 MiB initial
  push, fast-forward, annotated tag, stale-lease rejection, leased rewrite,
  delete, mixed hook rejection and `git fsck --strict` all passed. This proves
  the transport, not a native client. The disposable harness is recreated as
  repository fixtures in M3.

## 4. Milestones

Every step is a group of 100–300-line patches with tests. Fork and jj edits are
external (section 7). A step's gate passes before the next step starts; a
successful `cargo check` is never evidence of runtime support.

### M1 — gix CLI: local repositories and anonymous HTTPS

1. **Baseline and oracle.** Create the `gix-moturus-cli` branch (D2): rebase
   the port commit onto upstream gix 0.87.1 and record both revisions and the
   tree digest. Build the pinned Linux `gix` (`-p gitoxide --bin gix`) as the
   behavioural oracle and capture help for every acceptance command
   (repository selection is `gix -r PATH`). Inventory the target dependency
   graph separately from host build scripts and proc macros. Provision
   dependencies once, then build `--locked --offline`. Record the first
   `cargo check --target x86_64-unknown-motor -p gitoxide --bin gix
   --no-default-features --features pretty-cli,sha1` diagnostics.
2. **CLI shell.** Add a `motor-cli` feature recipe: `small` pulls the line
   renderer and crossterm, `max` pulls libcurl, OpenSSL and the TUI, so
   neither is the recipe. Keep clap and plain stderr progress; replace
   `terminal_size`, `is-terminal` and `crosstermion` uses with
   `std::io::IsTerminal` or gate a command together with its dependency
   (`open::that` in graph display, `tempfile` in core pack paths).
   Deterministic version identity instead of `build.rs` `git describe`.
   Motor `panic = "abort"` profile (D7). Stream stdout; test broken pipes.
3. **Filesystem and worktree.** Motor `Capabilities` defaults and a real
   executable-bit probe in `gix-fs`; replace `memmap2`/`filetime` in
   `gix-index` and any commit-graph or status path the CLI reaches with the
   fork's owned-buffer pattern, fallible allocation and checked lengths; map
   `100644`/`100755` to `moto_rt::fs` permissions and verify both execution
   and editability; conservative status cache tested with same-size rapid
   edits, permission-only changes and a host-imported index;
   `core.symlinks=false` checkout (D5); gitlinks stay gitlinks. Extend
   `gix-motor-tempfile` only as core needs: exclusive creation, private
   permissions, same-filesystem rename, no check-then-overwrite. Keep Git
   `.lock` files; never remove another process's lock; keep previous refs
   readable after a failed fetch. Reject unrepresentable names before writing;
   keep traversal and `.git` injection protections; test malicious trees and
   colliding names.
4. **Configuration, processes, cancellation.** Route every repository open
   through one CLI policy: no installed-Git configuration probing
   (`gitoxide-core/src/repository/clone.rs` enables `git_binary`), no helper,
   filter, hook or signing execution (D6). Precedence is `-c`, repository
   data, explicit user configuration, supported environment; resolve the user
   configuration path from Motor's home conventions and report it via
   `gix env`. Replace `signal-hook` with `moto_rt::process::ctrl_c_*` driving
   gix's interrupt flag without consuming stdin; cancellation stops transfer,
   pack and checkout work, kills and reaps children, releases this process's
   locks and exits 130. First link with the assembly linker: raw and stripped
   ELF are `DYN` with no interpreter, `NEEDED`, TLS segment, executable stack
   or unresolved symbols; reconcile the `strlen` export with the linked
   runtime rather than adding stubs.
5. **HTTPS transport.** A Motor backend in `gix-transport`'s blocking HTTP
   module behind a feature, selected by `gitoxide-core` for clone, fetch and
   remote-ref listing alike. Implement `Http` over the curl child: bounded
   pipes and staging, typed response metadata, CA
   `/system/cfg/ssl/ca-certificates.crt` with an explicit override for
   fixtures, hostname verification, same-origin redirects with a hop limit and
   no downgrade, 401/403/404 recognised before the pack parser, no userinfo or
   proxies. Bound bytes, disk, duration and decompressed memory; record the
   first measured limits in this document. No retries.
6. **Fixtures, packaging, gates.** `src/tests/test-gix.sh` with fixed
   identities and timestamps, isolated HOME/XDG/temp, loopback-only servers and
   host Git as the oracle (`upload-pack --stateless-rpc` behind the existing
   curl TLS fixture, `git fsck` on repositories copied back). Cover the matrix
   in section 6, package per section 6, wire the gates, measure.

Gate: the installed `gix` inspects, clones and fetches deterministic fixtures
in the VM without any Git executable; hostile-configuration sentinels never
run; Ctrl+C is clean; the assembly rebuilds reproducibly.

### M2 — jj: local authoring, fetch and clone

1. **Dependency contract.** Pin the inspected jj revision in an external
   checkout. Patch the whole `gix-*` closure to the D2 revision; keep CLI-only
   crates out of jj's target graph. Align Tokio, ctrlc and crossterm with the
   existing Motor forks; audit every selected `getrandom` version; keep
   `mimalloc` out of the Motor build. Record the first
   `cargo check -p jj-cli --bin jj --no-default-features --features git
   --target x86_64-unknown-motor` diagnostics. Enumerate every reachable guest
   `git` invocation and classify it: replaced, unsupported error, or M4.
2. **Platform boundary.** Motor arms in `core/src/file_util.rs`, `lib/src/lock`
   and `lib/src/local_working_copy.rs`: lossless paths, `entry_id` identity,
   std file locks for jj's advisory state locks (distinct from Git `.lock`
   files), exclusive same-filesystem temporary publication with sync ordering,
   jj's `NamedTempFile` reopen/keep/persist needs, the non-symlink working
   copy consistent with D5, editable executables, config/home/temp discovery,
   timezone, terminal size, and Ctrl+C shared with gix cancellation. No
   boot-time work.
3. **Local authoring.** `jj git init --no-colocate` and attaching to existing
   repositories; snapshot, commit/describe/new/edit, ignores, bookmarks and
   tags, revsets, merges, conflicts, rebase, squash/split, revert/abandon,
   operation-log undo/restore, recovery after interruption, concurrent
   invocations. External editor for descriptions, conflicts and hunk selection
   (D9). Colocated repositories and Git import/export verified against host
   Git, including index, HEAD, tags, modes and symlink text. Linked-worktree
   and submodule commands fail explicitly.
4. **Fetch and clone.** Implement jj's Git-operation boundary on Motor with
   typed gix fetch and ref results plus progress and cancellation callbacks;
   keep `GitFetch`/`import_refs()` transaction logic. Cover refspecs, branch
   and tag selection, shallow/deepen, rejected updates, pruning from
   advertisement diffs, the remote default branch from the advertisement, and
   bookmark tracking. `jj git clone` uses the same backend; objects and Git
   refs publish before import, and a failed import reports the durable state
   with a tested recovery path. Push and `jj util gc` return unsupported
   errors (D8).
5. **Fixtures, packaging, gates.** `src/tests/test-jj.sh` reusing the M1
   HTTPS fixture plus jj assertions: dirty and conflicted working copies
   survive fetch, exports pass `git fsck`, a sentinel `git` records unexpected
   launches. Package per section 6.

Gate: the edit/commit/branch/merge/conflict/rewrite/recover scenario, an
HTTPS clone and a second fetch after a host-side update pass in the VM.

### M3 — SSH: shared push engine, `gix push`, `jj git push`, SSH fetch

Design in section 5. Each step first passes a host slice against loopback host
Git through the host-built Motor `ssh` and `russhd`, then the same slice in
the VM.

1. **SSH adapter** in the fork's `gix-transport` ssh module: the Motor
   argument set (`-i`, `-p`, `-o StrictHostKeyChecking=…`, `-o BatchMode=yes`,
   no PTY), protocol V1 so `SendEnv` is never passed, a quoted remote path,
   bidirectional binary pipes with a stderr drain, cancellation, and child
   completion with exit status. Serves upload-pack (SSH fetch and clone for
   both tools) and receive-pack.
2. **Strict pack producer.** The exact outgoing object set from gix traversal
   and `gix-pack` output (`Entry::from_data`, `iter_from_counts`,
   `FromEntriesIter`): non-thin, base objects where no delta can be reused,
   `ofs-delta` only if advertised. Verified with host `index-pack` and `fsck`.
3. **Single-ref protocol.** Command list with capabilities, flush, raw PACK
   bytes through `into_parts()`, `report-status` parsing, create/update/delete,
   leases, the empty-pack and all-delete cases.
4. **`gix push` command.** The contract in section 5.3, with standalone
   fixtures containing no `.jj` and no `jj` executable.
5. **jj integration.** Replace the `push_updates()` subprocess path on Motor
   with typed per-ref results; keep tag IDs, guarded rewrites, no-op rules,
   dry-run and `unexported_bookmarks` reporting.
6. **Workflow gate.** `src/tests/test-git-workflows.sh`: jj author and export
   then `gix push`; `jj git push` then gix inspect and fetch; jj reconciles
   tracking changed by gix; tags; rejections; a concurrent remote change; a
   server hook; truncated reports; large stderr; broken pipes; cancellation;
   local update failure. Prove incremental pushes send only new objects and
   record transfer size, CPU, memory and temporary disk.

Gate: both installed commands publish to a host receive-pack over SSH from
the VM with accurate per-ref results, and every M1 and M2 gate still passes.

### M4 — extensions, each a separately reviewed slice

Token HTTPS (D4 mechanism, origin-bound, redaction fixtures); local-path
clone; native GC honouring jj's operation store and `refs/jj/keep/` (own
plan); sideband and report-status-v2; push-options and atomic push; HTTPS
push; `git://` with a local daemon fixture only; SHA-256 with an
interoperability fixture; the scm-record selector; native builds through
Lorry.

## 5. Push engine

### 5.1 Layering

The fork owns discovery, object selection, pack production, SSH IO and remote
status behind a typed API of Git ref names and object IDs, with no jj types or
CLI text. Policy sits above it:

| Policy | `gix push` | `jj git push` |
| --- | --- | --- |
| Sources | Git refs and objects of a bare or working-directory repository | jj-selected bookmarks and tags with their materialised Git objects |
| Rewrite | Refused unless `--force-with-lease=<ref>:<oid>` matches the advertisement | Allowed under jj's expected old target, keeping its no-op and already-deleted rules |
| Validation | Ref names, object types, refspecs, supported push configuration | jj's conflict, private-commit and description checks; dry-run |
| Bookkeeping | Remote-tracking refs and reflogs; `--set-upstream` after confirmed success | Git tracking plus jj view and operation state through existing jj code |

Both callers put the old and new IDs in every update command. Push URLs and
URL rewriting resolve through gix's push direction; more than one push
destination is rejected before publication.

### 5.2 Wire rules

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
  unknown remote tips are not assumed present. Extra reachable objects are
  acceptable; missing objects or private jj history are not. Replacement
  objects are disabled, gitlink targets skipped, shallow and promisor
  repositories rejected. Missing or corrupt objects are errors, never the pack
  pipeline's invalid-entry sentinel.
- Memory: object-ID sets, per-object compression buffers and worker queues are
  bounded and measured; streaming does not make memory constant.
- Outcomes are distinguished: local rejection, remote rejection, partial
  success, accepted with failed local bookkeeping, and unknown (dropped
  connection). Duplicate, missing or unexpected status entries are errors.
  SSH exit status alone never means success.

### 5.3 `gix push` contract

`gix [-r PATH] push [--dry-run] [--delete] [--set-upstream]
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

## 6. Packaging, tests and gates (both tools)

- `src/toolchain-versions.sh` gains `GIX_REPOSITORY/REF/REV` and
  `JJ_REPOSITORY/REF/REV`, validated in `src/toolchain-lib.sh`; the REV is the
  identity and the REF a fetch hint. Assembly inputs also carry the lockfile
  digest, feature recipe and profile.
- `src/toolchain-gix.sh` and `src/toolchain-jj.sh`, sourced by
  `src/build-motor-os.sh` like the rust-analyzer helper: `toolchain_managed_checkout`,
  a keyed target directory, an explicit dependency fetch, then a
  `--locked --offline` build of `-p gitoxide --bin gix` and `-p jj-cli --bin jj`
  with the assembly linker; host build scripts and proc macros stay on the
  host target. Version metadata is deterministic and runs no guest Git or jj.
- Stage only the executable, licences and a short version/feature/limits
  record under `gix/devtools` and `jj/devtools`. `src/toolchain-assembly.sh`
  gains the key fields and content-tree digests; bump the assembly key schema
  so an older assembly cannot be reused. Add `gix` and `jj` to `assembly_dirs`
  and `gix/devtools/bin/gix` and `jj/devtools/bin/jj` to
  `assembly_required_executables` in `motor-os-dev.yaml`; base and main
  manifests are unchanged.
- Host contracts `src/tests/test-toolchain-gix.sh` and `test-toolchain-jj.sh`
  (source selection, exact revision, flags, staging, permissions, tamper
  detection, key invalidation) join the toolchain list in `full-test.sh`.
  Guest drivers `test-gix.sh`, `test-jj.sh` and `test-git-workflows.sh` run
  from the `FULL_TEST_VERIFY_DEV_SOURCES=1` branch after SSH is up, each with
  a mode for an already running VM.
- Fixture matrix: loose and packed repositories; worktree changes (modes,
  UTF-8 names, same-length edits, symlink text, gitlinks); remote acquisition
  (empty remote, bare and worktree clone, selection, shallow, second fetch,
  destination collision, dirty worktree preserved); SSH publication and every
  push failure mode; TLS and protocol errors (bad CA, wrong host, redirect
  loop, 401/404, malformed advertisement, truncated pack, stopped peer);
  limits and lifecycle (just below and above limits, full or read-only disk,
  existing lock); trust sentinels; terminal and pipe IO with no leaked
  children. Regular tests never reach the public network.
- Measurements per milestone: startup, status, log, clone/fetch, initial and
  incremental push transfer size, peak memory, temporary disk, idle CPU and
  stripped size, on a small loose and a larger packed history. Enable gix's
  `parallel` feature only after serial commands work and the whole-pack buffer
  cost is measured; audit any `parking_lot` backend for idle spinning.
- Per patch: focused host tests, Motor check/link, the relevant guest fixture,
  repository-selected `cargo fmt`, clippy, shell syntax and `git diff --check`.
  Per milestone: `test-toolchain-*.sh`, `test-gix.sh`/`test-jj.sh --release`,
  `full-test.sh`, `full-test.sh --release`, `full-test-dev.sh --release`.
  Developer-image runs stay release-only; ask before adding a debug run if a
  patch touches `src/bin/lorry`. Any `src/sys` change is discussed first and
  passes three debug and three release `full-test.sh` runs; std and moto-rt
  changes are vetted separately. No retries, longer timeouts or weakened
  assertions; preexisting failures are diagnosed per `AGENTS.md`.

## 7. External scope, ledger and completion

Product edits happen outside this repository and are named in every patch
report: `/home/posk/motor-dev/gitoxide-motor-cli` (the D2 fork branch: root
manifest, `src/`, `gitoxide-core`, `gix-fs`, `gix-index`, `gix-worktree*`,
`gix-status`, `gix-pack`, `gix-transport`, `gix-protocol`,
`gix-motor-tempfile`, tests) and `/home/posk/motor-dev/jj-motor` (the jj
checkout). Any Tokio, ctrlc or crossterm change names its own authoring path
before editing. Never author in Cargo caches or managed checkouts. This
repository receives assembly integration, image manifests, tests and docs.
No kernel, std, moto-rt, mlibc, Lorry or curl change is assumed; if one
becomes necessary, stop and discuss.

Keep a ledger per milestone: fork and jj revisions and tree digests, lock
digests, feature recipes, build commands, binary digests, gate logs and
measured limits. A milestone is complete when the installed binaries pass
their gates from the developer image; a cross-compile alone is not
completion. Old assemblies stay; rollback restores the previous input tuple,
schema, manifest and selection pin together and never rewrites user
repositories. Publishing fork revisions is a separate, explicitly authorised
step after the local patches are reviewed.

Implementation starts after this plan is reviewed.
