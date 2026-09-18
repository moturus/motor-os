# gix on Motor OS

The developer image includes `gix` at `/devtools/bin/gix`. It supports
ordinary, full SHA-1 repositories using Git's object, index, ref and reflog
formats. Completed repositories can move between Motor OS and host Git.
The command set is deliberately small; there is no `git` alias.

## Getting started

Configure an identity in `~/.gitconfig` or the repository's `.git/config`
before committing or creating a merge commit:

```ini
[user]
    name = Your Name
    email = you@example.test
```

Clone a repository, create a branch, then stage and commit your edits:

```sh
gix clone https://example.test/project.git project
gix -r project branch create topic
gix -r project switch topic
# Edit files in project, then:
gix -r project status
gix -r project add -A
gix -r project diff --staged
gix -r project commit -m 'Describe the change'
```

Use `gix init DIR` for a new repository. It preserves existing worktree
files, refuses reinitialization, and selects `init.defaultBranch` or `main`.
Clone requires a new directory and records the remote as `origin`.

`-r PATH` selects the worktree root and defaults to `.`. Paths passed to
commands are literal and relative to that root; use `--` before names
starting with a dash. Run `gix COMMAND --help` for syntax.

## Commands

| Command | Behavior |
| --- | --- |
| `init [DIR]` | Initialize an ordinary worktree repository. |
| `clone URL DIR` | Clone over anonymous HTTPS or SSH. |
| `fetch [REMOTE]` | Fetch a configured remote, defaulting to `origin`; update tracking refs and tags without changing the current branch or worktree. |
| `status`, `log` | Inspect changes, pending operations and commit history. |
| `diff [--staged] [PATH…]` | Compare worktree to index, or index to HEAD; show text diffs, mode changes and binary summaries. |
| `add PATH…`, `add -A` | Stage selected paths or all additions, changes and deletions; honor ignores for untracked files. |
| `unstage PATH…` | Restore index entries from HEAD without changing files; on an unborn branch, remove them from the index. |
| `restore PATH…` | Discard selected tracked worktree changes using the index; refuse conflicts. |
| `commit -m MSG` | Commit the index to the attached local branch; reject unresolved conflicts and ordinary empty commits. |
| `branch list`, `branch create NAME [REV]` | List or create branches; REV defaults to HEAD and existing names are never replaced. |
| `tag list`, `tag create NAME [REV]` | List or create lightweight tags under the same creation rules. |
| `switch BRANCH` | Switch to an existing local branch with a clean index and tracked worktree. |
| `merge REV`, `merge --abort` | Fast-forward or merge a commit; abort discards merge work. |
| `recover` | Repair a recorded interrupted switch, merge or abort. |
| `push [OPTIONS] REMOTE SOURCE:DESTINATION` | Publish one explicit branch or tag over SSH. |

Fetch, then run `merge origin/BRANCH` to integrate remote changes. Create a
branch, then switch to it to start a topic. To stage a deletion, delete the
file in the shell and run `add` on its path. There is no configuration
editor: edit configuration files or use repeated `-c key=value` options.

## Configuration and remote access

Configuration loads from XDG Git configuration, `~/.gitconfig` (with
includes), repository configuration, and command-line `-c` overrides.
`--config-paths` reports the files used. Fixed filesystem and resource
policies cannot be overridden. `HOME` and `XDG_CONFIG_HOME` select user
configuration locations; `GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE`
are rejected in favor of `-r`.

Hooks, credential helpers, external filters, diff/merge drivers and signing
programs are not run. Operations requiring unsupported filters or drivers
fail explicitly. Transport executables are fixed to `/system/bin/curl`
and `/user/bin/ssh`.

HTTPS supports anonymous clone/fetch with certificate verification and
system trust. For a private CA, supply `-c http.sslCAInfo=/path/to/ca.pem`
explicitly; repository configuration cannot replace trust roots or disable
verification. Authenticated HTTPS, HTTPS push, plain HTTP and local-path
clone are unsupported.

SSH accepts `ssh://git@host/path` and `git@host:path` addresses. Set up
`/user/cfg/ssh/id_ed25519` and `/user/cfg/ssh/known_hosts` with the SSH tools
first. Gix uses batch mode, requires a trusted host and never prompts.

Push takes a configured remote name or an SSH URL. A configured `pushurl`
is used when present. For example, publish the branch from the HTTPS clone
above through SSH:

```sh
gix -r project push --dry-run git@example.test:project.git HEAD:refs/heads/topic
gix -r project push git@example.test:project.git HEAD:refs/heads/topic
```

The source must be a local ref, `HEAD` or a full SHA-1 object ID. The
destination must be under `refs/heads/` or `refs/tags/`; branches require
commit objects. Creation and provable fast-forwards are allowed. A branch
rewrite or tag replacement needs
`--force-with-lease=DESTINATION:OID`, matching the remote's exact old ID.
An empty OID requires the ref to be absent. If the remote commit is missing
locally, fetch first or supply a matching lease. Dry-run checks remote state
and update policy without sending an update. Push does not update local
tracking refs; fetch to refresh them.

There is no implicit destination, multi-ref push, deletion or `--force`.
If a push reports an unknown outcome, inspect the remote ref before trying
again. A confirmed acceptance remains reported even if later cleanup or
output fails. Network operations never retry automatically.

## Merge and recovery

Switch and merge require the index to match HEAD and tracked files to be
clean. They refuse untracked or ignored obstructions. Merge fast-forwards
when possible; a clean divergent merge creates a two-parent commit.
Unrelated histories and unresolved conflicts other than same-path regular
text conflicts are rejected before worktree changes.

Text conflicts leave markers and staged conflict entries. Resolve them,
run `add`, then `commit -m MSG`, or use `merge --abort`. Abort discards merge
work, all staged changes and affected worktree edits, while preserving
unrelated unstaged, untracked and ignored files. `restore` and `unstage`
refuse during a merge.

`status` reports an interrupted operation without repairing it. After
addressing the error, run `recover`. It restores the recorded original
state or preserves an already-published update and finishes cleanup. If a
merge commit did not publish, recovery retains staged resolutions so the
merge can be committed or aborted. Restoration has the same discard policy
as abort. Failed recovery leaves the operation record for another explicit
attempt; a ready merge must be committed or aborted instead.

Recovery does not clear stale Git lockfiles. Remove one manually only
after verifying that no writer remains. The persistent
`.git/gix-operation-lock` is normal and should stay in place. Avoid concurrent
edits during worktree transitions, and finish or recover an operation before
using host Git. Power-loss recovery is not guaranteed.

A failed clone retains its directory with `.git/gix-incomplete-clone`;
inspect it, then remove that directory explicitly before cloning again.
An interrupted `restore` can leave selected files changed or missing;
after addressing the cause, rerun it against the unchanged index. Ctrl+C
exits with status 130; an error does not imply that no changes were made.

## Compatibility and limits

Bare and linked repositories are unsupported. Authoring also rejects shallow,
partial and sparse repositories. Paths must be UTF-8 and use valid Motor file
names; Windows-reserved names and characters are also rejected. Symlinks are checked out as regular
files containing their target text, with their Git mode preserved.
Executable files remain writable. Submodule entries are preserved but
submodule operations and transitions that change them are unsupported.

| Resource | Limit |
| --- | --- |
| Staged file, decoded object or native index | 16 MiB each |
| Diff input | 16 MiB per side; text also limited to 262,144 lines per side |
| Loose reference file | 8 MiB |
| HTTPS response, total SSH response or outgoing push pack | 128 MiB each |
| SSH session | 8 MiB discovery, 64 KiB stderr, 30-second connection timeout, 300-second total deadline |
| Push selection | 65,536 outgoing objects, 65,536 reachable commits, 131,072 parent links, 65,536 changes per tree comparison |

Text diff supports Myers and Histogram; configured `minimal` is unsupported.
Push packs contain full objects without delta compression, so initial pushes
can be larger than Git's. Gix does not garbage-collect or repack repository
storage; loose objects accumulate. Rebase, stash, cherry-pick, amend,
annotated-tag creation, signing and LFS are unsupported.

The application lives in [src/bin/gix](../src/bin/gix). Its component tests
run through [test-gix.sh](../src/tests/test-gix.sh) and the release developer
suite, `src/tests/full-test-dev.sh --release`.
