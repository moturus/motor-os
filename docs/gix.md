# gix: Git on Motor OS

The developer image comes with `gix`, a small Git client, at
`/devtools/bin/gix`. It works with normal Git repositories: a worktree with a
`.git` directory, full history and SHA-1 object names. Gix reads and writes
the same files as Git does, so you can copy a repository between Motor OS and
a machine that has Git and keep working on either side. Just let gix finish
what it is doing before you copy.

Gix has fewer commands than Git, and some of them are stricter than Git's.
The program is always called `gix`; there is no `git` alias.

## Getting started

Gix has to know who you are before it can write a commit. Put your name and
email into `~/.gitconfig`, or into the repository's `.git/config`:

```ini
[user]
    name = Your Name
    email = you@example.test
```

A first session looks like this: clone a repository, start a branch, change
some files, and commit them.

```sh
gix clone https://example.test/project.git
gix -r project checkout -b topic
# Edit files in project, then:
gix -r project status
gix -r project add -A
gix -r project diff --staged
gix -r project commit -m 'Describe the change'
```

`gix clone` makes a new directory named after the repository, as Git does, so
the clone above ends up in `project`. You can give another name after the
URL. The directory must not exist yet. The remote is recorded as `origin`.

To start a repository of your own, run `gix init DIR`. The files already in
DIR are left alone. The first branch is called `main`, or whatever
`init.defaultBranch` says. Gix will not initialize a directory that is
already a repository.

Gix works on the repository in the current directory, which has to be the top
directory of the worktree: gix does not search the parent directories. Use
`-r PATH` to work on a repository somewhere else. File names you pass to a
command are taken literally (no wildcards) and are relative to that top
directory. Put `--` in front of a name that starts with a dash. `gix COMMAND
--help` shows the exact syntax of a command.

## Commands

| Command | What it does |
| --- | --- |
| `init [DIR]` | Create a new repository. |
| `clone URL [DIR]` | Clone over HTTPS or SSH. DIR defaults to the repository name. |
| `fetch [REMOTE]` | Download new commits and tags from a remote, `origin` by default. Your current branch and your files do not change. |
| `status` | Show what has changed, and whether a merge or another operation is unfinished. |
| `log` | Show the history of the current branch. |
| `diff [--staged] [PATH…]` | Show your unstaged changes, or with `--staged` what the next commit will contain. Binary files and mode changes are summarized. |
| `add PATH…`, `add -A` | Stage the named files, or with `-A` every new, changed and deleted file. `-A` skips new files that match an ignore rule; naming such a file yourself is an error. |
| `unstage PATH…` | Take files out of the next commit without touching the files themselves. |
| `restore PATH…` | Throw away your unstaged changes to the named files. |
| `commit -m MSG` | Commit what is staged to the current branch. |
| `branch [-a] [-v]` | List branches. |
| `branch list`, `branch create NAME [REV]` | Print the branch names only, or create a branch without switching to it. |
| `tag list`, `tag create NAME [REV]` | List tags, or create a lightweight tag. |
| `remote [-v]` | List the remotes. |
| `switch BRANCH`, `checkout BRANCH` | Move to another local branch. |
| `checkout [--track] -b NEW [START]` | Create a branch and move to it. |
| `merge REV`, `merge --abort` | Merge a commit into the current branch, or give up on a merge. |
| `recover` | Finish or undo an operation that was interrupted. |
| `push [OPTIONS] REMOTE SOURCE:DESTINATION` | Publish one branch or tag over SSH. |

A few things work differently from Git:

- There is no `pull`. Run `fetch`, then `merge origin/BRANCH`.
- To stage a deleted file, delete it in the shell and then run `add` on its
  name.
- `commit` refuses to make an empty commit, except to conclude a merge, and
  refuses while a merge still has unresolved conflicts.
- `unstage` on a branch that has no commits yet simply removes the files from
  the index.
- `restore` will not touch a file that is in conflict.
- Gix cannot edit configuration for you. Edit the configuration files, or
  pass `-c key=value` as many times as you need. The only thing gix writes to
  `.git/config` itself is the upstream of a branch made with `checkout -b`,
  and it leaves the rest of the file as it found it.

### Branches

`gix branch` prints the same list as `git branch`, with a `*` in front of the
current branch. With `-a` it also lists the remote branches, such as
`remotes/origin/main`. With `-v` every line also shows the short commit ID,
the first line of the commit message, and how the branch compares with its
upstream: `[ahead 2]`, `[behind 1]`, `[ahead 2, behind 1]`, or `[gone]` if the
upstream branch no longer exists. `gix remote` prints the remote names, and
`gix remote -v` adds the URLs used for fetching and pushing, as `git remote
-v` does.

`branch create` and `tag create` take a name and an optional commit, which
defaults to HEAD. They never replace a branch or tag that already exists.

`switch BRANCH` and `checkout BRANCH` do the same thing: they move you to a
local branch that already exists. Both need a clean repository, meaning
nothing staged and no changes to tracked files. `checkout` also prints what
Git prints, for example `Your branch is behind 'origin/main' by 1 commit, and
can be fast-forwarded.`

`checkout -b NEW [START]` creates the branch NEW and moves you to it. START
is where the branch begins; it defaults to HEAD.

- If START is a remote branch such as `origin/main`, it becomes the upstream
  of the new branch, and gix says so.
- With `--track`, START may also be a local branch. `--track` without START
  makes the current branch the upstream.
- If the new branch begins at the commit you are already on, your staged and
  unstaged changes come along, as in Git. This is the usual way to start a
  topic after you have already begun editing.
- If it begins anywhere else, the repository has to be clean first. When gix
  refuses, it does not create the branch either.

## Configuration

Gix reads Git's configuration files in this order: the XDG Git
configuration, `~/.gitconfig` and the files it includes, the repository's
`.git/config`, and finally the `-c key=value` options on the command line.
Run a command with `--config-paths` to see which files were read. `HOME` and
`XDG_CONFIG_HOME` say where your own configuration lives.

Some settings are fixed and no configuration can change them: the ones that
concern the Motor OS filesystem, and the size limits listed below. Gix does
not accept the `GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE` environment
variables; use `-r` instead.

Gix never runs other programs on a repository's behalf. Hooks, credential
helpers, external filters, diff and merge drivers and signing programs are
all ignored. If a repository cannot be handled without one of them, for
example a file that needs an external filter, the command stops with an error
instead of guessing. The only programs gix starts are `/system/bin/curl` for
HTTPS and `/user/bin/ssh` for SSH, and their paths cannot be configured.

## Remotes

### HTTPS

You can clone and fetch over HTTPS without logging in. The server's
certificate is always checked against the system's trusted certificates. If
your server uses a private certificate authority, name it on the command
line:

```sh
gix -c http.sslCAInfo=/path/to/ca.pem clone https://git.example.test/project.git
```

A repository's own configuration cannot replace the trusted certificates or
turn the check off. HTTPS with a login, pushing over HTTPS, plain HTTP, and
cloning from a local path do not work.

### SSH

SSH addresses can be written as `ssh://git@host/path` or as `git@host:path`.
Before you use one, set up your key in `/user/cfg/ssh/id_ed25519` and the
server's key in `/user/cfg/ssh/known_hosts` with the SSH tools. Gix never
asks questions: if the key is missing or the host is unknown, the command
fails.

### Pushing

Push goes over SSH only. You name the remote, by its configured name or by
its SSH URL, and exactly one source and destination. If the remote has a
`pushurl`, gix uses it. For example, to publish a branch from the HTTPS clone
above:

```sh
gix -r project push --dry-run git@example.test:project.git HEAD:refs/heads/topic
gix -r project push git@example.test:project.git HEAD:refs/heads/topic
```

`--dry-run` contacts the server and checks that the push would be allowed,
but changes nothing.

The source is a local branch or tag, `HEAD`, or a full 40-character object
ID. The destination is a full name under `refs/heads/` or `refs/tags/`, and a
branch has to point to a commit.

Gix will create a new branch or tag, and it will fast-forward a branch.
Anything else, such as rewriting a branch or replacing a tag, needs
`--force-with-lease=DESTINATION:OID`, where OID is the commit the remote
branch has right now. This protects you from overwriting work you have not
seen. An empty OID means "only if the destination does not exist yet". A
lease is checked even when there is nothing to push. If gix
cannot tell whether your push is a fast-forward because it does not have the
remote's commit, fetch first, or give a lease.

Push has no default destination, cannot push several branches at once, cannot
delete, and has no plain `--force`. It does not update your `origin/…`
branches either; run `fetch` afterwards.

Gix never repeats a network operation on its own. If a push ends with an
unknown result, look at the branch on the server before you push again. If
the server accepted the push, gix says so even when something goes wrong
afterwards, for instance while cleaning up.

## Merging

Like `switch`, `merge` needs a clean repository: nothing staged and no
changes to tracked files. Both also stop if an untracked or ignored file is
in the way of a file they have to write.

If REV is already part of your branch, there is nothing to do. Otherwise
`merge REV` fast-forwards when it can. If both sides have new commits and
they do not collide, gix creates a merge commit with two parents. Gix refuses
to merge histories that have nothing in common.

If the two sides changed the same lines of a text file, gix writes conflict
markers into the file and marks it as conflicted. Fix the file, run `add` on
it, and then `commit -m MSG`. Or run `merge --abort` to give up. Any other
kind of conflict, for example one side deleting a file that the other
changed, makes gix refuse the merge before it touches your files.

`merge --abort` discards the merge, everything staged, and the changes to the
files the merge touched. It keeps your unstaged changes to other files, and
it keeps untracked and ignored files. `restore` and `unstage` do not work
while a merge is in progress.

## When something goes wrong

If a switch, a merge or an abort is interrupted, by an error or by Ctrl+C,
the repository is left half-way. `gix status` tells you so but does not fix
it, and gix refuses to change the repository any further. Fix whatever caused
the problem (a full disk, for instance), then run `gix recover`.

`recover` normally puts the repository back the way it was before the
interrupted command. If the command had already moved the branch, `recover`
keeps that result and only finishes the cleanup. If a merge commit was not
written, `recover` keeps your staged conflict resolutions, so you can still
commit the merge or abort it. When it has to put files back, it discards the
same things as `merge --abort`. If `recover` itself fails, it keeps its
record of the interrupted command, so you can run it again. A merge that is
waiting for you to resolve conflicts is not a job for `recover`; commit it or
abort it.

A few more things to know:

- `recover` does not remove Git lock files (`*.lock`) left behind by a program
  that crashed. Remove one by hand, and only when you are sure nothing is
  still writing to the repository.
- The file `.git/gix-operation-lock` is always there. It is normal; leave it.
- Do not edit files while gix is switching or merging, and do not use Git on
  the repository until gix has finished or recovered.
- Gix does not promise that a repository survives a power loss in the middle
  of an operation.
- A clone that fails keeps its directory, marked with
  `.git/gix-incomplete-clone`, so that you can look at it. Remove the
  directory yourself before you clone again.
- An interrupted `restore` can leave some of the named files changed or
  missing. Fix the cause and run the same `restore` again.
- Ctrl+C makes gix exit with status 130. When gix reports an error, do not
  assume that nothing was changed; check with `gix status`.

## What gix does not do

- Bare repositories and linked worktrees are not supported. Gix will not
  commit to, merge in or push from a shallow, partial or sparse repository.
- There is no rebase, stash, cherry-pick or amend, no annotated tags, no
  signing and no LFS.
- File names have to be valid UTF-8 and valid Motor OS file names. Names and
  characters that Windows reserves are rejected as well.
- Motor OS has no symbolic links. A symbolic link in a repository is checked
  out as a small regular file that contains the link's target, and it is
  still committed as a symbolic link.
- Executable files stay writable.
- Submodule entries are kept as they are, but gix does not operate on
  submodules and refuses a switch or merge that would change one.
- Text diffs use the Myers or Histogram algorithm. The `minimal` setting is
  not supported.
- Gix sends whole objects when it pushes, without Git's delta compression, so
  the first push of a repository can be larger than Git's.
- Gix never repacks or garbage-collects a repository, so loose objects pile
  up over time.

## Limits

| What | Limit |
| --- | --- |
| Index file | 16 MiB |
| Text diff | 262,144 lines on each side |
| A loose reference file | 8 MiB |
| One HTTPS response, all the data of one SSH session, or one outgoing push pack | 128 MiB each |
| SSH session | 8 MiB for the list of references, 64 KiB of error output, 30 seconds to connect, 300 seconds in total |
| One push | 65,536 objects, 65,536 commits, 131,072 parent links, and 65,536 changes between any two trees |

As in Git, there is no limit on the size of a single file or object. Gix
holds each one in memory in full while it receives, checks out, stages, diffs
or pushes it. What limits the size of a repository are the totals: a pack
file can be at most 128 MiB and hold 65,536 objects, indexing a received pack
can use 512 MiB of buffers in all, and the files of one commit can add up to
128 MiB.

## Source and tests

The program is in [src/bin/gix](../src/bin/gix). Its tests are in
[test-gix.sh](../src/tests/test-gix.sh), which runs them on Linux and inside
a Motor OS VM, and they are part of the release developer suite,
`src/tests/full-test-dev.sh --release`.

### Testing changes to the Gitoxide fork

Gix is built on a fork of Gitoxide. The Motor OS tests cover gix itself and
the way it uses the fork, at the fork revision recorded in `Cargo.lock`. They
do not run the fork's own tests, because those need far more dependencies
than gix does; fetching the dependencies of gix does not download them.

So when you change the fork, run its tests in a checkout of the fork before
you move Motor OS to the new revision. The fork's
`.github/workflows/ci.yml` runs the whole workspace. The commands below are
the ones that matter most for the Motor OS port. Download the fork's
dependencies once with `cargo fetch --locked`, then run:

```sh
cargo test --release --locked --offline -p gix-motor-filetime \
  system_times_are_normalized_and_ordered
cargo test --release --locked --offline -p gix-index --features sha1 --test index \
  an_index_shorter_than_its_checksum_is_rejected
cargo test --release --locked --offline -p gix-features --test features fs::
cargo test --release --locked --offline -p gix-worktree --features sha1 --test worktree \
  stack::attributes::index_mappings_accept_all_regular_file_modes
cargo test --release --locked --offline -p gix-ref --features sha1 --test refs file::store::
cargo test --release --locked --offline -p gix-ref --features sha1 --test refs file::transaction::
cargo test --release --locked --offline -p gix-commitgraph --lib --features sha1 native::tests::
cargo test --release --locked --offline -p gix-pack --lib --features sha1,streaming-input
cargo test --release --locked --offline -p gix-pack --features sha1 --test pack \
  iter::new_from_header::
cargo test --release --locked --offline -p gix-pack --features sha1 --test pack \
  bundle::write_to_directory::
cargo test --release --locked --offline -p gix --test gix \
  --features blocking-network-client,worktree-mutation \
  clone::blocking_io::from_shallow_allowed_by_default
cargo test --release --locked --offline -p gix --test gix \
  --features blocking-network-client,worktree-mutation init::
```

The Motor OS tests still check, on Linux and on Motor OS, that file reads
are limited in size and that a cut-off index is rejected, and they exercise
creating repositories, references, file modes, timestamps, commit graphs and
packs. Two things are tested only in the fork: how it normalizes timestamps,
and the size limit of its commit-graph reader.
