# Tools/commands available in Motor OS

## VM running helpers

After successfully [building Motor OS image](./build.md),
`$MOTORH/motor-os/vm_images/[debug|release]` directory will contain several data files
and several useful scripts:

- `motor-os-base.img` contains the minimal bootable system and user shell tools;
- `motor-os.qcow2` is the standard production image, adding networking, DNS, and
  regular user programs;
- `motor-os-dev.qcow2` adds native toolchains, sources, diagnostics, tests, and
  the bundled sample website;
- `create-tap.sh` creates the local `moto-tap` interface the VMs use for
  networking and the NAT rules that let them reach the Internet; the build runs
  the same steps, so it is needed only after a host reboot;
- `run-qemu.sh` and `run-chv.sh` run the image selected by `MOTO_IMAGE`; it
  defaults to `motor-os.qcow2`. QEMU and Cloud Hypervisor also accept the raw
  base image; Firecracker supports only that raw image.

## Tools available inside the Motor OS VM

This is how `top` looks like:

![top](top.png)

Motor OS boots into a unix-like shell [rush](https://github.com/moturus/rush).
The shell is somewhat barebones now (contributions are welcome!).

- `ls /system/bin` and `ls /user/bin` show the standard commands; the
  development image also places `/devtools/bin` on `PATH`;
- `free`, `kill`, `ping`, `printenv`, `ps`, `ss`, and `top` are worth mentioning;
- `ping [-c COUNT] [-i SECONDS] [-W SECONDS] [-s BYTES] DESTINATION` supports
  numeric IPv4 and IPv6 addresses, `localhost`, and DNS names;
- On the development image, `/devtools/tests/systest`,
  `/devtools/tests/mio-test`, and `/devtools/tests/tokio-tests` are useful to
  make sure everything is working as expected;
- `/system/logs` contains current and rotated service logs. Interactive
  sessions can list and read them, System-role strobe alone creates and rotates
  them, and None-role processes cannot traverse the directory. The unfiltered
  kernel stream is `/system/logs/kernel.log`; its previous 4 MiB generation is
  `kernel.log.prev`. Strobe applies the same size bound to every tag and removes
  the oldest `.prev` files when free space falls below 50 MiB. Runtime
  diagnostics go to the process's stderr first, including debug records when
  debug logging is configured; for these diagnostics, the kernel log is a
  capability-gated fallback when that write fails;
- `/devtools/bin/mdbg print-stacks $PID`, where `$PID` can be deduced by running `ps`, will
  (attempt) to extract stack traces for all threads in the process; the stack traces
  are addresses, so `addr2line` will need to be used with the binary
  (e.g. `$MOTORH/motor-os/build/obj/sys-io/x86_64-unknown-motor/debug/sys-io`);
  - stack traces reaching into the VDSO object will be marked as so, and can be symbolized
  using `addr2line` applied to `$MOTORH/motor-os/build/obj/vdso/x86_64-unknown-motor/debug/rt`.

![ps -H](ps.png)

## Git on the developer image

The developer image includes `gix` in `/devtools/bin`. Its initial command set
can initialize or clone an ordinary SHA-1 worktree, update a configured remote,
inspect changes, stage local files, commit the index, switch branches, merge
commits, and publish one branch or tag over SSH:

```sh
gix init scratch
gix clone https://example.test/project.git project
gix clone ssh://git@example.test/project.git ssh-project
gix -r project status
gix -r project diff
gix -r project diff --staged src/main.rs
gix -r project add src/main.rs
gix -r project add -A
gix -r project unstage src/main.rs
gix -r project restore src/main.rs
gix -r project commit -m 'Describe the change'
gix -r project branch list
gix -r project branch create topic HEAD^
gix -r project switch topic
gix -r project merge main
gix -r project tag list
gix -r project tag create snapshot
gix -r project log
gix -r project fetch            # fetches origin
gix -r project fetch upstream
gix -r ssh-project push --dry-run origin HEAD:refs/heads/topic
gix -r ssh-project push origin HEAD:refs/heads/topic
```

`init` creates `.git` exclusively while preserving existing files in `DIR`,
which defaults to the current directory. It refuses to reinitialize a
repository. The initial branch is
`init.defaultBranch` when configured and `main` otherwise.

`diff [PATH…]` compares tracked worktree files with the index; `diff --staged`
compares the index with `HEAD` (empty for an unborn branch). Optional paths are
literal and relative to the selected worktree; use `--` before a leading dash.
It prints unified text changes, mode changes, binary summaries and opaque gitlink
IDs without updating the repository. Selected conflicts are rejected; worktree
conversion also rejects unsupported filters. Inputs are limited to 16 MiB per side
and text to 262,144 lines per side; configured `minimal` is unsupported for text.
Myers and Histogram are supported.

`add PATH…` stages literal paths relative to the selected worktree; use `--`
for names starting with a dash. `add -A` stages all additions, changes and
deletions. Tracked ignored files are included; explicitly naming an ignored
or unmatched path fails. Executable and indexed symlink modes are preserved.
Gitlinks are left unchanged. Staging refuses external filters and files over
16 MiB, and publishes the index only after all selected changes are prepared.

`unstage PATH…` restores the selected index entries from `HEAD`, or removes them
from an unborn branch's index, without changing worktree files. It requires one
or more literal paths, accepts `--` before a name starting with a dash, and
refuses while a merge or another operation is active.

`restore PATH…` replaces selected tracked worktree files with their staged index
contents without changing the index or references. Paths are literal and accept
`--` before a leading dash. It refuses during a merge or another active operation,
and rejects selected conflicts and unsafe filesystem or filter obstructions.
Gitlinks remain unchanged; blobs are limited to 16 MiB. An I/O error or cancellation
may leave selected files changed or missing. After addressing the cause, rerun
the command to restore them from the unchanged index.

`commit -m MSG` commits the staged index to the attached local branch, including
an unborn branch's first commit. It rejects unresolved entries. Outside a ready
merge, it also rejects an unchanged index. Author and committer name and email must
be configured; `user.name` and `user.email` provide both by default.

`branch list` and `tag list` print short names in sorted order. Creation takes
a name and optional `REV`, which defaults to `HEAD`, and refuses to replace an
existing reference. Branch targets are peeled to commits; lightweight tags retain
the exact selected object. These commands do not change the checkout, index or
worktree.

`switch BRANCH` selects an existing local branch. It requires the index to match
`HEAD` and the tracked worktree to be clean, and refuses untracked or ignored
obstructions. It preserves unchanged files and leaves both branches' IDs intact.

`merge REV` integrates a commit into the current attached local branch. It
requires the index to match `HEAD` and the tracked worktree to be clean. An
ancestor target is up to date, a descendant target fast-forwards, and a clean
divergent result creates a two-parent merge commit. Divergent authoring requires
configured author and committer identity.

Only unresolved same-path regular-text conflicts are installed; other unresolved
kinds fail before worktree changes. Supported conflicts leave conflict markers in
the worktree, index stages, `MERGE_HEAD`, `MERGE_MSG`, and a ready operation.
Resolve them, run `add`, then `commit -m MSG`, or run `merge --abort`. Abort
explicitly discards merge work, all staged changes and affected worktree edits;
it preserves unrelated unstaged, untracked and ignored files.

An incomplete operation is reported by `status` and blocks other mutations.
After addressing the error, run `recover`. It restores the recorded original
state, or preserves an already-published update and finishes cleanup. If a merge
commit did not publish, recovery keeps the staged resolutions and makes the
merge ready to commit or abort.
Restoration discards affected worktree changes and staged changes, preserves
unrelated unstaged, untracked and ignored files, and refuses unsafe obstructions.
Recovery leaves the record on failure so it can be invoked again. It never removes
another writer's Git lockfile; remove a stale lock manually only after verifying
that no writer remains. Power-loss recovery is not guaranteed.

Reference reads on Motor reject loose reference files larger than 8 MiB.

`fetch` updates remote-tracking references and tags without changing the current
branch, index or worktree. HTTPS uses the system CA bundle. A test or private CA
can be selected explicitly with
`gix -c http.sslCAInfo=/path/to/ca.pem clone URL DIR`; repository configuration
cannot disable certificate verification or replace the trust roots.

SSH clone/fetch/push uses the existing default key
`/user/cfg/ssh/id_ed25519` and `/user/cfg/ssh/known_hosts`. Set them up with the
SSH tools first: gix uses batch mode, requires an already trusted host and never
prompts. SSH URLs and scp-style `user@host:path` addresses are supported. Each
session allows 8 MiB of discovery data, 128 MiB of total response data and
64 KiB of stderr, with a 30-second connection timeout and a 300-second session
limit. Cancellation terminates and reaps the SSH child.

`push [--dry-run] [--force-with-lease=DESTINATION:OID] REMOTE SOURCE:DESTINATION`
updates exactly one branch or tag over SSH. Name the remote explicitly; its push
URL is used when configured. SOURCE is a local ref, HEAD or a full SHA-1 object
ID; DESTINATION must start with `refs/heads/` or `refs/tags/`. Branches require
commit objects. Creating a ref or fast-forwarding a branch needs no lease;
rewriting a branch or replacing a tag requires the exact advertised old ID in
`--force-with-lease`. An empty lease OID requires the destination to be absent.
A supplied lease is checked even for a no-op. Dry-run checks remote state and
update policy without sending an update. Push leaves local tracking refs and
configuration unchanged; fetch separately to refresh them.

Push prepares its pack before sending the update. The current limits allow
65,536 outgoing objects, 65,536 reachable commits, 16 MiB per decoded object
and a 128 MiB temporary pack. Packs contain full objects without delta
compression, so an initial push can send more data than Git. If the result is
reported as unknown, inspect the remote ref before pushing again; gix never
retries automatically. A confirmed remote acceptance remains reported if
command completion later fails.

Clone creates `DIR` exclusively and never adopts an existing directory.
A failed clone retains its owned directory for inspection; the
`.git/gix-incomplete-clone` marker identifies unfinished fetch or checkout.
Remove that owned directory explicitly before cloning again. Repository paths
must be UTF-8 and valid Motor file names; the current path policy also rejects
Windows-reserved names and characters. Because Motor OS has no symbolic links,
link entries are checked out as regular files containing their target text.
Authenticated HTTPS and HTTPS push are not yet supported.

For more details, see [https://motor-os.org](https://motor-os.org).
