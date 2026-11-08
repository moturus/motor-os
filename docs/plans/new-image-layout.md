# Developing Motor OS on Motor OS: image layout, Lorry as None, native tests

Status: under review, 2026-11-07; v1 is commit 68f70ed4. No code has
changed.

## The workflow this serves

1. The user logs into a Motor OS VM over ssh (Interactive).
2. They start a None shell and rmux in it.
3. They clone the Motor OS repository into `/none/dev/motor-os`.
4. They edit and build. Every build runs as None.
5. They run tests as None, or as Interactive when a test needs more.
6. As Interactive, they install what they built over the image's own tools:
   rush, rmux, sysbox, lorry, and the rest, in `/user/bin` and
   `/user/bin/dev`.

## Principles

**Image layout**

- `/system` holds only what sys-init starts at boot (sys-io, sys-tty, strobe,
  the DNS resolver, russhd) and configuration the user must never change.
  Nothing a user runs by hand lives there.
- `/user/bin` holds every user-callable command; `/user/bin/dev` holds the
  development tools; `/user/cfg` holds their configuration, including the
  files that set `PATH`, which the Interactive user may edit. Everything in
  `/user` can be replaced by Interactive on the live image.
- `/none` holds all source code and test trees. Builds happen there as None.
- Lorry has a `user` repository and cache under `/user/dev/lorry`, which
  None can read but not write, and a `none` repository and cache under
  `/none/dev/lorry`. Both are always used. When both hold the same vendored
  source, the `none` copy wins unless `prefer-user-vendored-sources = true`
  is set in `/user/cfg/lorry.toml`. `lorry fetch` and `lorry vendor` write
  the repository of the role they run as: the `user` one from an Interactive
  shell, the `none` one from a None shell. Everything compiled goes to the
  `none` cache, because every build runs as None; nothing writes the `user`
  cache at runtime.
- None cannot write `/system` or `/user`. On-disk modes enforce it. sys-io
  enforces it too if that costs nothing per write (phase 5).
- The root of every image holds exactly `/system`, `/user`, and `/none`.
  There is no `/devtools` and no `/system/bin`.

**Images**

- Two images are built and shipped: `base` and `standard`. The test-only
  images (`system-tty`, `vsock-test`, `wasm`) and the developer image go away.
- The standard image carries no development tools. The native toolchain
  archive carries them all: the compilers, lorry, gix, mdbg, Helix, sed, lua,
  javy, wasmtime, the doc site, and the host's imager, a Linux binary that
  does not run on Motor OS but can be copied out of the VM. The standard
  image with the archive installed is the complete development environment.
- Archives are identified by version only, never by a git hash.
- All tests run on the standard image, and base tests on the base image.

**Testing**

- A crate's tests are its own: `cargo test` and `lorry test` on Linux,
  `lorry test` on Motor OS. No crate starts a VM or talks to another machine
  from its tests.
- `src/tests/full-native-test.sh` runs every crate's tests on the machine it
  is on. `src/tests/cross-test.sh` runs what needs a host and a guest.
  `src/tests/full-test.sh` runs the host build checks, `full-native-test.sh`
  on Linux, installs the toolchain archive on the standard image, runs
  `cross-test.sh`, and then runs `full-native-test.sh` on the guest over
  ssh. The archive goes in before `cross-test.sh` so that a cross test may
  use the guest's development tools.
- Cross tests exist only for tools with networking built in: ssh and russhd,
  curl, wg, the DNS resolver, httpd, rnetbench, gix, and lorry. Tools without
  networking, such as Helix, rush, rmux, red, and sysbox, have native tests
  only.
- Lorry needs no sandbox beyond None without network. The VM is the
  isolation boundary.

## Where things stand

**Layout.** `/system/bin` holds rush, sysbox, `sh`, 38 Rush wrappers over
sysbox, and `curl`, `rg`, `tar`, `zstd`, `wg`, and `wg-tool`. `/system/bin`
has 707 references in 160 files, 47 of them `#!/system/bin/rush` lines, plus
russhd's `SHELL` constant, `sys-tty.cfg`, rush's own path in `exec.rs`,
Lorry's curl path, and the toolchain's launchers and libc `shells` file.
`/devtools` exists only in the developer and wasm images, with 646 references
in 95 files; it holds the toolchain (`llvm`, `rust`), `helix`, `javy`,
`wasmtime`, `bin`, `tests`, `www`, `src`, and `lorry/{user,none}`. Three paths
are compiled into binaries and need rebuilds, since Motor OS has no symlinks:
clang's `CLANG_CONFIG_FILE_SYSTEM_DIR`, the clang Motor ToolChain's
`<sysroot>/devtools/llvm/include`, and Helix's `HELIX_DEFAULT_RUNTIME`.

**Images.** The standard image has a 256 MiB data partition (227 MB qcow2);
the developer image 16 GiB (1.2 GB qcow2). The tracked source tree is 27 MB.

**The toolchain archive.** `../motor-os-toolchain` builds
`motor-toolchain-<version>.tar.zst` (194 MB) holding `install.sh` and
`images/<overlay>/devtools/…` for the `llvm`, `rustc`, and `rust-analyzer`
overlays. `install.sh` is a Rush script: it removes `/devtools/llvm` and
`/devtools/rust`, copies each overlay's `devtools` tree to `/`, and fixes
modes. The main repo reads the archive from `$MOTORH` and never writes there;
`test-native-toolchain-install.sh` uploads and installs it on the developer
image. The standard image has `tar` and `zstd`, so it can unpack the archive.

**Lorry's repositories and cache.** Lorry distinguishes the *repository*
(`vendor/`) from the *cache* (`cache/`). The repository holds source code:
the crate archives Lorry downloaded from crates.io and the source code it
cloned from Git, each verified by hash before it is stored, plus the
registry index records that describe them. The cache holds what rustc
compiled from that source code: for each dependency crate, its `rlib` and
`rmeta`, its static library and dep-info when it has them, the environment
it was compiled under, and rustc's messages, under a key made from the
compiler, the target, the crate's source code, its dependencies' outputs,
and its build script's output (`cache.rs`). A key that matches is copied
into `target/lorry` instead of compiled. Only dependencies from crates.io
and Git are cached there; path dependencies and the workspace's own crates
build into `target/lorry` only. Repositories are looked up as `local`, then
`user`, then `system`; `system` is read-only, has no Motor default, and
nothing ships one. On Motor each role has its own `user` repository and
cache under `/devtools/lorry/<role>/{vendor,cache}` (`config.rs`,
`role.rs`). The developer image preseeds the Interactive role's repository
with the `sys/lib` dependencies (`build-motor-os.sh`, `fetch_sys_lib_deps`),
and `prepare-dev-image.sh` fills its cache at image build.

**Lorry otherwise.** Runs as Interactive or None, refuses System. Builds are
offline; `fetch` and `vendor` use the built-in curl. The Motor
`Sandbox::apply` prints the warning and does nothing (`sandbox.rs:489`);
`spec.md:1800` makes the warning mandatory. The built-in native tools carry
argument prefixes (`native_tool.rs:72`) that only a real sandbox can enforce.
`lorry test` works natively today: `test-dev-sources.sh` runs it on the
staged `sys/lib` workspace.

**Executable lock.** sys-io locks an executable while a process uses it for
demand paging; a file under 1 MiB is loaded completely at spawn and holds no
lock afterwards (`docs/fs-permissions.md`). Release sizes: rush 707 KB, rmux
571 KB, sysbox 735 KB, red 251 KB (no lock); lorry 9.8 MB, gix 7.4 MB,
russhd 4.3 MB, ssh 4.1 MB, curl 1.4 MB (locked while running).

**Tests.** `full-test.sh` is 1687 lines and sources or runs about 70 scripts.
Host `cargo test` runs for imager, rnetbench, red, rmux, rush, russhd, wg,
wg-peer, sys-init, moto-sys, moto-sdk, frusa, motor-fs, memfs, and the
rust-analyzer crates. Guest tests are mostly host-driven over ssh: `systest`,
one binary with about 90 case files and 31 invocations from `full-test.sh`;
sysbox's utility tests; rush's capability tests; and the developer-image
suite (`full-test-dev.sh`, `test-dev-sources.sh`, `prepare-dev-image.sh`).
Truly cross-system tests exist for ssh and sftp, vsock, DHCP and networking,
UDP fragmentation and WireGuard against host peers, OOM abort, and boot
checks.

## Target image layout

| Path | Holds | Writable by |
|---|---|---|
| `/system/services` | sys-io, sys-init, sys-tty, strobe, dns-resolver, russhd, rt.vdso | System |
| `/system/cfg`, `/system/logs`, `/system/tmp` | as today | System (logs readable by Interactive) |
| `/user/bin` | rush, `sh`, sysbox and its wrappers, curl, rg, tar, zstd, wg, wg-tool, red, rmux, ssh, httpd, httpd-axum, kibim | Interactive |
| `/user/bin/dev` | installed by the toolchain archive: lorry, gix, mdbg, cc, c++, rustc, rustfmt, clippy-driver, rust-analyzer, hx, sed, lua, javy, wasmi, wasmtime, wasmtime-rt, www | Interactive |
| `/user/lib/{llvm,rust,helix,javy,wasmtime,www,imager}` | installed by the toolchain archive: the compiler trees, the Helix runtime, the wasm plugins, the doc site, the host imager | Interactive |
| `/user/dev/lorry` | Lorry's `user` repository (`vendor/`) and cache (`cache/`) | Interactive; readable by None |
| `/user/cfg` | all configuration, including `rush.cfg`, `sshd.toml`, `lorry.toml`, `lorry-workspaces/`, `helix/`, `russhd/`, `ssh/` | Interactive; closed to None |
| `/user/tmp` | Interactive scratch | Interactive; closed to None |
| `/none/dev` | source trees, including `/none/dev/motor-os` | None |
| `/none/dev/lorry` | Lorry's `none` repository (`vendor/`) and cache (`cache/`) | None |
| `/none/cfg`, `/none/tmp` | as today | None |

`PATH` is set in two files the Interactive user may edit, both moved from
`/system/cfg` to `/user/cfg`: `rush.cfg`, which a console shell sources
through `ENV`, and `sshd.toml`, whose `path` russhd gives every ssh session;
`sys-init.cfg` passes russhd the new path, and the host key in `sshd.toml`
becomes Interactive-readable with it. The standard image sets `/user/bin` in
both; the toolchain archive's `install.sh` appends `/user/bin/dev` to both,
and `helix/languages.toml` and the tests' `EXPECTED_PATH` follow. The
compiler trees cannot live inside `/user/bin/dev`:
the `javy` and `wasmtime` directories would collide with the commands of the
same names. clang's `cfg/` stays inside the LLVM tree, because None-role
builds run clang and must read it.

## Design

### Lorry: the parent process and its None children

The Lorry process the user starts keeps the caller's capabilities (System
is still refused). It parses the command, reads `/user/cfg/lorry.toml` and
the workspace approvals, shows reviews, asks for approval, records
decisions, and for `run` and `test` runs the programs it built. It never
runs package code.

The work runs in a child Lorry: `current_exe()` started with a private flag
and an explicit `MOTOR_OS_CAPS`, as rmux starts its server:

| Command | Child's mask |
|---|---|
| `build`, `check`, `clippy`, `metadata`, `tree`, `review`, and the build half of `run` and `test` | `own & (CAP_SPAWN \| CAP_FS_WRITE)`: None, no network |
| `fetch`, `vendor` | own capabilities: the caller's role, with network |
| `fetch`, `vendor` with `--offline` | own capabilities minus `CAP_NET` |

Builds run package code, so they drop to None. `fetch` and `vendor` run
none, so they keep the caller's role: an Interactive `vendor` writes the
`user` repository and a None one the `none` repository. A child refuses to
start if its capabilities do not match its phase, gets the
`TMPDIR` of its role, receives the effective configuration from the parent
over stdin, inherits stdout and stderr, and holds no detach authority, so
nothing it starts outlives it. A `vendor` child fetches and verifies into
its repository and reports the review to the parent, which prompts (or
applies `--accept-all`) and records the decision in the caller's
configuration directory; the child then writes the workspace's `.lorry/`
record. `run` and `test` build in a None child, then the parent runs the
binaries with the caller's capabilities, so a test run from a None shell is
None and one from an Interactive shell is Interactive. That is how step 5 of
the workflow chooses.

**Two repositories, two caches.** Each role keeps a repository and a cache,
as under `/devtools/lorry/<role>` today, at new paths and under Lorry's own
names:

| Name | Repository | Cache | Written by | Read by |
|---|---|---|---|---|
| `user` | `/user/dev/lorry/vendor` | `/user/dev/lorry/cache` | an Interactive `fetch` or `vendor`; image build | every role |
| `none` | `/none/dev/lorry/vendor` | `/none/dev/lorry/cache` | a None `fetch` or `vendor`; every build | every role |

The `system` repository goes. After this plan Lorry's repositories are
`local`, `user`, and `none`, on Linux too, where `none` has no default.
Nothing on the command line chooses where things go:

- **Source code.** `fetch` and `vendor` write the configured
  `repositories.local` when a workspace has one, otherwise the repository of
  the caller's role. Both repositories are always read.
- **Compiled dependencies.** Every build is None, so everything compiled
  goes to the `none` cache. Nothing writes the `user` cache at runtime; it
  holds what the image build put there, as `prepare-dev-image.sh` fills a
  cache today. Both caches are always read.
- **Precedence.** When both repositories hold the same crate archive or Git
  checkout, the `none` copy is used, unless `/user/cfg/lorry.toml` sets
  `prefer-user-vendored-sources = true`. It is `false` when absent:
  development is easier with `none` first, and a deployment that wants
  builds to read only sources None cannot touch turns it on. The caches have
  no such setting: the `none` cache is read before the `user` cache, since
  only the `none` cache is written at runtime.

So the `user` repository changes only through an Interactive `lorry fetch`
or `lorry vendor`, which runs in the caller's role and writes it directly.
Nothing is staged and nothing passes through the parent.

`role.rs` keeps the per-role configuration directories (`/user/cfg` for an
Interactive caller, `/none/cfg` for a None one) and gets the new
repository and cache paths. Linux is unchanged: one process, the Landlock
sandbox.

### The Motor build-script sandbox

`Sandbox::apply` on Motor gives each build script the build mask and fails
unless Lorry's own role is None. The warning goes, and the docs
(`sandbox.rs`, `spec.md:1800`, the README's "Package build-script
security", `design.md:352`) say what None enforces and what it does not:

- **Enforced:** no network; no writes to `/system` or `/user`; no reads of
  `/user/cfg`, `/user/tmp`, `/system/tmp`, or `/system/logs`.
- **Not enforced:** reads of public content; writes to every None-writable
  tree, including other workspaces, `/none/dev/lorry`, and other scripts'
  `OUT_DIR`s; starting any program None may execute.

The `none` repository and cache can be changed by any None process with
`CAP_FS_WRITE`, and so can the approvals a None `vendor` records under
`/none/cfg/lorry-workspaces/`: a build script could approve itself for the
next `vendor`. Both are accepted. A deployment that wants builds to read
only sources None cannot touch sets `prefer-user-vendored-sources = true`
in `/user/cfg/lorry.toml`.

### No native-tool grants

Lorry's native-tool grants go, on Linux as on Motor. Today a build script
may run a compiler or an archiver only if the configuration grants that tool
to its workspace, and Lorry puts arguments such as
`--target=x86_64-unknown-motor` in front of the script's own
(`native_tool.rs`); on Linux the Landlock sandbox enforces the list, and on
Motor nothing can. Cargo has none of this: a script runs whatever program it
finds, and the `cc` crate most scripts use takes the compiler from `CC`,
`TARGET_CC`, or `CC_<target>`, else `cc` from `PATH`. Lorry behaves the same
way. The built-in tool table, the per-workspace tool grants, the argument
prefixes, the tools listed in `vendor`'s review, and the Landlock list of
programs a script may run all go; the sandbox on Linux keeps its filesystem
and network limits. On Motor `cc` and `c++` are the toolchain's launchers in
`/user/bin/dev`, which select the Motor target through clang's configuration
files. Whether a dependency's build script and procedural macros run at all
is still decided in `vendor`'s review, as today.

### User-replaceable tools

Installing a tool is copying it into `/user/bin` or `/user/bin/dev`. sys-io
locks an executable over 1 MiB while a process runs it, so lorry, gix, ssh,
russhd, and curl can be replaced only when idle; rush, rmux, sysbox, and red
are smaller and can be replaced at any time. Nothing in this plan changes
that.

### The session shell

sys-tty and russhd start `/user/bin/rush`. russhd's `SHELL` constant becomes
the configured path; `sys-tty.cfg` names it. Every `#!/system/bin/rush` line
becomes `#!/user/bin/rush`, in the tree, in the toolchain, and in libc's
`shells` file. rush's recognition of its own path (`exec.rs:1261`) follows.
The System console test starts `/user/bin/rush` as System too; that is
acceptable for a test.

### Two images

The developer image, `system-tty`, `vsock-test`, and `wasm` go. What they
provided moves:

- **Development tools:** into the toolchain archive (next section).
- **The System console and the no-IP vsock run:** `cross-test.sh` makes a
  copy of the standard image and edits `/system/cfg/sys-init.cfg` in it
  (`tty:system:…`) with motor-fs's `image-admin` tooling, which the imager
  already uses, and starts the VMM without a network device where the test
  needs that (question 1).
- **The wasm checks at 256 MiB:** the VMM's `MOTO_MEMORY_MIB` on the standard
  image with the archive installed.
- **Staged first-party sources and the preseeded Lorry repository:** the
  test suite uploads the tree and the repository objects it needs (Tests,
  below); a developer clones and runs `lorry vendor`.

The standard image's data partition grows from 256 MiB to 4 GiB to hold an
installed toolchain, sources, and build output; qcow2 is sparse, so the
shipped file grows little. The base image stays at 64 MiB. Boot time is
unchanged: sys-init starts the same services, and partition size does not
affect the boot path.

### The toolchain archive

The native archive gains overlays for every development tool: lorry, gix,
and mdbg from the main repo's build, and Helix, sed, lua, javy, wasmtime,
and the doc site, which `build-motor-os.sh` already stages as overlays.
`install.sh` installs into `/user/bin/dev` and `/user/lib`, replacing the
`llvm` and `rust` trees as it replaces them today. The archive also carries
the imager: the statically linked Linux binary that `make` already installs
beside the images as `vm_images/<profile>/tools/imager` so that it runs on
other Linux hosts. It has never been run on Motor OS, so `install.sh` puts
it at `/user/lib/imager/imager`, off `PATH`, for a developer to `scp` out of
the VM and build images on a host that has no checkout of the repo.

Rebuilding LLVM and rustc takes hours; repackaging must not. The main repo
gets a `make toolchain-archive` target that unpacks
`$MOTORH/motor-toolchain-<version>.tar.zst`, replaces the overlays the main
repo owns with the binaries `make` just built, and writes the result under
`build/`. The packaging logic lives in `../motor-os-toolchain`
(`toolchain_package`), which `build-toolchain.sh` and this target both call.

An archive is identified by its version alone. A repackaged archive keeps
the version of the one it came from and lives only under `build/`; it is
never copied to `$MOTORH` or published. `full-test.sh` installs the
repackaged archive when lorry, gix, or mdbg differ from the ones in
`$MOTORH`'s archive, and the `$MOTORH` archive otherwise; the imager does
not count, since the guest never runs it. Publishing a changed lorry, gix,
mdbg, or imager means a new toolchain release with its patch version
bumped, as any toolchain change does today. The release that
carries this plan is 1.99.1-2. Its `install.sh` installs into the new layout
only; it does not look for or remove `/devtools`.

### None cannot write `/system` or `/user`

**On disk.** The imager rejects any policy rule or exact entry granting None
`w` at or below `/system` or `/user`. Every image is checked to have exactly
`/system`, `/user`, and `/none` at the root.

**In sys-io, last, and only if free.** This waits for the sys-io filesystem
refactoring now in progress, and it is done only if sys-io can tell which
tree an entry is in without walking its parents on every write. If every
write would have to re-trace its parents to find out where the entry lives,
this is not implemented and on-disk modes stay the only enforcement
(question 2, decided after phases 1-4). If it is free, the rules are: sys-io refuses every mutating
request from a None client whose target, or destination parent, lies in
`/system` or `/user`, whatever the entry's mode, including the `/system/tmp`
and `/user/tmp` mounts; no mode change may grant None `w` there; a rename
into those trees cannot carry None `w` along; native `systest` cases prove
each rule.

### Tests

**Rules for crates.** Every crate with a test harness passes `lorry test`
natively on Motor OS from `/none/dev/motor-os`, and `cargo test` and
`lorry test` on Linux where it builds there. Crates that are Motor-only
(kernel, sys-io, sys-tty, rt.vdso, systest, sysbox, mdbg, strobe,
dns-resolver) are tested natively only; kernel tests run inside Motor OS, as
`AGENTS.md` requires. Host-only tests stay `#[cfg(unix)]`, as rush's and
rmux's pty tests are today. No test starts a VM, uses the network beyond
loopback, or assumes a host.

**`full-native-test.sh`.** One script, run on either OS. It walks a fixed
list of crate directories and runs `lorry test` in each (`cargo test` as well
on Linux), stopping at the first failure. When `/user/bin/dev` is installed
it also runs the shell checks of the installed tools: Helix with
rust-analyzer, javy, wasmtime, sed, and lua. On Motor OS it runs as whoever
started it, and `full-test.sh` runs it twice, from a None shell and from an
Interactive one. There is no list of which tests need which role: a test
that needs Interactive authority, such as `/user/tmp` or the Interactive
rows of the filesystem permission tests, checks its own role and passes
without doing anything under a role it cannot use. Most tests work under
both.

**What becomes a crate test.** The host-driven guest tests move into the
crates they test:

- `systest` becomes a test crate run by `lorry test`. Its cases that need no
  host peer become its tests. Cases that need one (vsock, WireGuard, UDP
  fragmentation against a host echo, `--host-cpus`) become small guest-side
  programs that `cross-test.sh` drives.
- sysbox's utility tests (`systest sysbox-tests`) move into the sysbox crate.
- rush's capability tests (`test-rush-script-caps.sh`, `rush-caps-precedence`)
  become rush integration tests under `#[cfg(target_os = "motor")]`.
- rmux's checks that `full-test.sh` runs through ssh today (a pane is a
  terminal to its program, the alternate screen is taken and given back)
  become rmux tests under `#[cfg(target_os = "motor")]`. rmux has no
  networking, so nothing of it stays in `cross-test.sh`.
- The developer-image checks of native compilation become ordinary
  `lorry build` and `lorry test` runs in the checkout.

**`cross-test.sh`.** Boots the guest and runs what needs both machines: ssh
and sftp (client, server, keys, config, terminal size, the TUI acceptance
suite), vsock and its outgoing variant, DHCP and the base-image networking
check, UDP fragmentation and WireGuard against host peers, the existing DNS
and ping checks, rnetbench's stalled-peer tests, OOM abort, boot identity
and console checks, and the System console. Guest-side programs it needs
are cross-compiled on the host and uploaded to `/none/tmp`, as
`full-test.sh` already does for the standard image, so `cross-test.sh` does
not depend on the guest having built anything. It runs after the toolchain
is installed, so a cross test may also use the guest's development tools;
none does today, but a runner that makes `cargo test` drive cross tests on
Motor OS would.

**`full-test.sh`.** In order:

1. The host build checks that need no VM: imager tests,
   `test-vm-image-format.sh`, `test-make-driver.sh`, `test-kloader-image.sh`,
   the size contracts.
2. `full-native-test.sh` on Linux.
3. Boot the standard image, upload the toolchain archive, run its
   `install.sh`, shut down. Every later boot in the run has the development
   tools.
4. `cross-test.sh`, on that image and on the base image.
5. Boot the image again. Upload the tree as a `git ls-files` tar stream over
   ssh into `/none/dev/motor-os`, so uncommitted changes are tested, and the
   Lorry repository objects the crates need into `/user/dev/lorry/vendor`
   (the ssh session is Interactive, so it may write there), so the guest runs
   `lorry vendor --locked --offline --accept-all` and never reaches the
   network. Run `full-native-test.sh` as None, then again as Interactive.

The host produces the repository objects with its own Lorry once per
dependency change, as `fetch_sys_lib_deps` does today for `sys/lib`: a
host-built Lorry runs `fetch --locked` on the workspace with its `user`
repository pointed at a scratch directory, and the objects and index records
it writes there are uploaded. Repository objects are source code and index
records, the same bytes on either machine, and `fetch --locked` takes every
package of the lock whatever platform it is for, so the objects of a host
Lorry serve the guest for every crate in the tree.

**Removed.** Everything that exists only for the developer image or for
driving native tests from the host: `full-test-dev.sh`,
`test-dev-sources.sh`, `prepare-dev-image.sh`, `sys-lib-workspace.sh`,
`test-dev-memory-contract.sh`, `test-external-sources.sh`,
`test-sys-lib-workspace.sh`, `test-system-tty.sh` as a separate-image test,
the Helix, rust-analyzer, and rustfmt native and size scripts,
`test-gix.sh --guest`, the wasm smoke suites in their current form, and the
`systest` plumbing in `full-test.sh`. The javy and wasmtime checks become
native tests, except the comparison of the byte code compiled on the guest
with the host's, which stays in `cross-test.sh`. The Helix checks become
native: Helix has no networking. The two Python tests go: Python is not used
for tests. `test-helix-lsp-ready.py`, which waits for rust-analyzer's
progress messages in Helix's log, becomes the shell check of the installed
Helix that `full-native-test.sh` runs; `test-dev-path-locks.py`, which
checks that the curl and lorry lockfiles match their path dependencies,
becomes a shell host check in step 1. The x86_64 crate's `ci-release.py` is
a dependency's own release script, not a test, and stays.

### Outside the main Motor OS repo

**These changes touch other repositories and need a toolchain release:**

1. `../motor-os-toolchain`: `TOOLS`, `CFG_LLVM`, `CLANG_CONFIG_FILE_SYSTEM_DIR`;
   the cc and c++ launchers and their `#!/system/bin/rush` lines;
   `install.sh`, which must install into `/user/bin/dev` and `/user/lib`;
   `toolchain_package`, which must accept overlays from the main repo and be
   callable for repackaging; the cross sysroot's `devtools/llvm` layout;
   rust-analyzer packaging; libc's `shells` file.
2. The LLVM fork: the clang Motor ToolChain's `devtools/llvm` include path.
   Not yet read; there is no local checkout.
3. The Rust fork and mlibc: not checked. mlibc's `system()` and `popen()` may
   name `/system/bin/sh`. These are expected to be mechanical path changes;
   phases 1e and 3a size them when they are checked.
4. The toolchain release 1.99.1-2, since 1.99.1 installs into `/devtools`.

## Steps

This is refactoring, not development, so patches may be large, and the
full test gate does not run after every step. Each step makes sure that what
it moved or changed builds and that the tests of those components pass. The
full gate, `full-test.sh` in debug and release three times each, runs once
at the end of phase 4 and again after phase 5. Doc-only changes go in their
own patches.

**Phase 1: layout.** The developer image keeps being built through phases
1-3, as the standard layout with the toolchain preinstalled, so that moved
tools can be tested natively before the archive exists.

- 1a. `/devtools/src` → `/none/dev`; `/devtools/lorry/user` →
  `/user/dev/lorry` and `/devtools/lorry/none` → `/none/dev/lorry`, with
  `/user/dev/lorry` readable by None; `role.rs`, the imager,
  `prepare-dev-image.sh`, the docs.
- 1b. `/user/bin/dev` and `/user/lib`: lorry, gix, mdbg, sed, lua, www, the
  doc site, the host imager under `/user/lib/imager`. `rush.cfg` and
  `sshd.toml` → `/user/cfg`, `PATH=/user/bin` in both, `sys-init.cfg`;
  `install.sh` appends `/user/bin/dev` to both.
- 1c. Helix, Javy, Wasmtime, with the Helix rebuild.
- 1d. `/system/bin` → `/user/bin`: sysbox and wrappers, curl, rg, tar, zstd,
  wg, wg-tool; Lorry's curl path.
- 1e. rush → `/user/bin/rush`: shebangs, russhd, sys-tty, `exec.rs`, `sh`.
  `/system/bin` is removed from the imager, the policy, and `PATH`.
- 1f. The imager's root check and its rejection of None `w` under `/system`
  and `/user`.

**Phase 2: Lorry.** (Explicit Lorry work.)

- 2a. The parent and the None build child; builds write the `none` cache.
- 2b. The `none` repository and cache in place of `system`, both always
  read, and `prefer-user-vendored-sources`.
- 2c. The `fetch`/`vendor` child in the caller's role and the approval
  hand-off.
- 2d. `run` and `test` through the parent.
- 2e. The sandbox mask, the warning removed, `spec.md` and the README.
- 2f. Native-tool grants removed on both systems: `native_tool.rs`, the
  built-in tool table, the tool lists in policy rules and in `vendor`'s
  review, the Landlock program list; `spec.md` and the README.

**Phase 3: the toolchain archive.** Before the tests, because the native
suite needs lorry on the standard image.

- 3a. `../motor-os-toolchain`: `install.sh` for the new layout, overlays for
  lorry, gix, mdbg, the host imager, Helix, sed, lua, javy, wasmtime, and
  the doc site,
  `toolchain_package` callable for repackaging; the other out-of-repo paths;
  the release.
- 3b. `make toolchain-archive` in the main repo.
- 3c. `test-native-toolchain-install.sh` against the standard image; the
  partition size; Lorry's compiler paths.

**Phase 4: tests.**

- 4a. `full-native-test.sh` for Linux, over the crates that build there.
- 4b. `systest` as a test crate; sysbox, rush, and rmux tests into their
  crates.
- 4c. `cross-test.sh` from the cross-system parts of `full-test.sh`,
  including the System console and no-IP runs on the standard image.
- 4d. The new `full-test.sh`: install, `cross-test.sh`, upload, guest
  `full-native-test.sh`; the developer image, the test-only images, and
  their scripts removed; the two Python tests replaced with shell.
- 4e. The full gate.

**Phase 5: sys-io.** After the sys-io refactoring lands, and only if the
check is free (question 2). Then the full gate again.

## Open questions

The v1 review decided: the phase 1 renames happen even where phase 4
deletes the files; Interactive `fetch` and `vendor` write `/user`; no list
of Interactive tests; the toolchain release is 1.99.1-2 with no `/devtools`
handling; a host Lorry's repository objects serve the guest; Javy and
Wasmtime are tested natively except the byte-code comparison; the
out-of-repo changes are mechanical; `sshd.toml` moves to `/user/cfg`;
`prefer-user-vendored-sources`, `false` by default, picks the repository
copy; approvals that a None `vendor` records under `/none/cfg` are
accepted; Lorry's native-tool grants are removed and build scripts run
programs as under Cargo. What remains:

1. **System console and no-IP runs without their images.** Edit a copy of the
   standard image on the host (recommended, using motor-fs `image-admin`), or
   add a boot-time switch for sys-init? Pending: you will answer later in
   the review, and no work starts without the answer.
2. **sys-io.** Can sys-io tell which tree an entry is in without walking its
   parents on every write? If not, phase 5 is dropped. If so: should "no
   mode may grant None `w` in `/system` or `/user`" bind Interactive and
   System too, or only None's own requests? Deferred until phases 1-4 are
   done.
