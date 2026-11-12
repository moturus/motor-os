# Developing Motor OS on Motor OS: image layout, Lorry as None, native tests

Status: milestones 1-2 implemented; milestone 3 and its review fixes
implemented and validated locally;
milestones 4-5 ready, updated 2026-11-11;
milestone 6 remains conditional. v1 is commit e7d46767, v2 is 3035a48a,
v3 is 29779e3f, v4 is 98fe39e0.
Milestone 1 is implemented: kernel command-line access, the System-console
boot option, network-device omission, and launcher and guest coverage.
Milestone 2 moves user commands, development tools, configuration, and sources
to their new paths, and the imager rejects None-writable entries under
`/system` and `/user`. The 1.99.1-2 compiler trees and test fixtures remain
under `/devtools`; only the compatibility rush and sh copies remain under
`/system/bin`. Milestone 3's local implementation passed its complete
Lorry gate with Cargo `[env]` support committed separately in `1d0ff2f9`.
The subsequent review fixes passed the complete Lorry gate in 1,171 seconds.
The approved shared defaults live in `/user/cfg/cargo/config.toml`, with
`/user/cfg/cargo` as Motor's default Cargo home for both roles.
The updated native Lorry gate, release red/rush/russhd/Helix builds, and release
developer-source gate pass. Code and tests are staged; no milestone 3 commit
has been made.
Milestones 4-6 have not been implemented by this work.

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
  is set in `/user/cfg/lorry.toml`, which both roles may read. This is a
  lookup preference, not a source restriction. `lorry fetch` and
  `lorry vendor` write the repository of the role they run as: the `user`
  one from an Interactive shell, the `none` one from a None shell, unless
  a local repository is configured. On Motor, compiled dependencies go to
  the `none` cache; workspace outputs stay in `target/lorry`. Every Motor
  build runs as None, so no build writes the Motor `user` cache.
- Image and installation modes deny None writes to `/system` and `/user`.
  Live installation must preserve that restriction. sys-io enforces it
  independently of modes too if that costs nothing per write (milestone 6).
- The root of every final image holds exactly `/system`, `/user`, and `/none`.
  There is no `/devtools` and no `/system/bin`.

**Images**

- Two images are built and shipped: `base` and `standard`. The test-only
  images (`system-tty`, `vsock-test`, `ro-root`, `wasm`) and the developer
  image go away.
- The standard image carries no development tools. The native toolchain
  archive carries them all: the compilers, lorry, gix, mdbg, Helix, sed, lua,
  QuickJS (`qjs` and `qjsc`), javy, wasmtime, the doc site, and the host's
  imager, a Linux binary that does not run on Motor OS but can be copied out
  of the VM. The standard image with the archive installed is the complete
  development environment.
- Archives are identified by version only, never by a git hash.
- All guest tests run on the standard image, and base tests on the base image.

**Testing**

- A crate's tests are its own: `cargo test` and `lorry test` on Linux,
  `lorry test` on Motor OS, where its harness supports that OS. No crate
  starts a VM or talks to another machine from its tests. Privileged boot
  self-tests remain in the kernel or service that owns them.
- `src/tests/full-native-test.sh` runs the supported crate harnesses on the
  machine it is on. Host-only build tooling is checked by `full-test.sh`;
  `src/tests/cross-test.sh` runs what needs a host and a guest.
  `src/tests/full-test.sh` runs the host build checks, `full-native-test.sh`
  on Linux, installs the toolchain archive on the standard image, runs
  `cross-test.sh`, and then runs `full-native-test.sh` on the guest over
  ssh. The archive goes in before `cross-test.sh` so that a cross test may
  use the guest's development tools.
- Cross tests cover network peers, VM boot and device topology, failures
  requiring host observation such as OOM abort, and host/guest artifact
  comparisons, among them the check that Lorry and Cargo produce the same
  bytes. Helix, rush, rmux, red, and sysbox functional tests are
  native; end-to-end SSH terminal checks remain cross tests.
- Lorry needs no sandbox beyond None without network. The VM is the
  isolation boundary.

## Where things stand

**Layout at v1.** `/system/bin` holds rush, sysbox, `sh`, 38 Rush wrappers over
sysbox, and `curl`, `rg`, `tar`, `zstd`, `wg`, and `wg-tool`. The v1 inventory
counted 707 `/system/bin` references in 160 files, 47 of them
`#!/system/bin/rush` lines, plus russhd's `SHELL` constant, `sys-tty.cfg`,
rush's own path in `exec.rs`, Lorry's curl path, and the toolchain's launchers
and libc `shells` file.
`/devtools` exists only in the developer and wasm images; v1 counted 646
references in 95 files. It holds the toolchain (`llvm`, `rust`), `helix`, `javy`,
`wasmtime`, `bin`, `tests`, `www`, `src`, and `lorry/{user,none}`. Three paths
are compiled into binaries and need rebuilds, since Motor OS has no symlinks:
clang's `CLANG_CONFIG_FILE_SYSTEM_DIR`, the clang Motor ToolChain's
`<sysroot>/devtools/llvm/include`, and Helix's `HELIX_DEFAULT_RUNTIME`.
The 1.99.1-2 binaries hold more old paths than these; they are listed under
"Outside the main Motor OS repo".
Since v1, QuickJS adds `/devtools/bin/qjs`, `/devtools/bin/qjsc`, and
`/devtools/quickjs/{include,lib}` with headers and `libqjs.a`, plus its
documentation, smoke fixtures, and Test262 gate.

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
the crate archives Lorry downloaded from crates.io, each verified by hash
before it is stored, plus the registry index records that describe them.
Source code cloned from Git is not in a repository. It is stored in the
workspace that uses it, under `.lorry/vendor/git/<hash>/source` with a
record of where it came from (`git/direct.rs`), and an offline build
verifies and reads it there. `.lorry/` is ignored by Git, and 11 lockfiles
in the tree name Git sources, those of Lorry, russhd, rush, and `src/sys`
among them. The cache holds what rustc
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
cache under `/<role>/dev/lorry/{vendor,cache}` (`config.rs`,
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
lock afterwards (`docs/fs-permissions.md`). Release sizes: rush 719 KB, rmux
571 KB, sysbox 784 KB, red 251 KB (no lock); lorry 9.8 MB, gix 7.4 MB,
russhd 4.3 MB, ssh 4.1 MB, curl 1.4 MB (locked while running). Debug builds
of rush (1.5 MB), sysbox (2.1 MB), and rmux (1.6 MB) are locked while
running too.

**Tests.** At v1, `full-test.sh` was 1687 lines and sourced or ran about 70 scripts.
Host `cargo test` runs for imager, rnetbench, red, rmux, rush, russhd, wg,
wg-peer, sys-init, moto-sys, moto-sdk, frusa, motor-fs, memfs, and the
rust-analyzer crates. Guest tests are mostly host-driven over ssh: `systest`,
one binary with about 90 case files and 31 invocations from `full-test.sh`;
sysbox's utility tests; rush's capability tests; and the developer-image
suite (`full-test-dev.sh`, `test-dev-sources.sh`, `prepare-dev-image.sh`).
Truly cross-system tests exist for ssh and sftp, vsock, DHCP and networking,
UDP fragmentation and WireGuard against host peers, OOM abort, and boot
checks.
Lorry is tested apart from all this: about 530 Rust tests, and 55 shell
scripts under `src/bin/lorry/tests` (10,400 lines) that `tests/test-all.sh`
runs on Linux against a release Lorry. Most of the scripts run Cargo on the
same fixture and compare. The last one, `test-native.sh`, boots the
developer image and compares a Lorry build made on the host with one made
on the guest. `full-test-dev.sh` runs `test-all.sh`.

## Target image layout

| Path | Holds | Writable by |
|---|---|---|
| `/system/services` | sys-io, sys-init, sys-tty, strobe, dns-resolver, russhd, rt.vdso | System |
| `/system/cfg`, `/system/logs`, `/system/tmp` | as today | System (logs readable by Interactive) |
| `/user/bin` | rush, `sh`, sysbox and its wrappers, curl, rg, tar, zstd, wg, wg-tool, red, rmux, ssh, httpd, httpd-axum, kibim | Interactive |
| `/user/bin/dev` | installed by the toolchain archive: lorry, gix, mdbg, cc, c++, ar, rustc, rustfmt, clippy-driver, rust-analyzer, hx, sed, lua, qjs, qjsc, javy, wasmi, wasmtime, wasmtime-rt, www | Interactive |
| `/user/lib/{llvm,rust,helix,quickjs,javy,wasmtime,www,imager}` | installed by the toolchain archive: the compiler trees, the Helix runtime, QuickJS headers and `libqjs.a`, the wasm plugins, the doc site, the host imager | Interactive |
| `/user/dev/lorry` | Lorry's `user` repository (`vendor/`) and cache (`cache/`) | Interactive; readable by None |
| `/user/cfg` | Interactive configuration, including `rush.cfg`, `sshd.toml`, `lorry.toml`, `lorry-workspaces/`, `helix/`, `russhd/`, `ssh/` | Interactive; None may traverse the directory and read explicitly shared files |
| `/user/tmp` | Interactive scratch | Interactive; closed to None |
| `/none/dev` | source trees, including `/none/dev/motor-os` | None |
| `/none/dev/lorry` | Lorry's `none` repository (`vendor/`) and cache (`cache/`) | None |
| `/none/cfg`, `/none/tmp` | as today | None |

`/user/cfg/lorry.toml`, `rush.toml`, `rmux.toml`, and the files under
`helix/` have mode `rwxrw-r--`, and the `helix` directory `rwxrwxr-x`, so
None may read them: a None shell, and rmux and Helix started from it, use
the user's configuration. The
`/user/cfg` directory itself has mode `rwxrwxr-x`: None needs directory `x`
to look up the files. This also lets None list the directory. Private files
can retain `rwxrw----`, and private subdirectories retain `rwxrwx---`;
opening the parent directory does not make their contents readable.

`PATH` is set in two files the Interactive user may edit, both moved from
`/system/cfg` to `/user/cfg`: `rush.cfg`, which a console shell sources
through `ENV`, and `sshd.toml`, whose `path` russhd gives every ssh session;
`sys-init.cfg` passes russhd the new path, and the host key in `sshd.toml`
becomes Interactive-readable with it. The standard image sets `/user/bin` in
both; the toolchain archive's `install.sh` appends `/user/bin/dev` to both,
and `helix/languages.toml` and the tests' `EXPECTED_PATH` follow. A change
to either file takes effect late: a console shell reads `rush.cfg` when it
starts, and russhd reads `sshd.toml` once, when it starts
(`russhd/src/main.rs`), so ssh sessions keep the old `PATH` until the VM
reboots. russhd gets no reload. `install.sh` ends by saying that a reboot
is needed, and the gate reboots after installing. The
compiler trees cannot live inside `/user/bin/dev`:
the `javy` and `wasmtime` directories would collide with the commands of the
same names. clang's `cfg/` stays inside the LLVM tree, because None-role
builds run clang and must read it.

## Design

### Kernel command line and `system-tty`

The first milestone adds access to the kernel command line. The first boot option
is the bare token `system-tty`. When present, sys-init starts sys-tty with
`CAP_SYS`, overriding the console role in `sys-init.cfg` for that boot.
Without it, the configured console role applies as today. Other service
roles and sys-tty's remaining capabilities are unchanged.

The boot option is supported on Cloud Hypervisor and Firecracker only.
`run-chv.sh` and `run-fc.sh` accept an additional `--system-tty` parameter
through `vm-options.sh`. When present, they add `system-tty` to the kernel
command line, preserving any existing boot arguments. They consume this
launcher parameter rather than passing `--system-tty` itself to the VMM.
`run-qemu.sh` and `run-qemu-echr.sh` refuse `--system-tty` with an error:
QEMU boots from the disk, and that path has no kernel command line.

Both supported VMMs start `kloader` through PVH, and the loader already
hands the PVH start information, with its command-line pointer, to the
kernel. The disk-boot loader (`x64.boot`) keeps supplying a zero
command-line pointer, which the kernel exposes as empty; `x64.boot` does
not change.

All three launchers also accept `--no-network`, which starts the VM without
its network device; `run-qemu-echr.sh` forwards it.

The kernel retains the original command-line bytes with bounded length and
validated boot memory access. `SysRay::OP_QUERY_CMDLINE` serves those bytes
only to System processes. sys-init queries the kernel directly and recognizes
`system-tty` as a complete ASCII-whitespace-separated token when choosing
sys-tty's role. Missing or empty command lines mean no options; unrelated
tokens do not enable the System console. The kernel does not parse options,
and this path needs neither shared-page fields nor sys-io forwarding.
The no-IP test does not depend on `--no-network`; its image copy has
networking configured off ("Two images").

### Lorry: the parent process and its None children

The Lorry process the user starts keeps the caller's capabilities (System
is still refused). It parses the command, reads the caller's configuration
and workspace approvals under `/user/cfg` or `/none/cfg`, shows reviews,
asks for approval, records decisions, and for `run` and `test` runs the
programs it built. It never runs build scripts or procedural macros itself.
Both roles read `prefer-user-vendored-sources` from `/user/cfg/lorry.toml`.
Other settings and workspace approvals stay in the caller's configuration
directory; `/none/cfg/lorry.toml` does not override the shared preference.

The work runs in a child Lorry: `current_exe()` started with a private flag
and an explicit `MOTOR_OS_CAPS`, as rmux starts its server:

| Command | Child's mask |
|---|---|
| `build`, `check`, `clippy`, `metadata`, `tree`, `review`, and the build half of `run` and `test` | `own & (CAP_SPAWN \| CAP_FS_WRITE)`: None, no network |
| `fetch`, `vendor` | `own & ~CAP_SPAWN_DETACHED`: caller's role, retaining network if held |
| `fetch`, `vendor` with `--offline` | `own & ~(CAP_NET \| CAP_SPAWN_DETACHED)` |

Builds run package code, so they drop to None. `fetch` and `vendor` run
none, so they keep the caller's role: an Interactive `vendor` writes the
`user` repository and a None one the `none` repository. A child refuses to
start if its capabilities do not match its command, gets the
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

**Two repositories, two caches on Motor.** Each role keeps a repository and
a cache, as under `/<role>/dev/lorry` today, at new paths and under
Lorry's own names:

| Name | Repository | Cache | Repository written by | Cache written by | Read by |
|---|---|---|---|---|---|
| `user` | `/user/dev/lorry/vendor` | `/user/dev/lorry/cache` | Interactive `fetch` or `vendor`; image preparation | Interactive `fetch` or `vendor` (rustc query results only) | every role |
| `none` | `/none/dev/lorry/vendor` | `/none/dev/lorry/cache` | None `fetch` or `vendor` | every Motor build | every role |

The `system` repository goes. After this plan Lorry's repositories are
`local`, `user`, and `none`, on Linux too, where `none` has no default.
Nothing on the command line chooses where things go:

- **Source code.** `fetch` and `vendor` write the configured
  `repositories.local` when a workspace has one, otherwise the repository of
  the caller's role on Motor, or `user` on Linux. Both configured role
  repositories are searched. Git sources stay where they are today, in the
  workspace's `.lorry/vendor/git`; this plan adds no shared storage for
  them.
- **Compiled dependencies on Motor.** Every build is None, so cached output
  goes to the `none` cache. An Interactive `fetch` or `vendor` writes the
  `user` cache, but only the rustc query results Lorry keeps there
  (`rustc-queries`), never compiled dependencies; those reach the `user`
  cache only if whoever prepares an image or an installation puts them
  there, and nothing in this plan ships it filled. Both caches are always
  read.
- **Precedence.** A configured `local` repository is searched first. After it,
  `none` is searched before `user`, unless the effective configuration sets
  `prefer-user-vendored-sources = true`; the default is `false`. The setting
  swaps those two repositories, with fallback when an object is absent.
  It neither excludes None-writable sources nor changes `local` precedence.
  Preference with fallback is sufficient; no strict source restriction is
  part of this plan. Motor caches have no such setting: `none` is read
  before `user`, since only `none` is written at runtime.

Lorry writes the Motor `user` repository only through an Interactive
`fetch` or `vendor`, which runs in the caller's role and writes it directly.
Repository objects are not staged or passed through the parent.

**Workspace state is shared with None without losing executable modes.** An
Interactive `vendor` or `fetch` writes into the workspace: `target/` and
`target/lorry`, the lock file `.vendor.lock` (`vendor_lock.rs`), `.lorry/`
with its admission record, and the Git sources under `.lorry/vendor/git`.
A directory that Interactive creates gives None `r-x`, and a file `r--`
(`docs/fs-permissions.md`), so the None build that follows could not create
its own lock or its output. On Motor, either role creates and replaces
workspace entries with these final permissions for None:

| Entry | None's permissions |
|---|---|
| Directories, including `target/`, `target/lorry`, and `.lorry/` | `rwx` |
| Mutable data: lock files, admission records, `Cargo.lock`, non-executable sources and build outputs | `rw-` |
| Executable source files, including scripts materialized from Git | `rwx` |
| Finished build-script, program, and test executables | `r-x` |

Source materialization preserves the source's executable flag; it does not
apply one mode to all files. Executable sources remain editable, while
compiled executables keep the compiler's final `r-x` for None. Atomic
replacements follow the same rules. Permission changes leave higher roles
unchanged and obey their ceilings; a caller making its own `rw-` source
executable uses `rw-` -> `r-x` -> `rwx`, since a direct `rw-` -> `rwx` is
not allowed. These write grants apply inside the workspace, not to the
shared repository under `/user`.

**Source identity is the same in both roles.** `source_tree.rs` hashes the
executable flag, and Motor's `stat().perm` reports the caller's permissions.
For example, a non-executable file created by None has `rwx` for Interactive.
On Motor, source scans and their metadata fingerprints therefore use the
entry's **None execute bit**, regardless of the caller, for both pathname
and open-file checks. Read it by entry ID through the existing
`moto-sdk` filesystem metadata API, adding that Motor-only dependency to
Lorry. Its role-permission operations also implement the workspace modes
above; no runtime or stdlib API change is needed. All source materialization
preserves the original executable flag in None's permission byte. Sources
outside the workspace retain their storage policy: under `/user`, None gets
`r--` for data and `r-x` for executable sources, never `w`.
Linux keeps its existing executable-bit test, and the digest format stays
the same. Verification still rejects an executable-bit-only change; it must
not rewrite provenance to make a mismatching tree pass.

A workspace must be where None can read the sources and create `target`:
in practice under `/none`. For a workspace elsewhere, such as `/user/tmp`,
Lorry stops before building and says why. Lorry's tests create fixture
workspaces under `/none/tmp` on Motor whatever role runs them, giving the
fixture root and its contents the modes above; changing the path alone
does not make an Interactive-created fixture writable by None.

A Rust regression on Motor uses a Git dependency containing both executable
and non-executable source files. It exercises materialization by either
role and verification by both, checks the same digest as the fixture on
Linux, and rejects an executable-bit-only change. It also runs Interactive
`vendor` in a fresh workspace followed by a None build and execution of the
result, checking the workspace locks and final executable mode. Fixtures
use local files or loopback servers, with no Internet access.

`role.rs` keeps the per-role configuration directories (`/user/cfg` for an
Interactive caller, `/none/cfg` for a None one) and gets the new
repository and cache paths. Linux keeps one process, the Landlock sandbox,
and its writable configured cache (default `$HOME/.cache/lorry`). The Motor
role and cache-write rules do not apply on Linux.

### The Motor build-script sandbox

`Sandbox::apply` on Motor gives each build script the build mask and fails
unless Lorry's own role is None. The warning goes, and the docs
(`sandbox.rs`, `spec.md:1800`, the README's "Package build-script
security", `design.md:352`) say what None enforces and what it does not:

- **Enforced:** no network; no writes to `/system` or `/user`; no reads of
  private files and subdirectories in `/user/cfg`, or of `/user/tmp`,
  `/system/tmp`, or `/system/logs`. The shared configuration files
  (`lorry.toml`, `rush.toml`, `rmux.toml`, `helix/`) are readable.
- **Not enforced:** reads of public content; writes to every None-writable
  tree, including other workspaces, `/none/dev/lorry`, and other scripts'
  `OUT_DIR`s; starting any program None may execute.

The `none` repository and cache can be changed by any None process with
`CAP_FS_WRITE`, and so can the approvals a None `vendor` records under
`/none/cfg/lorry-workspaces/`: a build script could approve itself for the
next `vendor`. Both are accepted. Filesystem isolation relies on shipped
and installed modes until the optional independent enforcement in
milestone 6.

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
`/user/bin/dev`. Their default clang configuration is insufficient for cc-rs
1.11, which passes its own incorrect target mapping. Cargo `[env]` must supply
the overriding Motor C/C++ target flags and C++ standard library selection.
Whether a dependency's build script and procedural macros run at all
is still decided in `vendor`'s review, as today.

Three things the grants supply today must be supplied another way before
they are deleted:

- **The archiver.** Lorry's built-in table names `llvm ar` and hands it to
  scripts as `AR_<target>` (`config.rs`). The toolchain ships launchers for
  `cc` and `c++` only. Release 1.99.1-3 adds an `ar` launcher in
  `/user/bin/dev` that runs `/user/lib/llvm/bin/llvm ar`. Step 3f checks
  which archiver name the `cc` crate looks for when `AR` is unset, and the
  launcher gets that name.
- **The environment.** Lorry starts every build script with an empty
  environment plus the variables it computes (`build_script.rs`), and the
  `caller-env` setting refuses `PATH` and the compiler variables. A script
  that must find `cc` on `PATH`, or be told `CC`, gets neither. The new
  rule: a build script receives Lorry's own `PATH`, and from Lorry's
  environment `CC`, `CXX`, `AR`, `RANLIB`, `CFLAGS`, `CXXFLAGS`, `ARFLAGS`,
  and `CXXSTDLIB`, in their plain, `HOST_`, `TARGET_`, and `_<target>`
  forms. Everything else stays as today: cleared unless `caller-env` allows
  it. These variables become part of the cache key of a dependency whose
  build script ran with them.
- **Motor C/C++ defaults.** `CFLAGS_x86_64_unknown_motor` and
  `CXXFLAGS_x86_64_unknown_motor` need `--target=x86_64-unknown-motor`;
  `CXXSTDLIB_x86_64_unknown_motor` needs `c++`. Supply them through Cargo
  `[env]` in `/user/cfg/cargo/config.toml`, preserving caller and workspace
  overrides. Both roles default to that Cargo home; an explicit `CARGO_HOME`
  selects another configuration. The image supplies the defaults to ring,
  russhd, and Helix without per-project settings.

### User-replaceable tools

Installing a tool means putting a copy of it into `/user/bin` or
`/user/bin/dev`, with the existing commands. A plain `cp` over a shipped
executable fails: the image ships executables as `r-xr-xr-x`, and a copy
needs the caller's `w` on the destination file (`rt_fs.rs`,
`prepare_copy`). The directory is writable by Interactive, and a
non-writable file may be replaced where its directory is writable
(`docs/fs-permissions.md`). So the sequence is: `cp` the new file to a
temporary name in the same directory, `chmod` it, then `mv` it onto the
real name. `mv` is a rename, so the name never goes missing, and the
sequence is the same whether or not the name existed.

Modes after installation are those an Interactive process can set. It
cannot lower System's permissions on a file it created, so System keeps
`rwx` on everything installed at runtime: executables and scripts are
`rwxrwxr-x`, data files `rwxrw-r--`, directories `rwxrwxr-x`. Image-built
ELF binaries have `r-xr-xr-x` and data files `rw-rw-r--`; the mode check
of 2f accepts the appropriate image and runtime forms.

The compiler gives a None-built executable `rwxrwxr-x`. An Interactive
`cp` produces `rwxr-xr-x`: `rt_fs.rs`'s `copied_access` converts the
caller's `rwx` to `r-x`, and lower roles are capped by that result. The
explicit `chmod rwxrwxr-x` restores Interactive's write permission while
leaving None unable to write. Scripts also get that explicit final mode;
if the temporary copy is still `rw-` for Interactive, first set it to
`rwxr-xr-x`, then `rwxrwxr-x`, using the permitted two-step transition.
Data files get `rwxrw-r--`. Installation checks the final modes rather
than assuming `cp` preserves every permission byte.

The archive's `install.sh` follows the same rules and must work a second
time: it removes every tree it installs under `/user/lib` before copying
it, as it removes `llvm` and `rust` today, replaces each command in
`/user/bin/dev` through a temporary name, and sets the modes above. None
of this calls for a new install command or staging system. The gate
installs the archive twice on one image, and replaces one shipped
`/user/bin` executable with a rebuilt copy and runs it. It checks the
installed modes and that None can execute the programs but cannot write
the installed files.

sys-io locks an executable over 1 MiB while a process runs it, so lorry,
gix, ssh, and curl can be replaced only when idle; release builds of rush,
rmux, sysbox, and red are smaller and can be replaced at any time. Debug
builds of rush, sysbox, and rmux are over 1 MiB and are locked while they
run, like the larger tools. Nothing in this plan changes that.

### The session shell

sys-tty and russhd start `/user/bin/rush`. russhd's `SHELL` constant becomes
the configured path; `sys-tty.cfg` names it. Every `#!/system/bin/rush` line
becomes `#!/user/bin/rush`, in the tree, in the toolchain, and in libc's
`shells` file. rush's recognition of its own path (`exec.rs:1261`) follows.
Until the 1.99.1-3 toolchain is in use (milestone 4), every image also keeps
copies of rush and `sh` at `/system/bin/rush` and `/system/bin/sh`, because
the 1.99.1-2 launchers and libc name those paths.
The System console test boots with `--system-tty`, so sys-tty starts
`/user/bin/rush` as System too; that is acceptable for a test.

### Two images

The developer image, `system-tty`, `vsock-test`, `ro-root`, and `wasm` go.
What they provided moves:

- **Development tools:** into the toolchain archive (next section).
- **The System console:** `cross-test.sh` boots the standard image with the
  launcher's `--system-tty` parameter. The kernel's `system-tty` boot option
  selects the System console without editing the image's configuration.
  These checks run on Cloud Hypervisor, and on Firecracker in a `--vmm fc`
  run. A `--vmm qemu` run does not run them, on any VMM, and says so.
- **The no-IP vsock run:** the test works on a copy of the standard image.
  Removing the network device is not enough: the standard `sys-net.toml`
  turns loopback on, sys-io creates that interface whatever devices exist
  (`runtime/net.rs`), and the test expects sys-io's networking endpoint to
  be absent. So the test writes the `sys-net.toml` of today's `vsock-test`
  image, with no devices and loopback off, into the copy with the imager's
  `block-mount-fixture net-config`, and boots it with `--system-tty`. The
  network device stays attached, as in today's test. Nothing can be
  uploaded in such a boot, and `/none/tmp` is emptied at every boot, so an
  earlier boot of the copy, before its configuration is changed, uploads
  the guest-side program to a directory on disk, `/user/test-tmp`.
  Today's `vsock-test` image also starts no russhd. Step 5c checks that
  russhd and the DNS resolver of the standard image start cleanly with no
  networking endpoint; if they do not, the test also writes a
  `sys-init.cfg` without them into the copy.
- **The read-only root:** `test-block-mounts.sh` works on a copy of the
  standard image. It uploads its guest program and probe file while the
  root is writable, then writes the read-only `sys-fs.toml` (read-only
  root, memfs `/system/logs`) into the copy with the imager's
  `block-mount-fixture config`, as it already does for its other
  configurations. The launchers' existing `--root-read-only` covers
  read-only backing, and `--system-tty` the System checks.
- **The wasm checks at 256 MiB:** the VMM's `MOTO_MEMORY_MIB` on the standard
  image with the archive installed.
- **Staged first-party sources and the preseeded Lorry repository:** the
  test suite uploads the tree and the repository objects it needs (Tests,
  below); a developer clones and runs `lorry vendor`.

The standard qcow2 image's data partition grows from 256 MiB to 32 GiB to
hold an installed toolchain, sources, and build output; qcow2 is sparse, so
the shipped file grows little. The raw standard image that Firecracker needs
(`make raw.img`) keeps 256 MiB, so the toolchain is installed and the native
tests run on QEMU and Cloud Hypervisor only, as the developer-image suite
does today. The base image stays at 64 MiB. sys-init starts
the same services, and partition size adds no boot work. Milestone 1 adds
the bounded command-line copy, sys-init's query, and its boot-option parsing.

### The toolchain archive

The native archive gains overlays for every development tool: lorry, gix,
and mdbg from the main repo's build, and Helix, sed, lua, QuickJS, javy,
wasmtime, and the doc site, which `build-motor-os.sh` already stages as overlays.
`install.sh` installs into `/user/bin/dev` and `/user/lib`, replacing the
`llvm` and `rust` trees as it replaces them today, applying the installation
permission rule above. QuickJS installs `qjs` and `qjsc` in `/user/bin/dev`,
its headers in `/user/lib/quickjs/include`, and `libqjs.a` in
`/user/lib/quickjs/lib`, with its license and documentation retained.
The archive's hello-world examples go to `/none/dev/hello-world`, with
modes that let None build there.
The archive also carries the imager: the statically linked Linux binary
that `make` already installs beside the images as
`vm_images/<profile>/tools/imager` so that it runs on other Linux hosts.
It has never been run on Motor OS, so `install.sh` puts
it at `/user/lib/imager/imager`, off `PATH`, for a developer to `scp` out of
the VM and build images on a host that has no checkout of the repo.

Rebuilding LLVM and rustc takes hours; repackaging must not. The main repo
gets a `make toolchain-archive` target that unpacks
`$MOTORH/motor-toolchain-<version>.tar.zst`, replaces the overlays the main
repo owns with the current binaries and staged tool overlays, and writes
the result under `build/`. The packaging logic lives in `../motor-os-toolchain`
(`toolchain_package`), which `build-toolchain.sh` and this target both call.

An archive is identified by its version alone. A repackaged archive keeps
the version of the one it came from and lives only under `build/`; it is
never copied to `$MOTORH` or published. `full-test.sh` installs the
repackaged archive whenever any main-repo-supplied guest payload differs
from `$MOTORH`'s archive: binaries, libraries, runtimes, launchers,
configuration, documentation, or installer changes all count, including
QuickJS and the other staged external tools. Otherwise it installs the
`$MOTORH` archive. An imager-only change does not trigger guest repackaging,
since the guest never runs it; host checks test the current imager directly.
Publishing any changed archive payload, including the imager, means a new
toolchain release with its patch version bumped. The release that
carries this plan is 1.99.1-3. Its `install.sh` installs into the new layout
only; it does not look for or remove `/devtools`.

### None cannot write `/system` or `/user`

**On disk.** The imager rejects any policy rule or exact entry granting None
`w` at or below `/system` or `/user`. Every final image is checked to have
exactly `/system`, `/user`, and `/none` at the root.

**In sys-io, last, and only if free.** This waits for the sys-io filesystem
refactoring now in progress, and it is done only if sys-io can tell which
tree an entry is in without walking its parents on every write. If every
write would have to re-trace its parents to find out where the entry lives,
this is not implemented and on-disk modes stay the only enforcement
(question 1, decided after milestones 1-5). If it is free, the rules are:
sys-io refuses every mutating request from a None client whose target, or
destination parent, lies in `/system` or `/user`, whatever the entry's mode,
including the `/system/tmp`
and `/user/tmp` mounts; no mode change may grant None `w` there; a rename
into those trees cannot carry None `w` along; native `systest` cases prove
each rule.

### Tests

**Rules for crates.** Each ordinary crate harness passes `lorry test`
natively on Motor OS from `/none/dev/motor-os` where it supports Motor,
and `cargo test` and `lorry test` on Linux where it supports Linux.
Host-only tooling such as the Linux imager is tested in the host build
checks, not added to the Motor native list. Kernel tests and privileged
service self-tests that run during boot remain there, observed through the
VM gate; they are not converted into ordinary user-process harnesses.
Kernel tests still run inside Motor OS, as `AGENTS.md` requires. Other
Motor-only harnesses run on Motor; host-only cases stay `#[cfg(unix)]`, as
rush's and rmux's pty tests are today. No crate test starts a VM, uses the
network beyond loopback, or assumes a host.

**`full-native-test.sh`.** One script, run on either OS. It walks an explicit
list of supported crate harnesses for that OS, retaining the feature
variants exercised today, and runs `lorry test` in each (`cargo test` as
well on Linux), stopping at the first failure. When `/user/bin/dev` is
installed it also runs the shell checks of the installed tools: Helix with
rust-analyzer, javy, wasmtime, sed, lua, and QuickJS. QuickJS retains its
smoke, native compilation, and release Test262 checks; the host prepares
the patched runner sources and pinned corpus, and the guest run is offline.
Compilation in these shell checks also runs as None, including when the
check was started by Interactive. On Motor OS the script runs as whoever
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
  programs that `cross-test.sh` drives. So do the cases that need the
  System role (the OOM tests, MMIO validation, `block-ro-root` as System):
  Lorry does not run as System, so `cross-test.sh` runs them from the
  System console. The test crate runs its cases one at a time, in today's
  order.
- sysbox's utility tests (`systest sysbox-tests`) move into the sysbox crate.
- rush's capability tests (`test-rush-script-caps.sh`, `rush-caps-precedence`)
  become rush integration tests under `#[cfg(target_os = "motor")]`.
- rmux's checks that `full-test.sh` runs through ssh today (a pane is a
  terminal to its program, the alternate screen is taken and given back)
  become rmux tests under `#[cfg(target_os = "motor")]`. rmux has no
  networking, so nothing of it stays in `cross-test.sh`.
- The developer-image checks of native compilation become ordinary
  `lorry build` and `lorry test` runs in the checkout. Installed-tool shell
  checks keep their C/C++ and other compiler coverage.
- Lorry has only Rust tests, like every other crate: `lorry test` on Motor
  OS, `lorry test` and `cargo test` on Linux. Its shell scripts become Rust
  tests in the Lorry crate, which write a fixture workspace into a temporary
  directory and run the Lorry under test on it. Tests of behavior that
  exists on one system only (the Landlock sandbox; roles and the None
  child) are under `cfg`. No Lorry test runs Cargo, boots a VM, or reaches
  the network beyond loopback. Where a script today gets the expected
  result from a Cargo run, the Rust test states the expected result itself,
  as the checked-in Cargo results under `tests/oracles` already do for
  dependency resolution.
  The one comparison with a live Cargo that stays is of build output, and
  it is a cross test (below).
- The native build of Helix by Lorry stays one of Lorry's tests, on Motor
  OS and on Linux: a Rust test has the Lorry under test build Helix from
  `external-sources/helix`, the checkout `build-motor-os.sh` manages, and
  fails if the checkout is absent. Today this build runs only on request
  (`test-all.sh --full`) and only on the guest. It stays on request: the
  test is marked `#[ignore]`, and `full-test.sh --full` has
  `full-native-test.sh` run that one test by name with `-- --ignored`, on
  Linux and on the guest. It is selected by name because Lorry has other
  ignored tests. The build is offline like every other: the
  host's `fetch --locked` produces Helix's repository objects and Git
  sources, where today the guest vendors them from the network.
- Lorry's ignored curl integration tests (`curl::tests::`) stay in every
  run, not only `--full`, on Linux and Motor OS. Before running them,
  `full-native-test.sh` prepares the fixture that `curl-contract.sh`
  supplies today: it builds the curl executable and its HTTPS test harness
  for the current OS, and sets `LORRY_TEST_CURL`, `LORRY_TEST_TLS_SERVER`,
  `LORRY_TEST_CA`, `LORRY_TEST_HOSTNAME_CA`, and `LORRY_TEST_UNTRUSTED_CA`
  to the built programs and the checked-in certificates. It runs
  `curl::tests::` with `-- --ignored` through Cargo and Lorry on Linux,
  and Lorry in both guest role runs. Fixture preparation and test failures
  fail the gate. The `tls_server_child` helper in curl's `tests/https.rs`
  has no Linux restriction. The upstream comparison,
  `matches_upstream_curl_for_supported_success_output`, stays Linux-only.
  All fixture traffic uses loopback. The Motor
  test invocations retain `CAP_NET` for the tests and fixture server;
  their compilation still runs in None children without `CAP_NET`.

**`cross-test.sh`.** Boots the guest and runs what needs both machines: ssh
and sftp (client, server, keys, config, terminal size, the TUI acceptance
suite), vsock and its outgoing variant, DHCP and the base-image networking
check, UDP fragmentation and WireGuard against host peers, the existing DNS
and ping checks, rnetbench's stalled-peer tests, OOM abort, boot identity
and console checks, and the System console selected with `--system-tty` on
Cloud Hypervisor or Firecracker.
Guest-side programs it needs
are cross-compiled on the host and uploaded to `/none/tmp`, or to
`/user/test-tmp` ahead of the no-IP boot, as
`full-test.sh` already does for the standard image, so `cross-test.sh` does
not depend on the guest having built anything. It runs after the toolchain
is installed, so a cross test may also use the guest's development tools;
the host/guest byte-code comparison is also owned here. No crate's
`cargo test` or `lorry test` starts this driver.

`cross-test.sh` also owns the check that Lorry and Cargo produce
byte-identical output. It builds one fixture workspace for
`x86_64-unknown-motor` three ways: with Cargo on the host, with Lorry on
the host, and with Lorry on the guest. The three results must be the same
bytes. It also builds the fixture for Linux with Cargo and with Lorry on
the host and compares those. The fixture is today's
`tests/fixtures/cargo-identity-workspace`, which has no crates.io
dependencies, so the guest build needs no repository objects; the fixture
and the comparison move to `src/tests`. This replaces `cargo-identity.sh`
and the host/guest comparison in `test-native.sh`. The script that checks
the retained Cargo results still match the current Cargo
(`verify-resolution-oracles.sh`) needs Cargo too, so it moves to the host
checks of step 1.

**`full-test.sh`.** It runs on Cloud Hypervisor unless `--vmm` says
otherwise; today's default is QEMU. The full gate runs on Cloud Hypervisor,
where every test runs but one. That one is the check in
`test-block-mounts.sh` that a DHCP answer reaches a guest with a read-only
root: it uses QEMU's built-in DHCP server, and Cloud Hypervisor has none.
A Cloud Hypervisor run boots QEMU for that check alone and requires QEMU
on the host, so the coverage is not lost; a DHCP server on the host that
Cloud Hypervisor could use would be new work and is not part of this
plan. A `--vmm qemu` run skips
everything driven from the System console, since QEMU has no `system-tty`
option: the console checks, the `systest` cases that need the System role,
and the System part of `test-block-mounts.sh`. A `--vmm fc` run skips the
toolchain installation and the guest native tests (steps 3 and 5), and in
`cross-test.sh` the tests that need the guest's development tools: the
guest side of the Lorry and Cargo comparison, and the byte-code comparison
of javy and wasmtime. It names each skipped test. In
order:

1. The host build checks that need no VM: imager tests,
   `test-vm-image-format.sh`, `test-make-driver.sh`, `test-kloader-image.sh`,
   `test-external-sources.sh`, the size contracts, the shell replacement
   for `test-dev-path-locks.py`, and the check that Lorry's retained Cargo
   results match the current Cargo.
2. `full-native-test.sh` on Linux.
3. Boot the standard image, upload the toolchain archive, run its
   `install.sh`, shut down. Every later boot in the run has the development
   tools. A `--vmm fc` run skips this step and step 5, since the raw image
   has no room for them, and runs `cross-test.sh` without the development
   tools and without the tests that need them.
4. `cross-test.sh`, on that image and on the base image.
5. Boot the image again. Upload a snapshot of the working tree as a tar
   stream over ssh into `/none/dev/motor-os`. The snapshot is what a commit
   of everything would hold: tracked files as they are in the working tree,
   plus new files that are neither tracked nor ignored
   (`git ls-files --cached --others --exclude-standard`), minus tracked
   files deleted from the working tree. So uncommitted and unstaged work is
   tested, new files included. Upload with it each workspace's Git sources,
   to that workspace's `.lorry/vendor/git`, and the
   Lorry repository objects the crates need into `/user/dev/lorry/vendor`
   (the ssh session is Interactive, so it may write there). Stage the
   QuickJS runner sources and pinned Test262 corpus
   separately under `/none/dev`; they are not part of `git ls-files`.
   With `--full`, also upload the Helix checkout to
   `/none/dev/motor-os/external-sources/helix`, where Lorry's test looks
   for it on either system, and Helix's repository objects and Git sources.
   Extract sources with the workspace modes above, preserving every
   source's executable flag in None's permissions so that the uploaded
   Git provenance verifies unchanged in both roles. `tar` on Motor sets
   only the permissions of the role that runs it, so who extracts matters.
   The tree, the Git sources, and the Helix checkout are extracted by a
   None `tar`, which gives None `rw-` on data and `r-x` on executable
   sources. The repository objects under `/user` must be extracted by
   Interactive, and an Interactive `tar` leaves None `r--` on an executable
   file. Each object holds an extracted source tree that Lorry verifies,
   and 187 of the 2,665 crates in the host's Cargo registry ship
   executable files, so those objects would fail verification. The host
   therefore sends the list of executable files in the objects it uploads,
   and the upload sets each to `rwxr-xr-x` with `chmod`. Run
   `full-native-test.sh` as Interactive first, on the fresh tree, then as
   None, admitting the workspaces with
   `lorry vendor --locked --offline --accept-all` in each role first so
   each has its own approvals. Interactive goes first so that every gate
   run proves that Interactive-created workspace state supports a None
   build without losing executable modes. Both native-test invocations
   retain `CAP_NET` for their loopback tests, including the curl fixture;
   build children still drop it. Guest preparation never reaches the
   network.

The host produces the repository objects and the Git sources with its own
Lorry once per dependency change, at build time, as `fetch_sys_lib_deps`
does today for `sys/lib`: a host-built Lorry runs `fetch --locked` on a
copy of each workspace with its `user` repository pointed at a scratch
directory. The objects and index records it writes there are uploaded, and
so is what it writes to each workspace's `.lorry/vendor/git`: the Git
source and the record of where it came from, which the guest's Lorry
verifies before use as it does today. Repository objects and Git sources
are source code and records, the same bytes and source executable flags
on either machine. `fetch --locked` takes every package of the lock
whatever platform it is for, so a host Lorry's fetched sources serve every
crate in the tree on the guest. The offline builds of Lorry and russhd,
which both have Git
dependencies, are the acceptance case: they fail if a Git source is missing
or does not verify.

**Coverage before removal.** Milestone 5 maps each existing check to its native,
host-build, boot, or cross-test destination before deleting its old driver.
`test-external-sources.sh` keeps its applicable checkout, staging, and ELF
validation checks in host step 1; only obsolete developer-image assertions
go. The applicable Helix, rust-analyzer, and rustfmt size contracts stay in
host checks with updated paths. QuickJS smoke fixtures move out of the
developer image into the test tree, and the Test262 driver is split into
host input preparation and native execution.

**Removed after migration.** Drivers that exist only for the developer image
or for driving native tests from the host: `full-test-dev.sh`,
`test-dev-sources.sh`, `prepare-dev-image.sh`, `sys-lib-workspace.sh`,
`test-dev-memory-contract.sh`, `test-sys-lib-workspace.sh`,
`test-system-tty.sh` as a separate-image test,
the Helix, rust-analyzer, and rustfmt native drivers,
`test-gix.sh --guest`, the wasm smoke suites in their current form, and the
`systest` plumbing in `full-test.sh`. All of Lorry's shell tests go too:
`tests/test-all.sh` and its 30-minute budget, the contract scripts,
`test-native.sh`, and `test-native-projects.sh`. The native builds of red,
rush, and russhd that `test-native-projects.sh` made are covered by the
guest run of `full-native-test.sh`; its native build of Helix becomes the
Rust test described above. The javy and wasmtime checks become
native tests, except the comparison of the byte code compiled on the guest
with the host's, which stays in `cross-test.sh`. The Helix checks become
native: Helix has no networking. The two Python tests go: Python is not used
for tests. `test-helix-lsp-ready.py`, which waits for rust-analyzer's
progress messages in Helix's log, becomes the shell check of the installed
Helix that `full-native-test.sh` runs; `test-dev-path-locks.py`, which
checks that the curl and lorry lockfiles match their path dependencies,
becomes a shell host check in step 1. The x86_64 crate's `ci-release.py` is
a dependency's own release script, not a test, and stays.

**The other users of the developer image.** `stress-soak.sh` boots the
developer image too; it boots the standard image with the archive installed
instead. `run-dev.sh` goes with the developer image.

### Outside the main Motor OS repo

**`/devtools` and `/system/bin` go away in the toolchain too.** Release
1.99.1-3 ships no file under either directory, and nothing it builds names
either one: not the launchers, not `install.sh`, not libc, not the
compilers. This changes code outside the main Motor OS repo, in
`../motor-os-toolchain` and in the LLVM, Rust, and mlibc forks. Every old
path becomes a new one:

| Old path in 1.99.1-2 | New path in 1.99.1-3 |
|---|---|
| `/devtools/bin/{cc,c++,rustc,rustfmt,clippy-driver}` | `/user/bin/dev/…` |
| no archiver launcher | `/user/bin/dev/ar`, which runs `/user/lib/llvm/bin/llvm ar` |
| `/devtools/llvm`, with its `bin`, `lib`, `include`, and `cfg` | `/user/lib/llvm` |
| `<sysroot>/devtools/llvm` in the Linux archive's cross sysroot | `<sysroot>/user/lib/llvm` |
| `/devtools/rust`, with rust-analyzer and the Rust library source | `/user/lib/rust` |
| `/devtools/src/hello-world` | `/none/dev/hello-world` |
| `/system/bin/rush`, `/system/bin/sh` | `/user/bin/rush`, `/user/bin/sh` |
| the default `PATH` `/system/bin:/user/bin` | `/user/bin` |
| the default `PATH` `/system/bin:/user/bin:/devtools/bin` | `/user/bin:/user/bin/dev` |

Where the old paths are today:

1. `../motor-os-toolchain`: 56 lines in `build-toolchain.sh`,
   `lib/toolchain-package.sh`, `lib/toolchain-native-rust-analyzer.sh`, and
   `lib/toolchain-bootstrap.sh`, and 17 in the README. They are `TOOLS` and
   `CFG_LLVM`, which also set `CLANG_CONFIG_FILE_SYSTEM_DIR` and the
   `-resource-dir` line of the clang `.cfg`; the five launchers with their
   `#!/system/bin/rush` lines and `exec /devtools/…` targets; libc's
   `shells` file; the hello-world examples; rust-analyzer packaging; the
   `crt1.o` path in `toolchain-bootstrap.sh`; and `install.sh`, a
   `#!/system/bin/rush` script that removes and fills `/devtools`. Besides
   the path changes, `toolchain_package` must accept overlays from the main
   repo and be callable for repackaging.
2. The LLVM fork: the clang Motor ToolChain compiles in
   `/devtools/llvm/include`, `/devtools/llvm/include/c++/v1`,
   `/devtools/llvm/lib`, and `/devtools/llvm/lib/crt1.o` (strings of the
   1.99.1-2 `llvm` binary). The fork's source is not yet read; there is no
   local checkout.
3. mlibc: the 1.99.1-2 `libc.a` holds `/system/bin/sh`, `/system/bin/rush`,
   and the default `PATH` `/system/bin:/user/bin`. It is linked into the
   compilers, so they are rebuilt too.
4. The second default `PATH`, `/system/bin:/user/bin:/devtools/bin`, is
   compiled into both `rustc` and `llvm` next to Motor runtime strings.
   Milestone 2e located it in mlibc's Motor runtime code, as detailed below.
   `rustc` holds no other `/devtools` path.

Milestone 2e audited the installed Rust library sources, the toolchain scripts,
and mlibc at `2b86b98c4fa26de6c6961f4f357f1a3daf8f277d`. The longer default
PATH is in mlibc's `sysdeps/motor/moto-rt-cabi/src/processes.rs`, not Rust std.
Other shell references are in `sysdeps/motor/generic/process.cpp` (`popen`),
`options/ansi/generic/stdlib.cpp` (`system`), `options/posix/generic/wordexp.cpp`,
`options/posix/generic/unistd.cpp`, and `options/glibc/include/paths.h`.
The installed Rust Motor process and environment implementations delegate to
moto-rt and contain no old shell paths. The LLVM fork is still unread.
No code outside the main Motor OS repository changes in milestone 2: the
compatibility rush and sh copies keep the 1.99.1-2 launchers and libc working.
Their removal still requires the milestone 4 toolchain rebuild and release
1.99.1-3 in both archives.

Milestone 4c checks the result. After `install.sh` runs, the guest has no
`/devtools` and no `/system/bin`. No entry of either archive lies under
`devtools/` or `system/bin/`. The launchers, `install.sh`, `libc.a`,
`rustc`, and `llvm` hold none of the strings `/devtools/`,
`/system/bin/rush`, `/system/bin/sh`, and `/system/bin:`. clang's Android
strings, such as `/system/bin/linker`, are not Motor paths and stay.

## Steps

Patches may be large, and the full test gate does not run after every step.
Each step makes sure that what it moved or changed builds and that the
tests of those components pass. The
full gate, `full-test.sh` on Cloud Hypervisor in debug and release three
times each, runs once
at the end of milestone 5 and again after milestone 6. Doc-only changes go
in their own patches.

**Milestone 1: kernel command-line access.** Implement and test this before
the image-layout migration. The first option is `system-tty`.

- 1a. Read the kernel command line from the PVH start information that
  Cloud Hypervisor and Firecracker supply. Retain its bytes in the kernel
  with bounded reads. Disk boot keeps its zero command-line pointer, which
  means an empty command line.
- 1b. Expose the original bytes through `SysRay::OP_QUERY_CMDLINE`, restricted
  to System processes. sys-init queries the kernel directly and matches the
  exact `system-tty` token. When present, sys-init gives sys-tty `CAP_SYS`;
  otherwise it uses the role from `sys-init.cfg`.
- 1c. Add `--system-tty` to `vm-options.sh`, `run-chv.sh`, and `run-fc.sh`,
  passing the bare `system-tty` token in the kernel command line;
  `run-qemu.sh` and `run-qemu-echr.sh` refuse it. Add `--no-network` to all
  three launchers and forward it through `run-qemu-echr.sh`. Update launcher
  help and documentation.
- 1d. Extend the existing System-console and launcher tests, through
  `full-test.sh`, to cover boots with and without the option on Cloud
  Hypervisor and Firecracker, QEMU's refusal of it, and a `--no-network`
  boot on each VMM. Check sys-tty's capabilities and its console shell's
  role on the standard image. Cover empty command lines and tokens that
  resemble but do not equal `system-tty`. Kernel reader and syscall tests run
  inside Motor OS, including denial to Interactive and None processes; the
  host checks sys-init's parser and launcher argument construction.

**Milestone 2: layout.** The developer image keeps being built through
milestones 2-4 so moved tools can be tested natively before the new archive
exists. It shares the migrated layout but temporarily retains `/devtools` for the
old compiler trees and remaining test fixtures. The final three-directory
root check waits until milestone 5d removes the last legacy paths and images.

- 2a. `/devtools/src` → `/none/dev`; `/devtools/lorry/user` →
  `/user/dev/lorry` and `/devtools/lorry/none` → `/none/dev/lorry`, with
  `/user/dev/lorry` readable by None; `role.rs`, the imager,
  `prepare-dev-image.sh`, the docs.
- 2b. `/user/bin/dev` and `/user/lib`: lorry, gix, mdbg, sed, lua, www, the
  doc site, the host imager under `/user/lib/imager`. `rush.cfg` and
  `sshd.toml` → `/user/cfg`, with `sys-init.cfg` updated. Give None traversal
  of `/user/cfg` and read access to `lorry.toml`, `rush.toml`, and
  `rmux.toml`, keeping private entries closed. Keep `/system/bin` on `PATH` until 2e; the developer image also
  needs `/user/bin/dev` and `/devtools/bin` while tools are split between
  the layouts.
- 2c. Helix, Javy, Wasmtime, and QuickJS, with the Helix rebuild. Give None
  read access to `/user/cfg/helix`, and have the `hx` launcher keep its
  cache under the caller's own temporary directory, not always
  `/user/tmp`. Move `qjs`
  and `qjsc` to `/user/bin/dev`, and their headers and `libqjs.a` to
  `/user/lib/quickjs`; update their documentation and existing checks.
- 2d. `/system/bin` → `/user/bin`: sysbox and wrappers, curl, rg, tar, zstd,
  wg, wg-tool; Lorry's curl path.
- 2e. rush → `/user/bin/rush`: shebangs, russhd, sys-tty, `exec.rs`, `sh`.
  Audit the toolchain, Rust fork, and mlibc shell paths here; any rebuild
  needed to stop invoking the old shell is a prerequisite to removing it.
  Then remove `/system/bin` from `PATH`, and everything in it except copies
  of rush and `sh`, which the 1.99.1-2 launchers and libc still name; 4c
  removes those and the directory. Base and
  standard use `/user/bin`; the transitional developer image keeps both
  development-tool paths until milestone 4.
- 2f. The imager's rejection of None `w` under `/system` and `/user`.
  Validate installed modes as well; the exact root check comes in 5d.

Milestone 2 validation used release images on Cloud Hypervisor. The release
build, external-tool rebuilds, build-script contracts, affected host tests,
and imager checks passed (54 unit tests, 16 integration tests, and Clippy with
warnings denied). The standard-image SSH credential gate also passed.
`full-test-dev.sh --release --vmm chv` completed its `full-test.sh` and
httpd-axum phases; the remaining developer phases were resumed separately
after correcting migration failures. Native source builds and system-library
tests, native toolchain installation, the complete Lorry suite (927 seconds),
and both regular and service-mode WebAssembly runs passed. QuickJS Test262
matched its existing Linux baseline in 312 seconds: 40/82220 errors,
4802 excluded, and 5736 skipped, with exit status 0. No debug developer-image
run was added.

The corrected migration failures covered the new SSH configuration permission
ceiling, rust-analyzer's process allowlist for the old compiler launchers,
libc test expectations for the retained 1.99.1-2 paths, and the installation
test's write-denial probe. The probe sends bytes: opening a readable file
for append alone need not check write access. Compiler/libc compatibility
assertions stay on the old paths until milestone 4 rebuilds the toolchain.

**Milestone 3: Lorry.** (Explicit Lorry work.) Lorry's existing suite,
`tests/test-all.sh`, gates these steps; milestone 5 replaces it.

- 3a. The parent and the None build child; builds write the `none` cache.
- 3b. The `none` repository and cache in place of `system`, both always
  read, and `prefer-user-vendored-sources` read from `/user/cfg/lorry.toml`
  for both roles.
- 3c. The `fetch`/`vendor` child in the caller's role and the approval
  hand-off. Apply the workspace modes by file kind, preserve source
  executable flags, and make Motor source hashes and metadata fingerprints
  use None's execute bit through the existing SDK metadata API. Lorry
  refuses a workspace None cannot build in. Add the Git fixture regression
  for both materializing roles, equal digests, executable-bit tampering,
  and an Interactive `vendor` followed by a None build and execution.
  Update fixture helpers to give None access to the fixture root too.
- 3d. `run` and `test` through the parent.
- 3e. The sandbox mask, the warning removed, `spec.md` and the README.
- 3f. Native-tool grants removed on both systems: `native_tool.rs`, the
  built-in tool table, the tool lists in policy rules and in `vendor`'s
  review, the Landlock program list; `spec.md` and the README. First the
  replacement: build scripts receive `PATH` and the compiler variables,
  and an archiver is on `PATH`. Until 1.99.1-3 supplies the `ar` launcher,
  the developer image carries one. A C dependency (`ring`) builds on the
  guest before and after the grants go.

Milestone 3 implementation status (2026-11-11): the parent/worker split,
role-specific writes and shared reads, source permissions and fingerprints,
parent-run programs/tests, sandbox masks, compiler environment, transitional
archiver, and grant removal are implemented locally. Focused Motor regressions
pass in both roles, including Git source modes, caller-role execution, bundled
tests, workspace paths, and cache/repository separation. Linux and Motor Clippy
are clean. Before the shared Cargo-home change, the complete Lorry suite
(`tests/test-all.sh --keep`) passed in 1,171 seconds. With that change, all host
checks passed; the native phase caught the image-permission issue described
below. After the correction, `tests/test-native.sh --warm --keep` passed,
including cross/native Lorry byte identity, editor integration, cancellation
and recovery, both-role regressions, and ring's compiler/archiver and SHA-256
checks. Its guest phase took 426 seconds. The native driver built both copies
from the reviewed source and manifests.

Review fixes cover parent-owned redirect prompts (including declining the
worker's automatic session-terminal relay), permissions only on newly created
directories, warned misses for corrupt read-only cache entries, explicit
rejection of Motor cache-directory overrides, and Interactive cleanup of both
role caches. Linux exposes selected compiler installations through PATH or
compiler variables, including symlinks and installation resources. Guest
drivers now expect None-built outputs; the real-project driver stages writable
workspaces under `/none/tmp` and prepares dependencies without network access.
`tests/test-native-projects.sh --release` passed: red in 14 seconds, rush in 18,
russhd in 215, and Helix in 274, including its static C/C++ grammars. Fixture
preparation supplies both reviewed targets from local caches, and materializes
Helix's themes link into regular archive members. The developer-source driver
also prepares local fixtures, including both red's and Lorry's locked Git
sources, preserving guest registry acquisition checks without external
networking. `src/tests/test-dev-sources.sh --release` passed on a freshly rebuilt
image, including source builds, output permissions, cache placement, and native
library tests without rebuilding prepared dependencies. The imager's 54 unit
and 16 integration tests pass; its Clippy check is clean. The direct
moto-sys dependency was removed in favor of
`moto_sdk::sys`. Parent-owned approval records and the bundle's existing
`moto_rt` permission API are retained deliberately.

An earlier gate found a pre-existing compiler-target problem: `cc` 1.11.0's
target table maps `x86_64-unknown-motor` to `x86_64-unknown-none-elf`, overriding
the installed clang launcher's default and losing the libc headers. The old
native-tool settings supplied an overriding C flag, so the before-removal
baseline passed. An isolated diagnostic with
`CFLAGS_x86_64_unknown_motor=--target=x86_64-unknown-motor` also passes after
removal. Cargo `[env]` support landed separately in `1d0ff2f9`. The ring
fixture first supplied that flag through `.cargo/config.toml`, and its native
build and SHA-256 assertion passed without a shell override. The approved image
configuration now supplies C/C++ target flags and `CXXSTDLIB` through the shared
Cargo home. The ring fixture's own configuration has been removed so its native
test verifies the image defaults. Both-role regression coverage checks the
shared home, caller and workspace overrides, and an explicit `CARGO_HOME`.
That regression caught the new directory inheriting `/user/cfg`'s private
permissions: Interactive could load the defaults, while None could not. The
image policy now shares only the Cargo directory and `config.toml`; credential
files retain private permissions. Guest source archives are staged under
`/none/tmp` with read access for None, which then extracts the writable sources.
A subsequent gate exposed a stale None-cache test assumption: reading a shared
user-cache entry requires no None-cache write. A cache-hit/miss diagnostic
confirmed correct fallback and write placement. The fixture now uses a distinct
configured environment to exercise a cache miss and verifies that value at
compile time and runtime; the directory assertion remains. No code outside the
main repository has been changed.

Left for milestone 5b: the Motor-only Rust tests added here that run Lorry
or inspect a workspace do not create their own fixtures. They are in
`tests/unit/motor-children.rs`, `motor-new.rs`, and `motor-source-modes.rs`.
`tests/test-native.sh` passes them a fixture workspace, the Lorry executable
to run, and a redirecting mock curl in `LORRY_MODE_WORKSPACE`,
`LORRY_NATIVE_LORRY`, and `LORRY_REDIRECT_CURL`. It also runs `vendor` and
`run` in that workspace before the tests inspect the results, and repeats
the tests in each role. It keeps the fixtures on disk under
`/none/dev/lorry-tests` rather than `/none/tmp`, so that `--warm` runs can
reuse them. Without that driver these tests panic on the missing variables,
so a plain `lorry test` in the Lorry crate fails on Motor until 5b.

**Milestone 4: the toolchain archive.** Before the tests, because the native
suite needs lorry on the standard image.

- 4a. `../motor-os-toolchain`: `install.sh` for the new layout, overlays for
  lorry, gix, mdbg, the host imager, Helix, sed, lua, QuickJS, javy, wasmtime,
  and the doc site; the `ar` launcher and shared Cargo configuration in
  `/user/cfg/cargo/config.toml`; an installer that can run again
  over its own installation, sets modes an Interactive process can set, and
  says that a reboot is needed;
  `toolchain_package` callable for repackaging; the other out-of-repo paths;
  the release. Move LLVM/Rust trees and launchers together with their
  compiled-in paths. `install.sh` appends `/user/bin/dev` to both PATH
  configurations; remove the developer image's legacy `/devtools/bin` entry.
- 4b. `make toolchain-archive` in the main repo, covering all current guest
  payloads when selecting the archive for tests.
- 4c. Switch the main repo to 1.99.1-3. `test-native-toolchain-install.sh`
  against the standard image: it installs the archive, installs it again,
  and replaces one shipped `/user/bin` executable through a temporary
  name. The 32 GiB partition of the qcow2 image, with
  `--raw-output` keeping 256 MiB; Lorry's compiler paths. Remove the
  temporary `/system/bin/rush` and `/system/bin/sh`, and `/system/bin`
  itself, from the imager and the policy. Add the check that the release
  and an installed guest hold no `/devtools` or `/system/bin` path
  ("Outside the main Motor OS repo").

**Milestone 5: tests.**

- 5a. `full-native-test.sh` for Linux, over the crates that build there.
  Record the supported harnesses and feature variants for both OSes, and
  the host-only and privileged boot checks that stay outside this script.
  Prepare the curl fixture and run Lorry's ignored curl integration tests
  through both Cargo and Lorry on every Linux run.
- 5b. `systest` as a test crate; sysbox, rush, and rmux tests into their
  crates. Lorry's shell scripts into Rust tests in the Lorry crate, in
  several patches, the native Helix build among them. The Motor-only Rust
  tests that milestone 3 left dependent on `tests/test-native.sh` create
  their own fixtures under `/none/tmp` here, so that `lorry test` in the
  crate passes on Motor without that driver. How the checks that need both
  roles (one role writes, the other verifies) are ordered without it is
  decided in this step.
- 5c. `cross-test.sh` from the cross-system parts of `full-test.sh`,
  including the System console via `--system-tty` and the no-IP run on a
  copy of the standard image with networking configured off, and the
  comparison of Lorry's build output with Cargo's. The tests that need the
  guest's development tools are skipped, by name, on Firecracker.
- 5d. The new `full-test.sh`, with Cloud Hypervisor as its default VMM:
  install, `cross-test.sh`, upload, guest
  `full-native-test.sh`, including QuickJS smoke, release Test262, and the
  curl fixture and Lorry integration tests in both guest role runs.
  A `--vmm qemu` run skips what the System console drives. A Cloud
  Hypervisor run boots QEMU for the DHCP check on a read-only root. `--full`
  adds Lorry's native Helix build on Linux and on the guest. The upload is
  the working-tree snapshot with each workspace's Git sources and preserved
  executable flags; the Interactive run of `full-native-test.sh` comes
  before the None one. Both test invocations retain loopback networking,
  while their build children have no network capability.
  Preserve applicable host build and size checks. After their coverage and
  fixtures have moved, remove the developer image, test-only images, and
  obsolete drivers; replace the two Python tests with shell. Remove the
  remaining `/devtools` paths and enable the imager's exact root check for
  every final image. Update contributor instructions that name removed
  gates. `src/bin/lorry/AGENTS.md` is one: its rules about `test-all.sh`,
  the developer image, and where the Cargo comparison runs change, and a
  change confined to Lorry is gated by `cargo test` and `lorry test` in
  the crate. Remove Lorry's shell tests. Move `stress-soak.sh` to the
  standard image.
- 5e. The full gate, on Cloud Hypervisor.

**Milestone 6: sys-io.** After the sys-io refactoring lands, and only if the
check is free (question 1). Then the full gate again.

## Open questions

The v1 review decided: the milestone 2 renames happen even where milestone 5
deletes the files; Interactive `fetch` and `vendor` write `/user`; no list
of Interactive tests; the toolchain release is 1.99.1-3 with no `/devtools`
handling; a host Lorry's repository objects serve the guest; Javy and
Wasmtime are tested natively except the byte-code comparison; the
out-of-repo changes are mechanical; `sshd.toml` moves to `/user/cfg`;
`prefer-user-vendored-sources`, `false` by default, picks the repository
copy; approvals that a None `vendor` records under `/none/cfg` are
accepted; Lorry's native-tool grants are removed and build scripts run
programs as under Cargo. QuickJS is included in the development archive.
Both roles read the shared preference from `/user/cfg/lorry.toml`, with
directory traversal and file permissions set accordingly. Preference with
fallback is sufficient; no strict source policy is planned. Installation
uses copying and the existing permission commands. Kernel command-line
access is milestone 1: the launchers' `--system-tty` parameter supplies
the `system-tty` boot option, which makes sys-tty run with `CAP_SYS`.
This resolves the System-console choice. The patch and test-gate policy is
the one stated in Steps. The v2 review decided: `/system/bin/rush` and
`/system/bin/sh` stay until the 1.99.1-3 toolchain is in use; `system-tty` is supported on
Cloud Hypervisor and Firecracker, not QEMU; the launchers get
`--no-network`; the standard qcow2 image's partition is 32 GiB; `ro-root`
goes too, its test working on a copy of the standard image; rush, rmux, and
Helix configuration is shared with None as `lorry.toml` is; `systest` cases
that need the System role stay driven from the System console; the `user`
cache is kept and nothing ships it filled. The v3 review decided: Lorry has
only Rust tests; the check that Lorry and Cargo produce byte-identical
output is a cross test, not a Lorry test; `/devtools` and `/system/bin` go
away in the toolchain as on the images; `run-dev.sh` is removed;
`full-test.sh` and the full gate run on Cloud Hypervisor, and a
`--vmm qemu` run skips what the System console drives; the
native Helix build stays a Lorry test on Motor OS and on Linux.

A second reviewer's pass over v3 changed these, each checked against the
code: Git sources are uploaded with each workspace, since they are not in
a repository; workspace state is shared with None, and the gate runs as
Interactive first; build scripts receive `PATH` and the compiler variables,
and the toolchain gains an `ar` launcher, before the native-tool grants go;
installation is `cp` to a temporary name, then
`mv`, with modes an Interactive process can set, and the archive can be
installed twice; the no-IP run turns networking off in the configuration
of an image copy and no longer uses `--no-network`, which stays a launcher
option with its own boot check; Firecracker skips the cross tests that
need the guest's development tools; one check, DHCP on a read-only root,
still needs QEMU in a Cloud Hypervisor run; the Helix test is selected by
name and Lorry's curl tests stay in every run; a `PATH` change needs a
reboot to reach ssh sessions; the upload includes new untracked files.

The v4 review is addressed here: workspace modes distinguish mutable data,
executable sources, and finished executables; source hashing uses None's
execute bit on Motor so both roles verify the same provenance; Git fixtures
cover both roles and executable-bit tampering; the curl fixture runs on
Motor as well as Linux, using only loopback; and the installation sequence
accounts for the caller's `rwx` becoming `r-x` on copy. A check of that
revision added how the gate's upload keeps the flags: a None `tar` for the
tree and Git sources, and a `chmod` of the executable files in the
repository objects that Interactive extracts. Milestones 1-5 have
no remaining design questions. The independent, optional milestone 6 is
still deferred:

1. **sys-io.** Can sys-io tell which tree an entry is in without walking its
   parents on every write? If not, milestone 6 is dropped. If so: should "no
   mode may grant None `w` in `/system` or `/user`" bind Interactive and
   System too, or only None's own requests? Deferred until milestones 1-5 are
   done.
