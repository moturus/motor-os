# Lorry workspace support: details

Reference for [workspace-plan.md](workspace-plan.md), v3, updated after
review on 2026-10-02. The main plan gives the scope and nine milestones.
This file keeps the evidence, implementation contracts, defect backlog,
policy choices, and decisions.

Milestone numbers refer to v3 unless explicitly marked v1 or v2. Finding
and early-fix numbers are retained from v1. The final section explains
each revision. The v3 review's recommended answers to policies A, B, and C
are incorporated into the plan. This documentation update implements no
code or runtime policy changes.

The existing baseline includes whole-workspace `metadata --no-deps`
without a lock or downloads (commits `8695aa16` through `ed5a5900`),
matching Cargo for `src/sys`. Builds still select one member per command,
with a shared lock and per-member admission. Inheritance and the other
manifest gaps below remain.

V1 consolidated `workspace-metadata-plan.md` and
`docs/plans/helix-rust-workspace-discovery.md`; the editor discovery work
described by the latter was already complete.

## Terms and graph boundaries

- **Member:** a package that belongs to the workspace.
- **Selected package:** a member selected for this command. Membership and
  selection are independent; a selected member can also be another
  selected member's dependency.
- **Workspace root:** the directory of the manifest with `[workspace]`.
  A virtual root has no package of its own.
- **Unit:** a compiler invocation or build-script execution, with its
  package, target, mode, compilation platform, features, and effective
  settings. "Member" is not a new unit kind.
- **Complete lock graph:** the dependency resolution for all members,
  including every optional member feature, dependency kind, and platform.
  It determines one shared `Cargo.lock`.
- **Reviewed graph:** the locked packages, feature sets, host/target
  contexts, and capabilities covered by admission. It need not include
  every inactive package in the lock.
- **Build graph:** the units needed for this invocation's selected members,
  target kinds, feature options, profile, host, and target platform.
- **Admission record:** `.lorry/dependencies-v2.toml`. Its filename is
  historical; the revised workspace format will have a new format version.
  Path packages remain outside portable dependency admission.
- **Dependency repository:** Lorry's source store, not the project's Git
  repository.
- **Contract:** a test under `tests/`, often comparing Lorry with the
  pinned toolchain's Cargo.
- **Resolution oracle:** the paired test of Cargo and Lorry lock resolution.
- **Unit oracle:** a comparison with Cargo's build/check/test unit graphs.
- **Bundle:** a self-extracting test executable produced by `test --bundle`.
- **W1:** the spec's name for today's single-selected-member support.

## Review findings (2026-10-01)

The plan was checked against Lorry's code, the source of Cargo 1.99 (the
version in the Motor toolchain), the rust-analyzer fork, and every manifest
in the local Helix, ripgrep, sed, and Motor OS checkouts.

Findings marked "probe" were reproduced on small fixtures with the host
Lorry and the paired Cargo (`1.99.0-dev`, `eb98b54bc`). The others were
read from source.

### What the review found in Lorry today

These exist now. None comes from this plan. Most are differences from
Cargo. Findings 15, 19, and 20 are defects of other kinds.

1. **A selected workspace member is not built the way Cargo builds it**
   (probe). Cargo runs rustc in the workspace root and passes
   `app/src/main.rs`. Lorry runs rustc in the member's directory and passes
   `src/main.rs`. Lorry also hashes the member's identity as if it were at
   the workspace root. So `file!()`, panic locations, `-C metadata`, and the
   final binary all differ. The Cargo identity suite has no workspace
   fixture, so it did not notice. See early fix 5.
2. **A member used as a dependency is compiled under a made-up path**
   (probe). Cargo passes `shared/src/lib.rs`. Lorry passes an absolute path
   and remaps it to `.lorry/path/sha256/<digest>/source`. `file!()` in that
   member prints the remapped path. See milestone 1.
3. **Diagnostics for path dependencies name files that do not exist**
   (probe). A warning in a path dependency prints
   `--> .lorry/path/sha256/85c8…/source/src/lib.rs:2:9`. A person cannot
   open that file. rust-analyzer cannot either. See milestone 3.
4. **Warnings from a cached unit are shown only once** (probe). The first
   `check` prints a path dependency's warning. The second restores the unit
   from the cache and prints nothing. Cargo prints the stored warnings of
   every unit it does not rebuild. See milestone 3.
5. **`run` and `test` do not give the program Cargo's environment** (probe).
   Cargo sets `CARGO`, `CARGO_MANIFEST_DIR`, `CARGO_PKG_NAME`, and the other
   package variables for the program it starts. Integration tests also get
   `CARGO_BIN_EXE_<name>` at run time. Lorry sets none of them. ripgrep's
   tests read `CARGO_BIN_EXE_rg` at run time. Also, `lorry run -p NAME`
   changes into the member's directory. Cargo keeps the caller's directory.
   See early fix 6.
6. **Git dependencies are compiled with their lints uncapped.** Lorry passes
   `--cap-lints` only for crates.io packages. Cargo passes
   `--cap-lints allow` for every package that is not a path package. A Git
   dependency that denies a lint can fail under Lorry and pass under Cargo.
   See early fix 7.
7. **`metadata` drops `[package.metadata]` and `[workspace.metadata]`**
   (probe). Lorry prints `null` for both. Cargo prints the tables. See early
   fix 8.
8. **`metadata` lists different features** (probe). Cargo lists the features
   requested by every dependency edge, on every platform. Lorry lists the
   features used on the one platform it was asked about. On a fixture with a
   Windows-only edge, Cargo printed `["viamid", "winonly"]` and Lorry
   printed `[]`. See milestone 6 and "Exact metadata".
9. **`check` accepts two options and ignores them** (probe).
   `check --workspace` checks only the root package, and fails at a virtual
   root. `check --examples` checks nothing and reports success. See
   milestones 5, 7, and 8.
10. **Lorry rejects member manifests that Cargo accepts** (probe). A member
    may not repeat the workspace's `resolver`. `src/sys/lib/rt.vdso` does,
    so `-p rt` fails today. A member with `[profile]` or `[patch]` is also
    an error in Lorry. Cargo prints a warning and ignores the table. See
    milestone 5.
11. **A package with more than 64 test files cannot be a dependency**
    (probe). Lorry reads the test targets of every dependency and stops
    at 64. `tokio 1.47.1` has 156. `src/sys` and Helix both depend on
    tokio. The error is "package describes more than 64 integration-test
    targets". See early fix 9.
12. **Configuration is read from a different place.** Cargo reads
    `.cargo/config.toml` from the directory the command runs in, and
    upward. Lorry starts at the selected package's directory and goes
    upward from there. See "Configuration" under milestone 5.
13. **Every command repeats work that Cargo skips** (probe). Every `check`,
    and every `build` that finds anything changed, compiles and runs every
    build script again, and copies every cached dependency artifact into a
    new directory. See milestone 2 and "Defect backlog and performance".
14. **`metadata` leaves out example and bench targets** (probe). For a
    package with `examples/demo.rs` and `benches/b.rs`, Cargo lists four
    targets and Lorry lists two. Nothing warns. rust-analyzer then does not
    analyze those files. See milestone 5.
15. **The spec's command list is incomplete.** It does not list `check`,
    `metadata`, `tree`, `locate-project`, or the `rustc` queries. The
    README lists the first three. Nothing documents the other two. The
    first patch that changes the spec's command list fixes this.
16. **Resolver 3 looks at the wrong Rust version.** With resolver 3, Cargo
    prefers dependency versions that suit the `rust-version` of the
    workspace's members. It looks at every member, also when only one is
    selected. It uses the compiler's version only when no member sets one.
    Lorry always uses the compiler's version. So `lorry vendor` can write a
    different lock than Cargo for a package like sed, which sets
    `rust-version = "1.88"`. A second, smaller difference: Cargo drops the
    `-dev` part of the compiler's version before it compares. Lorry does
    not. The Motor toolchain is `1.99.0-dev`, so Lorry treats a package
    that needs Rust 1.99 as too new. See early fix 10.
17. **A lint level that Cargo rejects makes Lorry panic** (probe). Lorry
    accepts `force-warn` in `[lints.rust]`. The code that builds the rustc
    command then hits `unreachable!`. Cargo has no such level and reports a
    manifest error. See early fix 11.
18. **A build script may not name a file outside its package** (probe).
    `rerun-if-changed` must name an existing path inside the package or
    `OUT_DIR`. Cargo accepts any path, also one that does not exist.
    `moto-rt-cabi`'s script names `../moto-rt/src/lib.rs`, and Helix's
    grammar script names files in `vendor/grammars` at the workspace root.
    See milestone 8.
19. **Two commands that publish the same directory can collide** (probe).
    Publishing is two renames: the old directory moves away, then the new
    one moves in. A second command in between makes one of them fail. The
    error is "failed to preserve previous output" or "failed to atomically
    install output". The old directory can stay behind under a hidden
    name. rust-analyzer's build-script pass and its check on save share one
    directory. See early fix 12.
20. **A killed command leaves its staging directory behind** (probe). The
    directory sits in the target directory under a hidden name. It holds a
    copy of every dependency artifact. Nothing removes it later.
    rust-analyzer kills the running check whenever it starts a new one, so
    this happens in normal editor use. The developer image's data
    partition has 4 GB. See early fix 12.
21. **Any change in the environment rebuilds every dependency** (probe).
    The cache key of a unit covers every environment variable of the
    Lorry process. So does the record that says "nothing changed". A
    probe set an unrelated `FOO=1`, and Lorry compiled the dependencies
    again. Cargo tracks only the variables that rustc reports as read.
    The results:
    - rust-analyzer sets `CARGO_LOG` for its check on save and not for its
      build-script pass. So its two passes never share dependency
      artifacts.
    - The editor and a terminal never share them either. Nor do two
      sessions whose environments differ in any variable. Two `make`
      recipes that run in different directories are such sessions,
      because `PWD` differs.

    See early fixes 15 and 13.
22. **Cargo settings in the environment are ignored silently** (probe).
    With `CARGO_PROFILE_RELEASE_OPT_LEVEL=1`, Cargo builds with
    `opt-level=1`. Lorry builds with `opt-level=3` and reports success.
    The same holds for `CARGO_INCREMENTAL` and `CARGO_BUILD_TARGET_DIR`.
    Lorry reads a few such variables and rejects three others. sed's image
    build sets `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`. See early fix 14.
23. **A new lock can get the wrong format version** (probe). Cargo picks
    the version from the lowest `rust-version` among the members. For
    `rust-version = "1.82"` it writes version 3. `lorry vendor` writes
    version 4. Helix and one `src/sys` member name 1.82. See early fix 10.
24. **A path package with a symbolic link is rejected** (probe). Lorry
    scans the whole directory of a path package. It skips only `.git` and
    `target`. It rejects symbolic links, and it stops at 20,000 entries or
    128 MiB. Cargo follows links and does not descend into another
    package. ripgrep's root directory has a symbolic link. In `src/sys`,
    the member `sys-io` contains the member `netstack`. See milestone 5.
25. **A build script does not see the caller's environment** (source).
    Cargo runs a script with the caller's environment. Lorry clears it,
    and treats a variable that the script names with
    `rerun-if-env-changed` as unset. Nothing warns. `moto-netstack`'s
    script reads `MOTO_NETSTACK_*` variables. Helix's build sets
    `HELIX_DISABLE_AUTO_GRAMMAR_BUILD` and `CXXSTDLIB_x86_64_unknown_motor`
    for its scripts. See milestone 8 and policy C.

### What rust-analyzer does

Read from the fork in `toolchain-src/rust/src/tools/rust-analyzer`, with
the developer image's Helix configuration.

- It asks `locate-project --workspace` for the workspace root manifest. It
  uses that one manifest for every later command.
  - In `src/sys`, Helix starts it at the workspace root. The answer is the
    root manifest already.
  - When it starts from a member's manifest, Lorry answers today with that
    same manifest. Resolved `metadata` for it describes only that member.
    So rust-analyzer treats the member as a workspace of its own.
- It runs `metadata --no-deps` first, then full `metadata`. Both carry
  `--filter-platform x86_64-unknown-motor`. If the full call fails, it
  keeps the `--no-deps` result.
- It asks for the compiler's settings with `rustc -Z unstable-options
  --print cfg`, and a similar query for the target. It runs both in the
  root manifest's directory, without `--manifest-path`. Lorry's handler
  needs a current package, so at a virtual root it fails. rust-analyzer
  then asks rustc directly, and loses the flags from Cargo configuration.
- It asks for Cargo's configuration with `-Z unstable-options config get`.
  Lorry answers with a usage error. rust-analyzer carries on. It then does
  not see an `[env]` table from Cargo configuration. No local workspace
  has one.
- **Build-script pass:**
  `check --quiet --workspace --message-format=json --manifest-path <root>
  --target-dir <dir> --target x86_64-unknown-motor --keep-going
  --all-targets`.
  - It runs at start, and after a reload that changed the workspace.
  - It runs on the next save after a file of a procedural-macro crate
    changed. Saving a build script does not run it again.
  - It does not run while the full `metadata` call fails.
  - It is a full check of the whole workspace, because the image sets
    `cargo.buildScripts.useRustcWrapper = false`.
  - When it fails, this version of rust-analyzer only writes to its log.
    Helix shows nothing. See milestone 9.
- **On save, default settings:** a file of a member's library sends
  `check --workspace`. A binary, test, example, or bench file sends
  `check -p <package id> --bin NAME` (or `--test`, `--example`, `--bench`).
  A file that belongs to no member also sends `check --workspace`.
- **On save, with `check.workspace = false`:** a file of a member sends
  `check -p <package id>`, with `--bin NAME` and the like for a file of
  such a target. A file that belongs to no member sends nothing. The path
  packages in `src/third_party` are such files.
- Every check also carries `--message-format=json` (or
  `json-diagnostic-rendered-ansi`), `--manifest-path <root>`,
  `--keep-going`, `--target`, `--all-targets`, and `--target-dir`.
- It kills the check that is still running when it starts a new one
  (finding 20).
- It joins a relative file name in a diagnostic to the workspace root. So
  rustc must run in the workspace root, as it does under Cargo.
- It cannot parse `lorry 0.1.0` as a Cargo version. So it never adds
  `--lockfile-path` or `--compile-time-deps` on its own.
- On Motor the fork never asks for metadata of the standard library's own
  workspace. That part needs no work.

## What this means for `src/sys`

Even Cargo cannot build or check `src/sys` as one workspace for Motor. With
the host cache and no network, `cargo check --workspace --all-targets
--target x86_64-unknown-motor` fails on a copy of `src/sys`:

- Across the workspace, Cargo turns on `moto-rt`'s `base` and `libc`
  features together. No single member uses that combination, and
  `moto-rt/src/libc.rs` fails to compile with it (8 errors).
- `getrandom 0.2.17`, used through `rand`, does not support the Motor target.

This is why `make` builds members one at a time, each with its own target and
features. So `src/sys` will keep working member by member. For `src/sys`,
whole-workspace metadata (milestone 6) and checking one member from the
workspace root (milestone 5) matter most. Whole-workspace builds serve
workspaces that build as a whole.

Facts about `src/sys` that the milestones rely on:

- It has 35 members: 33 are listed, and `lib/moto-io` and
  `tests/virtio-task-tests` are members because other members depend on
  them by path.
- Its Motor graph has 151 packages from outside the workspace: 135 from
  crates.io, 7 from Git, and 9 path packages in `src/third_party`.
- Its whole lockfile has 209 packages from outside the workspace.
- The graph contains tokio, so it needs early fix 9.
- `rt` (`lib/rt.vdso`) repeats `resolver = "2"`. Lorry rejects that today.
- Three members have build scripts: `moto-io`, `moto-netstack`, and
  `moto-rt-cabi`. None uses a native tool or a build-dependency.
  `moto-rt-cabi`'s script reads and names a file in another member,
  `../moto-rt/src/lib.rs` (finding 18).
- Three members have dev-dependencies: `frusa`, `motor-fs`, and
  `moto-netstack`. `moto-rt-cabi` is a static library.
- `motor-fs`, `tokio-tests`, and `rt.vdso` each have their own
  `.cargo/config.toml`. Under Cargo these apply only because `make` or the
  test scripts change into the member's directory first.
- Two members stay outside Lorry builds, because their builds need
  non-goals: `kernel` needs a custom JSON target and `build-std`, and `rt`
  needs `build-std`. `metadata` still describes both, so navigation works
  in them. `check` may work for them once the manifest and configuration
  changes are in (milestone 5). Today `-p rt` stops on two
  things: the repeated `resolver`, and a `[profile]` table in
  `rt.vdso/.cargo/config.toml`.

## What the real workspaces need

Taken from a scan of all 124 manifests. The last column says where this plan
provides it.

| Need | Helix | ripgrep | sed | `src/sys` | Where |
|---|---|---|---|---|---|
| `[workspace.package]` inheritance | yes | yes | | | 5 |
| `[workspace.dependencies]` | yes | | yes | | 5 |
| `default-members` | yes | | | | 5–6 |
| A workspace table with no `members` | | | yes | | 5 |
| Members found through path dependencies | | | | yes | 5 |
| A member that repeats `resolver` | | | | yes | 5 |
| Extra profiles in the manifest | yes | yes | yes | | 5, 8 |
| `debug` in the release profile | | yes | | | 8 |
| `[lints.clippy]` | | | yes | | 4, 5 |
| `[alias]` in `.cargo/config.toml` | yes | | | | 5 |
| Build scripts in members | 7 | 1 | 1 | 3 | 8 |
| A build script that runs a C and a C++ compiler | 1 | | | | 8 |
| A build script that reads files outside its package | 1 | | | 1 | 8 |
| Build-dependencies | yes | | yes | | 8 |
| Dev-dependencies | 8 | 7 | yes | 3 | 8 |
| `[[test]]` tables, `autotests = false` | | yes | | | 8 |
| Examples or benches | | yes | yes | | 5, 8 |
| `staticlib` | | | | 1 | 8 |
| Feature options on the command line | yes | | | yes | 5–8 |
| Source files included from outside the package | yes | | | | 2, 5 |
| Tests that read `CARGO_BIN_EXE_*` when they run | | yes | | | 3 (fix 6) |
| A dependency with more than 64 test files | yes | | | yes | first patches (fix 9) |
| A dependency's build script that compiles C | | 2 | | | today, with tool grants |
| A build script that reads the caller's environment | 2 | | | 1 | 8 |
| A symbolic link in a package directory | | yes | | | 5 |
| A member directory inside another member | | | | yes | 5 |
| `CARGO_TARGET_DIR` or `--target-dir` in its `Makefile` or scripts | yes | | | yes | 2 |
| A smaller review than the whole workspace | useful | | | | 6 |

Details behind the table:

- No local manifest uses a member glob, `workspace.exclude`, `[replace]`,
  `[workspace.lints]`, or `links`.
- Helix's build runs `-p helix-term --bin hx --release --locked --offline
  --no-default-features`. One member depends on another member as a
  build-dependency. `helix-loader` includes `../../languages.toml`, a file
  at the workspace root. Helix's Motor graph has 224 packages from outside
  the workspace, with 24 build scripts. The image's limit is 192, so
  Helix's graph is over it. sed's graph has 142.
- Helix's `helix-static-grammars` script compiles C and C++ sources from
  `vendor/grammars` at the workspace root. Lorry gives a build script a C
  compiler and an archiver, and no C++ compiler.
- Two build scripts run `git` to put a commit hash into the program:
  `helix-loader`'s and ripgrep's. Both carry on without it. Under Lorry
  they cannot run it, so the version text differs from a Cargo build.
- ripgrep's release profile sets `debug = 1`. Its `globset` bench uses the
  unstable `test` crate. Its root build script prints `rustc-link-arg-bin`
  only when it builds for Windows.
- sed has `[workspace.dependencies]` and no `members` key. Its bench sets
  `harness = false`. Its Motor build sets
  `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`.
- `src/tests/full-test.sh` passes
  `--features stdio-pipe,moto-async/host-construction-test` and
  `--manifest-path <member>`.
- Helix's real build needs far less than its whole workspace. For Motor,
  `-p helix-term --no-default-features` needs 145 packages from outside
  the workspace. The whole workspace with default features needs 224. Most
  of the difference is the `gix` graph. It comes in through the `xtask`
  member and through `helix-term`'s default `git` feature. The Motor build
  never compiles it. See "Admission scope" under milestone 6.
- ripgrep's `grep-pcre2` member depends on `pcre2-sys`, whose build script
  compiles the PCRE2 C sources. ripgrep's lock also has
  `tikv-jemalloc-sys`, for musl targets. The host's Cargo cache has
  neither, so the review could not scan that part of the graph.
- The Motor OS `Makefile` sets `CARGO_TARGET_DIR` in 38 places, one
  directory for each recipe. Lorry rejects that variable today.

## How Cargo treats each kind of package

Several milestones depend on these rules. They were read from Cargo 1.99.
"Selected" means named by `-p`, `--workspace`, or the default members.

| Rule | Selected package | Other member | Path package outside the workspace root | crates.io or Git package |
|---|---|---|---|---|
| Directory rustc runs in | workspace root | workspace root | package root | package root |
| Source path passed to rustc | relative to the workspace root | relative to the workspace root | absolute | absolute |
| What the identity hash names | path relative to the workspace root | path relative to the workspace root | absolute path | registry or Git URL |
| Lints | package's `[lints]`, no cap | package's `[lints]`, no cap | package's `[lints]`, no cap | `--cap-lints allow` |
| `CARGO_PRIMARY_PACKAGE` | set | not set | not set | not set |
| Clippy driver | runs and lints | runs; lints unless `--no-deps` | not used | not used |
| Dev-dependencies | built for its tests, examples, and benches | not built | never | never |
| Files copied to the profile directory | all its outputs | none | none | none |
| Stored warnings printed again | yes | yes | yes | no |

Three notes:

- For the last two columns, Lorry differs from Cargo in the first three
  rows. Lorry runs rustc in the workspace root. It tells rustc to print a
  made-up path of the form `.lorry/<kind>/sha256/<digest>/source/…` in
  place of the real one. That makes a build on Linux and a build on Motor
  produce the same bytes. This plan does not change it.
- Cargo also copies a `dylib` output of any package. Motor has no dynamic
  libraries, so the table leaves that out.
- A member is a package that the workspace lists, or that a member depends
  on by path from inside the workspace root. Exclusion prevents implicit
  discovery; an explicitly listed member takes precedence over exclusion.

## First patches

Four fixes depend on nothing else. They land before milestone 1.

- **Early fix 7.** Pass `--cap-lints allow` for Git dependencies, as for
  crates.io dependencies (finding 6). The cap is not part of a unit's
  identity, so no artifact changes.
- **Early fix 9.** Allow up to 1,024 described targets in a package, and
  keep 64 for the targets of a selected package (finding 11). tokio has 156
  test files and zerocopy has 70 benches. A dependency's targets only
  appear in `metadata`. They are never built.
- **Early fix 11.** Accept Cargo's four lint levels. Report `force-warn` as
  a manifest error and do not panic (finding 17).
- **Early fix 15.** Leave three variables out of the unit cache key and out
  of the unchanged-build record: `CARGO_LOG`, `RUSTUP_TOOLCHAIN`, and
  `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS`. Lorry removes them
  before it starts rustc ([process.rs](src/process.rs)), so they cannot
  change what rustc builds. The selected compiler is in the key by its own
  identity. rust-analyzer sets `CARGO_LOG` for its check on save and not
  for its build-script pass (finding 21). With this fix the two passes
  share dependency artifacts. Every other variable stays in the key.
  Narrowing the key further is early fix 13, which stays optional.

## Milestone 1: one unit graph

**Result.** The selected package's own targets are units on the same planner
and executor as its dependencies. The separate code that compiles the
selected package is gone. A single package builds exactly as before. A
workspace member is built the way Cargo builds it.

### Units

Extend the existing dependency planner and executor to include the
selected package's targets. A unit has a package identity, target,
compilation mode, host/target platform, resolved features, and effective
compilation settings. Settings include the profile and relevant compiler
flags. Represent compiling and running a build script as distinct
operations.

Workspace membership is a property of a package; selection is a property
of the command. Neither is a new unit kind. A member may be selected,
a dependency, or both. Avoid a second executor or a workspace-only cache.

The planner must preserve Cargo's distinctions between:

- A library used normally, as a host dependency, and in a test harness.
- A library and the same package's binaries that depend on it.
- Build-script compilation, execution, and consumers of its output.
- Dependency aliases and the actual extern names passed to rustc.
- Profile settings for a selected package, a dependency, and a host tool.

Deduplicate only equivalent units. Set `CARGO_PRIMARY_PACKAGE` only for
selected packages, and include effective compiler environment in freshness
without making selection a separate unit kind.

### Moving the targets

Move one kind of target in each patch: the library, then binaries, then
test harnesses, then check targets. Keep the single-package contracts as
the regression gate. Remove each separate root compilation path once its
replacement works.

The selected package's targets then compile in parallel, like
dependencies. `--keep-going` follows Cargo: units that do not depend on a
failed unit still run, and the command fails at the end.

In this milestone the selected package's units are not stored in the unit
cache. The cache key covers a package's own directory, and the selected
package may read files outside it. The existing record in the profile
directory still decides whether anything changed. Milestone 2 replaces
that record with one for each unit.

### Cargo's path rule

This is early fix 5, extended to members that are dependencies (findings 1
and 2). A package inside the workspace root is compiled the way Cargo
compiles it:

- rustc runs in the workspace root.
- It receives the source path relative to the workspace root.
- The identity hash names the package's path relative to the workspace
  root.
- Dep-info paths are resolved from the workspace root.
- There is no source remapping.

Path packages outside the workspace root, and crates.io and Git packages,
keep today's remapping. The cross/native byte identity needs it.

Add a selected member to the Cargo byte-identity fixture in the same
patch. This changes the bytes of member builds. They become what Cargo
builds.

### Proof

- The Cargo byte-identity suite, the cross/native identity suite on Motor,
  and every build, test, and check contract pass unchanged for single
  packages.
- The unit oracle starts here. It compares Lorry's plan with Cargo's
  `--unit-graph` output for `build`, `check`, and `test`. It compares
  nodes **and** dependency edges, extern aliases, selected roots,
  effective profiles, and compiler settings. A correct list of units with
  the wrong wiring is a failure. Normalize only documented differences,
  including Lorry's current full compilation of dependencies during check.

## Milestone 2: per-unit publication

**Result.** Each finished unit is published by itself, into one layout, and
is reused there. Finished outputs survive another selection and failure of
an unrelated unit. Replacement of the same unit follows Cargo's ordinary
artifact lifetime. This closes findings 19 and 20, and the copying part of
finding 13.

### Layout

Use the same layout for a root package and for a selected member:
`<target-dir>/lorry/[<triple>/]<profile>/`. Keep existing separate check
output naming until a change is needed. Selected binaries have Cargo-style
top-level names; dependency artifacts and harnesses use disambiguated unit
paths; examples use `examples/`.

Replace whole-profile staging and swapping with publication of completed
units. Building `-p a` and then `-p b` must leave both packages' completed
outputs available. Do not select a different layout merely because the
selection contains one member.

A fresh unit that is already in the target directory is reused where it
is. Lorry copies a unit from the cache only when the target directory does
not have it. This removes the copy of every dependency artifact that each
command makes today.

Preserve the existing unchanged-build shortcut for `build` and `run` in
the cases it covers today. Once the required inputs, artifacts, and policy
state are validated, the build phase starts no build-script processes.
Moving to per-unit records must not turn an unchanged build into a script
execution pass. For `run`, this concerns the build phase; the selected
program still runs.

Outside that shortcut, scripts continue to execute as today. The compiled
script is a unit like any other and is reused. A unit that consumes the
script's output stays fresh while that output is unchanged. General reuse
of script results across otherwise changed builds needs Cargo's exact
rerun rules and remains an optional optimization.

Migrate the old `lorry/packages/<name>/` layout explicitly. Ignore its
freshness records and either remove obsolete outputs under the lock or
tell the user how to clean them. Never interpret an old member result as
a result for a new selection. The spec's rule for that directory changes.

### Publication

For each completed unit:

1. Finish and validate its outputs before making them available to
   downstream units.
2. Publish files or the unit's output directory safely, with its success
   and freshness record last. A failed or interrupted write must not
   create a valid fresh record.
3. Preserve the previous completed result until replacement succeeds for
   compiler artifacts that can be staged. Recover an interrupted replacement
   under the same lock. A build script's `OUT_DIR` is the exception below.
4. Emit artifact/build-script messages only after their paths exist in
   the published layout.

A build-script run uses a stable, published `OUT_DIR` for the same unit,
including when its source changes. Its consumers use that path and the
generated files. Do not compile them against a temporary path and rename it
away afterwards. Cargo allows a failed replacement script to change files
in the previous `OUT_DIR`; Lorry does too. Invalidate the script's freshness
before running it, and publish a fresh success record only after it succeeds.
Never treat a failed or interrupted replacement as fresh. Cover embedded
`OUT_DIR` paths as well as JSON filenames. The pinned Cargo oracle confirmed
that the `OUT_DIR` path stayed the same after a `build.rs` edit, a failing
replacement changed a file there, and the old binary remained on disk.

Keep successful units when another unit fails. Under `--keep-going`,
independent units finish normally; dependents of failed units are skipped.
The final command status is failure. Successful artifact and build-script
messages must still name usable files after the command exits. This
replaces today's failure path that discards the whole check staging tree.

### Lock

Take one artifact-mutation lock for the chosen target directory, before
reading its freshness state or modifying outputs. Keep the lock file
outside the cleanable `lorry/` artifact tree; `clean` uses the same
lock and never unlinks the live lock file. Different target directories
remain independent, including the explicit directories used by the
Motor OS Makefile.

Release the artifact lock before running a user program or test harness.
Use the published unit paths for harnesses. A later build of another
selection must not remove a harness that is waiting to run, or another
package's generated files. Match Cargo's ordinary lifetime contract:
explicit `clean` or replacement of the same unit is not an immutable
snapshot guarantee. Do not add leases, a generation-retention service, or
a new artifact database for this feature.

### Cancellation

Native evidence on 2026-10-03: the first controlled Motor fixture killed
Lorry while its compiler wrapper was blocked, but incorrectly retained its
`Child` handle after `wait()`. Motor schedules descendant kills when the
process object is dropped, so that probe could not establish a termination
deadline. The corrected probe drops the handle and passed the native gate:
recovery completed after the killed child exited. A separate held-owner case
proved that the next build waits behind an active child. Linux's child-held
file lease contract passed too.

The approved Motor-only barrier keeps an atomic owner-PID record outside
`target/lorry/`, written under the artifact lock before any writer child is
spawned and removed before normal lock release. A later command that finds a
record from a killed owner holds the artifact lock while checking the retained
Motor process tree and waits until that owner's descendants are no longer
active. Lorry implements the record and process-tree wait. It removes a unit's
abandoned staging only after that wait and the lock have completed. A stale
record matching the current PID can only predate the current process and is
replaced. Other PID reuse or process-listing uncertainty fails closed, with a
bounded wait for descendants.
The native probe must block a compiler, kill Lorry, start the next Lorry
immediately, and verify that publication waits for the compiler's exit and
then recovers the edited result. It also tests a controlled live owner with a
child that remains active until the probe releases it. This needs no change
outside Lorry and adds no child process to ordinary builds.

An alternative is a Lorry-owned supervisor for compiler and build-script
children. It can hold a lease until each child exits, but requires another
process boundary and handoff protocol for every build and has a larger
performance and complexity cost. The owner chose the process-tree barrier.

The complete Lorry suite passed in 564 seconds on 2026-10-03, including the
native recovery and abandoned-staging probe. A prior parallel Rust-test run
failed in `builds_a_selected_workspace_member_into_shared_artifacts` when
executing its published binary: Linux returned `ETXTBSY` at the test's
`Command::output()` call. The fixture uses a PID-and-counter directory, and
the primary executable is committed after its staging file is closed.
Targeted `lsof` instrumentation did not reproduce the failure, so it did not
identify a remaining writable handle. A later passing run is not a root-cause
explanation.

The 2026-10-03 continuation traced one parallel Rust-suite run (357 passed,
10 ignored), which did not reproduce the intermittent failure. A separate
deterministic diagnostic then held a fork child before exec while an
`AtomicFile` executable staging descriptor was open. The parent committed
and closed its descriptor; launching the published file returned `ETXTBSY`.
After the held child exited, that executable launched successfully. This
demonstrates the descriptor-inheritance window used by Linux sandbox and
child-lease pre-exec hooks. The diagnostic was removed; its source patch and
logs remain under `/tmp/lorry-m2-inherited-writer-*`, with the parallel trace
under `/tmp/lorry-m2-writers.*`. The owner approved Cargo's policy. Commit
`1d47c873` atomically hard-links the completed compiler output on Linux
instead of opening a new executable for writing, with Cargo's copy fallback
when linking is unavailable. Primary and unit paths share one inode and its
permissions; Motor retains independent copies. A permanent Linux regression
holds a fork child before exec and successfully launches the published file
before releasing that child. It would reproduce `ETXTBSY` with the previous
copy implementation. Additional coverage checks atomic replacement, dropped
staging cleanup, preserved permissions, and symlink rejection.

Milestone 2 is complete. The final `tests/test-all.sh --warm` gate passed in
566 seconds on 2026-10-03: 362 Rust tests passed, the 10 ignored request-contract
tests ran in their dedicated curl driver, all host contracts passed, native
online vendoring succeeded without retries, Cargo byte-identity fixtures
passed, and cross/native Lorry self-builds were byte-identical on Motor.
Motor cancellation, held-child recovery, and abandoned-staging checks passed.
The full log is `/tmp/lorry-m2-hardlink-full.log`; native evidence is retained
below `target/lorry/native-self-tests/`. No temporary diagnosis remains in
the source. The Lorry-local `AGENTS.md` explicitly puts existing Lorry issues
in scope, so independent milestone-3 patches have continued.

### Native performance checkpoint, 2026-10-03

The release developer VM used 8 virtual CPUs and 8 GiB of memory. A tracked
copy of `src/sys` lived at `/devtools/tmp/lorry-m2-sys`; no repository system
sources changed. A release cross-built Lorry ran natively, using only the
Motor vendor context. Online vendoring preceded a cold check with empty
artifact and unit caches, followed by an unchanged warm check. Durations
include command startup and the SSH invocation.

| Command | Seconds |
|---|---:|
| `lorry vendor --accept-all` | 11.349 |
| Cold `lorry -v check` in `tools/sysbox` | 22.623 |
| Warm `lorry -v check` in `tools/sysbox` | 1.424 |
| Resolved `lorry metadata --format-version 1` | 1.411 |

The target tree contained 219,837,042 regular-file bytes in 1,117 files;
the per-user unit cache contained 71,210,520 bytes in 1,151 files. These are
logical file sizes, measured by a small standard-Rust walker, not filesystem
allocated-block counts. The warm check reused compiler units and reran the
five dependency scripts; the build/run no-script shortcut is a separate
contract. Logs and phase timings are `/tmp/lorry-m2-measure-metadata-fixed.log`
and `/tmp/lorry-m2-measure.tsv`.

The temporary copy granted exact, checksum-bound proc-macro capabilities to
`async-trait 0.1.89`, `bytemuck_derive 1.10.2`, and `derive_more-impl 2.1.1`.
The exercised scripts were `crossbeam-utils 0.8.21`, `proc-macro2 1.0.106`,
`quote 1.0.45`, the locked Git `parking_lot_core 0.9.12`, and the tracked
path `moto-io 0.1.0`; path/Git grants used exact source-tree digests. The
snapshot also retained exact `camino` and `serde_core` script grants from
setup; they were not exercised by this native check.

Two compatibility failures were diagnosed and fixed during setup.
`pin-project-lite 0.2.17` declares boolean `lib.doc-scrape-examples`, which
is inert for these commands and is now accepted with type checking.
Resolved metadata previously interpreted a sparse-index dependency position
as a manifest position. `async-trait`'s index interleaves dev dependencies
that the build manifest reader omits. Edges now retain their platform
condition, and metadata matches alias, package, dependency kind, and condition
instead of list position. A regression covers reordered declarations and
rejects identity/condition mismatches; resolver and Cargo metadata contracts
passed. The original native metadata failure took 1.420 seconds and was
preserved before the successful rerun.

A released lock does not itself prove that a killed command's compiler
or build-script children have stopped writing. Track child completion and
staging ownership, and clean abandoned staging only when no live writer
can own it.

Use the existing process and lock facilities where possible. Keep
cancellation cleanup bounded to Lorry-owned paths. Prove that Motor
releases the lock after cancellation, that surviving children cannot
corrupt the next command's publication, and that a subsequent invocation
recovers interrupted work. Diagnose any missing process-lifecycle support
before choosing a broader mechanism.

### Freshness and inputs

Give every published unit a freshness record. Retain rustc dep-info and
use its actual inputs when validating both cache entries and the
unchanged-build fast path. Cover:

- Paths relative to rustc's working directory.
- Files outside the package, allowed generated files, and symlink targets.
- File edits, removal, and symlink retargeting.
- Build-script input/output dependencies and the configuration that
  affects a compiler invocation.

A hash of the package directory alone is not sufficient. An allowed
external input must not silently disappear from freshness tracking.
Continue validating source integrity and admission on cache hits.
An unchanged-build shortcut must cover every requested unit and its
effective selection/settings; a previous selection's success is not a
freshness result for another selection.

With these records, the selected package's units are reused like any
other unit.

Retain today's conservative whole-environment key, less the three
variables of early fix 15. Narrowing it further is a separate
optimization, original early fix 13. If implemented:

- Discover compiler-read variables from dep-info `env-dep` entries,
  including the distinction between unset and empty.
- Use a base lookup key to locate candidates, then validate recorded
  input names and values. Include the observed values in the final
  artifact/freshness identity consumed by downstream units.
- Changing a variable read by a dependency invalidates that unit and its
  affected dependents. Unrelated units stay fresh.
- Unread variables should not invalidate ordinary compiler units.
  Build scripts keep their explicit environment and rerun rules.

A two-stage lookup that reuses the old dependency identity after rebuilding
it is incorrect: downstream units could retain the old compiled value.

### Target directory and environment settings

Support `--target-dir`, `CARGO_TARGET_DIR`, and `build.target-dir` on every
command that builds or cleans. Resolve relative paths with Cargo's rules
and precedence. Lorry's files stay under the chosen target directory's
`lorry/` subtree. The spec rejects the variable and the configuration key
today. That rule changes. Until milestone 5, `build.target-dir` is read
with today's configuration search.

Early fix 14 lands here. It covers unsupported `CARGO_PROFILE_*`,
`CARGO_BUILD_*`, `CARGO_UNSTABLE_*`, and `CARGO_INCREMENTAL` settings that
affect a command. Implement recognized supported settings with Cargo's
meaning, starting with the target directory. Do not silently ignore a
meaningful unsupported setting. Variables that only control Cargo's
terminal or network behavior may remain ignored by offline commands.
Milestone 8 adds the profile settings.

### `clean`

Record output ownership in unit freshness records. `clean -p` removes
outputs owned by those packages and invalidates the associated records;
it must not recursively delete shared dependencies belonging to other
packages. A full clean removes Lorry's artifact tree while preserving
its lock. `clean` accepts the same target, profile, and directory options as the
commands that build.

### Proof

Add lifecycle contracts for partial failure with `--keep-going`, ordinary
overlapping commands, a test harness waiting while another build runs,
package clean, cancellation, and recovery. After failure, verify every
emitted successful artifact and build-script path.

Add a fixture with an admitted dependency build script that records each
execution. After the initial build, unchanged `build` and `run` must start
no script processes. Changed relevant inputs invalidate the shortcut, and
a revoked grant or stale admission must still fail before code execution.
Use execution counts, not a timing threshold, for this contract.

Use fixtures that edit a file included from outside the package and
retarget an allowed symlink. Prove on Motor that a killed command releases
the lock and that the next command recovers.

## Milestone 3: structured output

**Result.** Tools and AI agents drive `build`, `check`, `test`, and `run`
without parsing Lorry's human text. The output is Cargo's JSON message
format, so tools written for Cargo work unchanged. What a test harness or
a program prints stays plain text, as under Cargo.

### Cargo's messages

Extend the existing Cargo message writer to `build`, `test`, and `run`
before adding another message subsystem. Support the approved `json`
and `json-diagnostic-rendered-ansi` modes (decision 6), space and equals
option forms, and Cargo's supported combinations.

Use Cargo package IDs and target descriptions, the same IDs as in
`metadata`. Emit compiler messages, completed artifact messages,
build-script results, and one final `build-finished` with the command's
success status. Keep JSON stdout separate from human progress and errors.

For `test` and `run`, emit `build-finished` before any harness or program
starts. Their stdout remains plain output as under Cargo; add no Lorry
test-result messages (decision 8). `test --no-run` reports published
harness paths as artifact executables with `profile.test`. Exercise
partial build failure.

Additional JSON rendering modes stay later work. Record that
`src/tests/test-gix.sh` uses the deferred `json-render-diagnostics` mode.

### Diagnostics

Cache hits replay warnings with the same package/target identity and
report freshness correctly (finding 4).

Packages inside the workspace root use real paths since milestone 1. Keep
nonmember remapping where required for cross/native byte identity, but
translate diagnostic paths back to real files before printing or
reporting them (finding 3). Pair both paths with diagnostic, dep-info,
and identity fixtures.

### Environment for `run` and `test`

This is early fix 6. For the program that `run` starts and for every test
harness, set what Cargo sets: `CARGO`, `CARGO_MANIFEST_DIR`,
`CARGO_MANIFEST_PATH`, the package variables, and library search paths.
For integration tests, also set `CARGO_BIN_EXE_<name>`. `run` keeps the
caller's working directory. A harness runs at its package root. Bundles
keep their own rules, because they run on another machine.

When milestone 8 adds build scripts for selected packages, `run` and
`test` also pass `OUT_DIR` and the script's `rustc-env` values, as Cargo
does.

### Lorry's own messages

Cargo reports its own errors as text. Lorry adds its own messages behind
a separate opt-in option (decision 7). They must never appear in the
Cargo stream consumed by rust-analyzer. AI agents are expected to use the
option and learn Lorry's messages.

This milestone adds the option and the error message. An error message
carries the error kind, the text, the file and line when known, the help
text, and the exit code. The codes are 1 for usage, 101 for failure, and
130 when interrupted.

The second kind of message is a summary of what a `vendor` run would
change. It lands in milestone 6, with the workspace review that it
describes.

The owner approved `--lorry-messages` on 2026-10-03. Its implemented interface
puts newline-delimited Lorry JSON messages on stderr,
while stdout retains the selected command's output, including Cargo JSON.
For example, `lorry build --message-format=json --lorry-messages` reports
compiler and artifact events on stdout and Lorry's own failures on
stderr. `-q` suppresses human progress. The new option changes message
presentation; it does not replace Cargo's format option. Usage, failure,
and compiler/script interruption tests cover the separate stream and codes.

### Cargo options that scripts expect

Agents and scripts written for Cargo pass these out of habit. Use one
parser where their semantics agree:

- `--locked`, `--offline`, and `--frozen` on existing commands
  that are already locked and offline. These flags must not weaken the
  separate acquisition/admission rules.
- `-q`, `-v`, and `--color` after the command name.
- `-j N` and `--jobs N`, using the existing executor limit.
- `test NAME`, a name filter for every harness, and options after `--`.
- `metadata` without `--format-version`: Cargo's warning and
  version 1 default.
- `locate-project` with or without `--workspace` or
  `--manifest-path`, including `--message-format plain`. Until milestone
  5 the manifest must be in the current directory or be named. Until
  milestone 9 a member's manifest still answers with itself.

Keep unsupported options explicit.

### Documentation and proof

Add a README section for tools and agents: the formats, Lorry's own
messages, exit codes, and how to avoid prompts. Update the spec's command
list, including the commands it lacks today (finding 15).

Compare each command's JSON with Cargo's on fixtures, using the existing
`differential-messages` check. Cover a failed build, a cache hit with
warnings, and `test --no-run`. Prove that Lorry's own messages appear
only with their option.

### Completed milestone, 2026-10-03

The final gate at commit `430fa0a5` passed `tests/test-all.sh --warm` in
629 seconds. It passed 371 regular Rust tests and 3 own-message integration
tests; 10 intentionally ignored Rust contracts ran in their dedicated
driver. The host contracts, paired Cargo native/cross artifact checks,
native Motor self-build and command equivalence, cross/native byte identity,
and interrupted-child recovery all passed. Online host and native vendoring
succeeded without external-failure retries. Strict offline Clippy validation
passed with `-D warnings`. No main-image or developer-image full OS gate was
run, because all milestone changes were confined to Lorry.

The first run failed after 203 seconds in the procedural-macro contract.
Its macro printed `proc-macro stdout is preserved`; the shared reporter
mistook that plain compiler stdout for JSON and failed after rustc succeeded.
The original log is `/tmp/lorry-m3-full.log`. Targeted tracing retained the
fixture and failure in `/tmp/lorry-m3-proc-macro-diagnosis.log`. Inspection
of the pinned Cargo compiler callbacks and an actual Cargo build confirmed
that Cargo forwards compiler stdout without caching it and retains plain
stderr. A diagnostic rerun also caught a human-output routing regression:
`run` command substitution received the macro's stdout before the program's
value. The final fix preserves existing human routing, forwards raw stdout
in JSON mode, and caches/replays stderr alone. The procedural-macro contract
now asserts these cold and fresh output boundaries. Temporary diagnostics
were removed before validation and commit.

Final full-suite evidence is `/tmp/lorry-m3-full-fixed.log`; native evidence
is under `target/lorry/native-self-tests/self-20261004T022044Z-3597527/`.
The focused verified regression and strict Clippy logs are
`/tmp/lorry-m3-proc-output-contract-verified.log` and
`/tmp/lorry-m3-clippy-verified.log`. The original failure was diagnosed and
fixed, rather than resolved by a passing rerun alone.

## Milestone 4: `lorry clippy`

**Result.** `lorry clippy` lints a package the way `cargo clippy` does, on
Linux and natively on Motor. It takes the same options as `check`. So an
agent gets the lints as JSON, and a user can set rust-analyzer's
`check.command = "clippy"`. The shipped Helix configuration keeps `check`
(decision 12).

### Contracts

- Reuse check's planning, options, Cargo messages, and artifact rules.
  Invoke `clippy-driver` directly; do not enable general compiler
  wrappers.
- The driver must be the sibling of the selected rustc from the same
  toolchain. Compare `clippy-driver --rustc -vV` with rustc. A missing or
  mismatched driver is a clear error.
- Default linting covers workspace members, including members used as
  dependencies and members' build scripts. `--no-deps` restricts
  linting to selected packages using `CARGO_PRIMARY_PACKAGE`. Packages
  outside the workspace are compiled by plain rustc.
- Pass lint arguments after `--` through `CLIPPY_ARGS`, with the
  driver's `__CLIPPY_HACKERY__` separator. Preserve its behavior for
  capped lints, compiler queries, and `--cfg clippy`.
- Include driver identity in member unit identity/freshness; keep check
  and Clippy outputs distinct.
- Let the driver find `clippy.toml` or `.clippy.toml` (decision 14). Set
  `CARGO_MANIFEST_DIR` and pass `CLIPPY_CONF_DIR` through.
  Track configuration inputs outside the member, environment inputs,
  and discovery of a newly created configuration file.
- Accept/pass `lints.clippy` as Cargo does even for plain rustc.
  Lints that invoke `$CARGO metadata` must reach Lorry's metadata.
- For a member that is a dependency, allow the Clippy configuration file
  above its directory as an input. Milestone 5 extends this to other
  files.

### Which packages count as members

The rule is "a unit of a workspace member goes through the driver". The
Clippy code does not change when later milestones widen what that covers:

- Until milestone 5, the members are the ones that the workspace lists,
  as today.
- From milestone 5 on, members found through path dependencies count too.
- From milestone 7 on, `clippy --workspace` and repeated `-p` work,
  because `clippy` takes `check`'s options.
- From milestone 8 on, a selected member's own build script goes through
  the driver too.

Until milestone 5, a path dependency inside the workspace root that the
workspace does not list is not linted. Lorry prints a note when that
happens, and the spec says so. Do not silently claim Cargo's workspace
lint coverage.

### The native driver

The native driver is toolchain/image work outside Lorry (decision 11).
Investigate adding `src/tools/clippy` alongside rustfmt in
`src/toolchain-native.sh`; stage the driver, not `cargo-clippy`.
Preserve identity/ELF checks, size gates, toolchain build keys, and image
tests. Motor compilation and sysroot discovery still need validation;
expect an image-size cost comparable to rustc. Use the repository's full
debug/release gates for that broader scope.

This work depends on nothing in Lorry and has a long lead time. It can
start at any time.

### Patches

1. Find `clippy-driver` beside the selected rustc and check that the two
   match.
2. Accept `[lints.clippy]` and pass it as Cargo does, for `check`,
   `build`, and `clippy`.
3. `lorry clippy`: the check path with the driver for member units, its
   own output naming, `--no-deps`, and lint options after `--`. A contract
   compares the output with `cargo clippy --message-format=json` on a
   fixture with a known lint.
4. `CLIPPY_CONF_DIR` pass-through, with a contract that a changed
   `clippy.toml` is picked up, including one above the package root.
5. The native driver: build, validate, and stage it in the developer
   image.
6. Native acceptance in the VM, with human and JSON output.
7. Documentation: the spec, the README, `docs/helix.md`, and
   `docs/build-rustc.md`.

Patches 1 to 4 work on Linux right away, because the Linux toolchain
already has `clippy-driver`. Patch 6 waits for patch 5.

`clippy --fix` stays later work (decision 13). A rustfix dependency or
other edit machinery needs its own design and dependency decision.

### Progress and focused evidence

The Linux implementation is committed in `70c0bf62`, `f50ce0cd`, `a544f655`,
and `26581c1a`. Focused parser, CLI, discovery, cache, and configuration
tests passed, along with strict Clippy validation. The offline paired
contract covers member libraries and build scripts, external-package
exclusion, fresh warnings, `--no-deps`, denied lint arguments, parent
configuration discovery, edits and nearer-file creation/removal, and a
relative `CLIPPY_CONF_DIR` override. Its metadata lint reaches Lorry via
`$CARGO` and matches Cargo's diagnostics. Evidence is in
`/tmp/lorry-m4-config-contract.log` and
`/tmp/lorry-m4-metadata-lint-current-contract.log`. The first metadata-lint
invocation used the stale milestone-3 release binary and failed before
Clippy; its log is `/tmp/lorry-m4-metadata-lint-contract.log`. Checking the
binary timestamps identified the setup error, and the current binary passed.

The native recipe and assembly integrity contracts passed in
`/tmp/lorry-m4-native-{recipe,assembly,resolution}-contract.log`. The native
build completed in `/tmp/lorry-m4-native-build.log`. It adds Clippy to the
same stage-2 bootstrap invocation as rustc and rustfmt, validates the
compiler identity and ELF, and stages only the driver and its TMPDIR
launcher. The native configuration schema is `motor-native-config-v6`;
the Clippy recipe is `motor-native-clippy-v1`. Assembly
`51adb8693d4efc14ba72ee560484b7335c2f19788966631cf13fb1225cca6155`
records driver SHA-256
`dd179b841119f9444e2c468b2d3aecd3275505305897d677e005ffb9b207935a`.
The stripped driver is 131,375,832 bytes; rustc is 119,030,776 bytes.
The Rust, mlibc, Helix, ripgrep, and sed source checkouts remain clean and
at their original revisions; no source patches were authored outside Motor OS.
The full debug gate passed in `/tmp/lorry-m4-full-debug.log`: 0.9 minutes
of preparation and 16.8 minutes of testing. The full release gate passed in
`/tmp/lorry-m4-full-release.log`: 0.6 minutes of preparation and 9.6 minutes
of testing. The final release developer-image gate passed in
`/tmp/lorry-m4-full-dev-release-fixed.log`: its repository phase took 0.2
minutes of preparation and 12.8 minutes of testing. Its native tools, HTTP,
and source-build phases also passed. The complete Lorry suite passed in 516
seconds, with 377 Rust tests, 3 own-message integration tests, the dedicated
contracts, and Cargo native/cross byte identity. Online host and Motor
vendoring succeeded without retries.

Native evidence is in
`target/lorry/native-self-tests/self-20261004T044525Z-3859854/summary.txt`.
The native gate took 224.339 seconds and proved self-build, cross/native
identity, child recovery, matching Clippy/rustc identity, human and JSON
lint diagnostics, a metadata lint through `$CARGO`, and denied lint exit 101
with a separate own-message error. The existing analyzer and formatter
image-size gates passed. Milestone 4 is complete.

The first release developer-image run passed its repository, HTTP, and
native source phases, then failed the Lorry suite after 146 seconds in
the paired failed-build diagnostic comparison. The original log is
`/tmp/lorry-m4-full-dev-release.log`. Lorry processed `first` and reported
its deprecation warning before `second` failed. Cargo processed `second`
first and never visited `first`, so its stream contained only the error.
Recreating the original fixture path reproduced the exact mismatch; Cargo's
job-queue debug log confirmed the missing dispatch. Evidence is in
`/tmp/lorry-m4-failure-order-diagnosis.log` and the retained fixture
`/tmp/lorry-check-contract-AMfPGV`.

The pinned Cargo queue assigns the same cost to independent leaf units,
breaks ties through its hash map, and stops dispatch after an error. One
job therefore does not guarantee an order between the two binaries. The
test incorrectly required diagnostics from an independent unit. Commit
`f2aef013` moves the warning into the failing binary's library prerequisite
and also compares a build selecting only the failing binary. The exact
diagnostic comparison, warning/error requirements, exit status, and failed
finish event are unchanged. The focused contract passed in
`/tmp/lorry-m4-failure-order-fixed-contract.log`; temporary instrumentation
was removed. The corrected full developer gate passed in
`/tmp/lorry-m4-full-dev-release-fixed.log`.

## Milestone 5: workspace model and selection

The first patch shares source metadata's membership reader with builds and
applies the same default-member rules. Focused manifest tests passed (23),
as did `/tmp/lorry-m5-membership-contract-excluded.log` and
`/tmp/lorry-m5-implicit-clippy-contract.log`. The latter now discovers its
linted dependency member implicitly. Two earlier contract invocations failed:
temporary HOME hid Cargo's offline cache, and the package-limit fixture's
unlisted namesake became an implicit member, causing duplicate-name rejection.
The driver now preserves CARGO_HOME and explicitly excludes the intended
nonmembers. Both Cargo and Lorry reject the duplicate when those exclusions
are removed; the package-limit assertions are unchanged. Original logs are
`/tmp/lorry-m5-membership-contract.log` and
`/tmp/lorry-m5-membership-contract-fixed.log`.

Commits `60344a1e`, `05a3c00b`, and `e703746e` establish common discovery,
inherited package identity, and metadata fields with original-source type
diagnostics. The remaining package fields are now implemented too. Focused
manifest tests (23) and paired Cargo contracts passed in
`/tmp/lorry-m5-inherited-identity-contract.log`,
`/tmp/lorry-m5-inherited-source-contract.log`,
`/tmp/lorry-m5-inherited-metadata-contract-fixed.log`, and
`/tmp/lorry-m5-inherited-all-fields-contract.log`. Strict Clippy passed in
`/tmp/lorry-m5-inherited-all-fields-clippy.log`. An intermediate new
source-location assertion expected an extra trailing colon; its diagnosis
confirmed the correct workspace line, and the exact-line assertion was fixed.

Readme work exposed a preexisting Lorry defect: explicit `readme = false`
still discovered an existing README.md. The unchanged-binary reproducer in
`/tmp/lorry-m5-readme-false` produced that path in Lorry metadata and null in
Cargo metadata; the paired JSON outputs are beside it. Parsing now preserves
the boolean's meaning instead of treating false as an absent field. The
contract proves explicit false/true, inherited paths and default discovery,
Cargo's rejection of inheriting false, and all publish forms. Include/exclude
arrays are retained for the member-file work.

Member and default-member component globs now share a standard-Rust matcher
with linear star closure. Focused manifest tests (23), strict Clippy, and
paired metadata/build contracts passed in `/tmp/lorry-m5-globs-unit.log`,
`/tmp/lorry-m5-globs-clippy.log`,
`/tmp/lorry-m5-globs-metadata-contract.log`, and
`/tmp/lorry-m5-globs-build-contract.log`. Cargo comparisons cover star,
question mark, ranges and negated classes, explicit exclusion overrides,
matching files, missing manifests, unmatched patterns, and empty virtual
workspaces. Recursive `**` is rejected explicitly.

Workspace lint inheritance and rustdoc lint flags passed the 23 focused
manifest tests, the paired Clippy contract, and strict Clippy in
`/tmp/lorry-m5-inherited-lints-{unit,contract,clippy}.log`. The fixture inherits
all three namespaces, including lint priorities, in explicit and implicit
members. Both Cargo and Lorry reject a member override alongside inheritance.

Configuration discovery now separates the invocation directory from the
workspace policy root. Sixteen focused configuration tests and the paired
Cargo target-directory contract passed in `/tmp/lorry-m5-config-unit.log` and
`/tmp/lorry-m5-config-contract.log`. The contract gives a member a different
Cargo target directory and proves root invocation and manifest-path selection
still use root configuration, while member invocation uses its own Cargo
configuration. It also covers alias acceptance without execution, an
actionable member-local Lorry configuration error, and moving that file to
the workspace root.

Manifest discovery now searches the invocation directory and its parents,
including relative invocation paths used by locate-project. Manifest-path
selection establishes the workspace independently of the selected member.
The 23 focused manifest tests and paired build/source-metadata contracts
passed in `/tmp/lorry-m5-parent-discovery-unit.log`,
`/tmp/lorry-m5-parent-discovery-contract.log`, and
`/tmp/lorry-m5-parent-discovery-metadata-contract.log`. Cargo comparisons
cover subdirectory invocation, locate-project output, and a root manifest
path combined with another member's package selection.

**Result.** Every command uses the same workspace membership and manifest
inheritance rules. One member can be built or checked from the workspace
root. The shared model is ready for multi-member execution.

Workspace dependency inheritance now rebases paths from the root, preserves
renames, adds member features, and permits optionality only in members.
The pinned Cargo 1.99 default-feature policy is covered for editions 2021
and 2024 with unspecified, enabled, and disabled workspace defaults.
Collected manifest warnings are deduplicated at command reporting, and quiet
mode suppresses them. Missing inherited dependencies and even unused optional
workspace dependencies fail. The 23 focused manifest tests, strict Clippy,
and paired metadata/build contracts passed in
`/tmp/lorry-m5-inherited-dependencies-unit.log`,
`/tmp/lorry-m5-inherited-dependencies-clippy.log`,
`/tmp/lorry-m5-inherited-dependencies-metadata-contract.log`, and
`/tmp/lorry-m5-inherited-dependencies-build-contract.log`.

### Workspace and manifest loading

Unused custom/dev/release/test profiles are now read without rejecting
settings that cannot affect the command. Unsupported selected profile keys
still fail before compilation, including explicit test-profile overrides;
known values retain validation. The 23 focused manifest tests, strict
Clippy, and paired Cargo build/check/no-run contract passed in
`/tmp/lorry-m5-unused-profiles-unit.log`,
`/tmp/lorry-m5-unused-profiles-clippy.log`, and
`/tmp/lorry-m5-unused-profiles-contract.log`.

Member profiles, patches, replacements, and conflicting explicit resolvers
now warn and use root settings. Source descriptions and builds share root
resolver computation; virtual roots default to resolver 1 with the Cargo
edition warning. Nested workspace roots remain rejected. Focused manifest
tests (23), strict Clippy, and paired build/metadata contracts passed in
`/tmp/lorry-m5-workspace-settings-unit.log`,
`/tmp/lorry-m5-workspace-settings-clippy.log`,
`/tmp/lorry-m5-workspace-settings-build-contract.log`, and
`/tmp/lorry-m5-workspace-settings-metadata-contract.log`.

Lorry currently has three workspace-table readers: builds, source metadata,
and path/Git dependency loading. Replace their workspace-table handling with
one implementation. Retain descriptive loading and build-capable loading:
metadata must describe packages such as `kernel` without claiming Lorry
can compile their custom targets.

The workspace model records the root, current manifest/package, canonical
member directories, default members, resolver, root profiles and patches,
and inheritable fields. It does not hold the command's selected members.

Implement:

- `members` may be absent, as in sed.
- Explicit members, a root package, and members reached through normal,
  dev, build, and target-specific path dependencies. Patches alone do not
  discover members.
- `default-members`, `exclude`, and metadata tables.
- Cargo's resolver defaults: a virtual root without an explicit resolver
  uses resolver 1, with the warning for member editions that imply a newer
  resolver.
- Inheritance of all 16 Cargo-supported `workspace.package` fields.
  Rewrite inherited `readme` and `license-file` paths relative to the
  member.
- `workspace.dependencies`: inherited paths are relative to the root;
  member features are additive; workspace dependencies cannot be optional.
  Preserve the pinned Cargo 1.99 edition rules: edition 2024 members may
  override `default-features`; older editions warn and ignore a member's
  `false` when the workspace has not disabled defaults.
- `workspace.lints` and `[lints] workspace = true`, with no extra member
  lints alongside inheritance.
- Component globs `*`, `?`, and `[...]` in `members` and
  `default-members`. Reject unsupported `**` explicitly. Follow Cargo's
  behavior for matches that are files or directories without manifests.
  `exclude` is a path prefix, not a glob; an explicit member wins over
  exclusion, while a glob match does not.
- Cargo's warning-and-ignore behavior for member `profile`, `patch`,
  and `replace` tables and conflicting member resolver declarations.
  Reject `replace` at the root and `package.workspace`.
- Accept `lints.clippy` (since milestone 4) and `lints.rustdoc`. Preserve
  the manifest lint flags Cargo passes even when that lint tool does not
  run.
- Read unused profiles without rejecting settings that cannot affect the
  command. Validate all settings that contribute to the selected profile.
- Discover example and bench targets, explicit target tables, and
  auto-discovery settings for metadata. Compilation support follows in
  milestone 8. Until then, selecting an unsupported target is an error.

Keep `metadata --no-deps` independent of the lock, admission state,
downloads, and buildability. Preserve its existing offline contracts.

### Members' files

Member compilation may legitimately read files outside the member's own
directory. `helix-loader`, for example, includes a workspace-root file.
Preserve the compiler access that selected packages have today for
other workspace members too. Milestone 2's freshness records track those
files. Retain current source boundaries for crates.io, Git, and nonmember
path dependencies.

For members, use Cargo's package file set: do not descend into another
package, and do not reject a symbolic link merely because it is a link
(finding 24). Dependency archive size/entry limits must not be applied to
the member's editable tree. Keep the existing dependency-source rules for
nonmembers.

The symbolic-link rejection was reproduced before the fix: Cargo succeeded,
while Lorry rejected the shared member during resolution. The isolated logs
are `/tmp/lorry-m5-member-links-original-isolated-fixed-toolchain.log` and
`/tmp/lorry-m5-member-links-cargo-isolated.log`. Resolution and path evidence
now use an editable file reader for members, leaving nonmember rules intact.
The reader matches Cargo's package file list for plain trees, include rules,
Git ignores, tracked files, and symlinks, and stops at nested packages. The
existing Git dependency's walker feature is enabled with an offline lock
update; no external source was edited. The shared reader and its integration
form one larger patch because all source-verification callers must agree.
The focused Cargo file-list test and strict Clippy passed in
`/tmp/lorry-m5-member-reader-cargo-unit-final.log` and
`/tmp/lorry-m5-member-reader-clippy.log`. Compiler cache/freshness integration
is the next patch; this source-validation patch alone does not fix builds.

Compiler caches and completed profiles now use the member reader too.
Every member's dep-info permits external reads and participates in published
unit validation and library-cache restores. Completed profiles record member
dep-info, including host paths, and distinguish editable roots from fixed
dependency trees in freshness format 5. Workspace-manifest changes invalidate
the shortcut. Path patches naming members use the same reader. The focused
freshness tests, strict Clippy, and paired workspace contract passed in
`/tmp/lorry-m5-member-cache-freshness-unit-final.log`,
`/tmp/lorry-m5-member-cache-clippy.log`, and
`/tmp/lorry-m5-member-cache-contract-corrected-probes.log`. The contract checks
external edits, warm symlink retargeting, unchanged-profile reuse, library
cache restores, strict validation, and member sources exceeding configured
archive file/byte limits.

The initial expanded contract failed (`/tmp/lorry-m5-member-cache-contract.log`).
The retained fixture and trace (`/tmp/lorry-m5-member-cache-diagnostic-trace.log`)
showed that Cargo reused old contents after a symlink retarget to an older
file; both target files had identical mtimes. Cargo's fingerprint code checks
the followed file's mtime. The warm Cargo log reports both units fresh, while
a cold shared-member build produces the expected contents
(`/tmp/lorry-m5-member-retarget-cargo-{warm,cold}.log`). Lorry's approved
retarget validation passed. The comparison now keeps Lorry warm and uses
cold Cargo for this content oracle. The unchanged-build probe now establishes
the same build selection before its warm assertion, and its inverted grep
checks are explicit failures instead of relying on shell errexit.

The remaining discovery audit reproduced an automatic-library bug: source
metadata included `src/lib.rs` despite `autolib = false`, while Cargo
reported only the binary (`/tmp/lorry-m5-autolib-{original,cargo}.json`).
The reader now honors that flag in all modes, while an explicit `[lib]`
remains enabled. Root manifests accept and validate the flag too. The paired
workspace metadata contract passed in `/tmp/lorry-m5-autolib-contract.log`;
it also builds a package whose disabled library contains `compile_error!`,
and both tools reject a nonboolean flag.

The local corpus now contains 128 manifests. The first source-only scan
matched Cargo for 111; the other 17 had the same binary-discovery defect.
Helix, gix, and rush rename an inferred binary through an explicit source
path, but Lorry retained both names. Original projections and failures remain
in `/tmp/lorry-m5-corpus/`. Explicit names and paths now suppress inferred
binaries without removing explicit targets that share a file. The paired
metadata/run contract passed in `/tmp/lorry-m5-renamed-bins-contract.log`.
The new scan matches all 128 projections, recorded in
`/tmp/lorry-m5-corpus-source-scan-fixed.log` and `/tmp/lorry-m5-corpus-fixed/`.

Focused target probes retained in `/tmp/lorry-m5-binary-discovery-diagnosis/`
also showed incorrect named-bin path inference, edition-2015 auto-discovery,
and rejection of symlinked Rust binary files. The reader now follows Cargo's
named inferred paths, legacy edition defaults and warnings, and non-dotfile
discovery. Metadata normalizes source components without resolving links.
The paired contract and strict Clippy passed in
`/tmp/lorry-m5-target-discovery-{contract,clippy}.log`; the contract also
builds an edition-2015 package whose uninferred binary cannot compile.

The read-only build-capable audit is retained in
`/tmp/lorry-m5-build-loader-scan-fixed.log`: 90 of 128 manifests load.
The other 38 explicitly reject dependency/target features assigned to later
milestones (32), multi-package selection (3), procedural-macro roots (2),
or inert badges (1). Temporary audit instrumentation was removed. The
badges rejection is corrected in the next focused patch.

Selected packages now accept the inert badges table too. The paired
build/metadata contract passed in `/tmp/lorry-m5-badges-contract.log`.

The first full milestone gate failed in 40 seconds with 379 Rust tests
passing and one stale assertion (`/tmp/lorry-m5-full.log`). Enabling gix's
dirwalk feature added exactly ten locked packages in `71d110fb`, but the
manifest test still expected 154 instead of 164. The test now checks the
enabled feature and the exact new count. Its focused run passed in
`/tmp/lorry-m5-lock-count-test.log`; no product behavior or assertion strength
changed. The complete gate is rerun after this test-only correction.

The rerun passed all host contracts and both Cargo byte-identity targets,
then failed native preparation at the unchanged depth limit of 16
(`/tmp/lorry-m5-full-lock-count-fixed.log`, 305 seconds). A diagnostic native
run preserved the exact selected graph in `/tmp/lorry-m5-depth-lorry-graph.json`
and its log in `/tmp/lorry-m5-depth-diagnostic-native.log`. The 17-package
path runs through gix, gix-dir, gix-worktree, gix-index, and finally
thiserror-impl, syn, quote, proc-macro2, and unicode-ident. Cargo's host and
Motor compiler graphs confirm the same package path. An initial comparison
of distinct packages on Cargo's longest *unit* path incorrectly reported 16;
weighting package transitions correctly reports 17. No policy bug was found.

The member reader now calls the same gix-dir walker directly, with public
gix index/ignore/pathspec APIs and filesystem capabilities. Gix retains its
attributes feature but no longer depends on gix-dir; Lorry depends on it
directly. Cargo's compiler graph now has a maximum package depth of 16
(`/tmp/lorry-m5-depth-cargo-direct-walker-unit-graph.json`). The package count
remains 164, and no policy limit, timeout, or external source was changed.
Temporary policy diagnostics were removed. Cargo file-list comparison and
strict Clippy passed in `/tmp/lorry-m5-direct-walker-{unit,clippy}.log`.

The next full run failed in 31 seconds in the executable-link unit test
(`/tmp/lorry-m5-full-direct-walker.log`). Its `/bin/true` fixture was copied
in the parallel test process. A concurrent fork can inherit the copy's
writable descriptor, leaving the supposedly completed source inode busy.
The targeted reproducer in `/tmp/lorry-m5-executable-fixture-diagnosis/`
gets `ETXTBSY` while a stopped child holds that descriptor; the same hard link
executes after that child releases it. Both executable-link tests now create
their completed source in an isolated helper process. Publication, inode,
mode, symlink, and held-child execution assertions are unchanged. Fourteen
focused atomic tests passed in `/tmp/lorry-m5-executable-fixture-tests.log`.
This is a test-only correction; no retry or product publication change.

The following gate passed its 381 Rust tests, three own-message tests, all
host contracts, and Cargo byte identity, then failed while inspecting Clap's
examples (`/tmp/lorry-m5-full-executable-fixture-fixed.log`, 268 seconds).
Clap's cached manifest and Cargo's target configurator confirm that
`example.doc-scrape-examples` is an inert boolean for the supported commands.
The shared auxiliary-target reader now accepts and validates it just like
the existing library flag. The paired metadata contract passed in
`/tmp/lorry-m5-example-scrape-contract.log`, including a nonboolean rejection.

The final full milestone gate passed in 677 seconds on 2026-10-04
(`/tmp/lorry-m5-full-example-scrape-fixed.log`). It ran 381 Rust tests
(ten contract tests intentionally run through their dedicated drivers),
three own-message tests, all host contracts, Cargo native/cross byte identity,
and native Motor self-build, cross/native identity, and interrupted-child
recovery. Native preparation took 165.356 seconds and the native gate took
256.335 seconds. Host and native online vendoring succeeded without retries.
The original failures and their diagnoses above remain part of the evidence.

### Configuration

Cargo configuration comes from the invocation directory and its parents,
then `CARGO_HOME`, as Cargo does. Neither `-p` nor `--manifest-path`
moves the configuration search to a member. An `alias` table may exist,
but Lorry does not execute aliases. The spec says today that aliases must
be rejected. That rule changes.

Project `lorry.toml` is the nearest file at or above the workspace root,
layered over the existing user/system configuration. A member-local
`lorry.toml` is an actionable error identifying where to move it.
System constraints remain enforced.

Find the nearest `Cargo.toml` at or above the current directory when no
manifest path is supplied. The spec lists this search as unsupported
today. That rule changes. Keep manifest discovery separate from Cargo
configuration discovery. Rustc configuration queries at a virtual root
must work without selecting a package.

Support `--manifest-path` on every command that reads a manifest.

Rustc configuration queries now load descriptive workspace context without
selecting a buildable package. Multi-member and empty virtual roots work
without lockfiles or admission state, and create no project artifacts.
Sixteen configuration tests, strict Clippy, the exact query contract, and
the Cargo configuration-discovery contract passed in
`/tmp/lorry-m5-virtual-queries-config-unit.log`,
`/tmp/lorry-m5-virtual-queries-clippy.log`,
`/tmp/lorry-m5-virtual-queries-contract.log`, and
`/tmp/lorry-m5-virtual-queries-config-contract.log`.

Every manifest-reading command now accepts the option, including build,
run, test, clean, vendor/upgrade, review, and rustc configuration queries.
Relative paths resolve against the supplied invocation directory. The
23 manifest tests, 24 CLI tests, and strict Clippy passed in
`/tmp/lorry-m5-all-manifest-paths-{unit,cli,clippy}.log`. The initial contract
(`/tmp/lorry-m5-all-manifest-paths-contract.log`) failed because its new
rustc query omitted the required trailing `-- -O`; all preceding manifest-path
commands passed. Commit `a7c03cfb` was created before its nonzero exit was
noticed. The fixture now uses the supported query form, and the failed
contract's validation record is corrected here.
The corrected workspace contract passed in
`/tmp/lorry-m5-all-manifest-paths-contract-fixed.log`. A diagnostic run of
the dedicated compatibility driver failed at its obsolete assertion that
parent discovery was unsupported (`/tmp/lorry-m5-parent-compatibility-stale-contract.log`).
That assertion now checks the approved parent-discovery result exactly.

### Package and feature selection

The common single-member selector now accepts names, partial/full versions,
Cargo file package IDs, and member-name patterns. IDs work without a manifest
path; wrong names, versions, and source directories still fail before
compiler queries. Run rejects patterns, and a multi-member pattern reports
the pending execution limitation. The 23 manifest tests, 24 CLI tests,
strict Clippy, workspace contract, and editor contract passed in
`/tmp/lorry-m5-package-selectors-{unit,cli,clippy}.log`,
`/tmp/lorry-m5-package-selectors-workspace-contract.log`, and
`/tmp/lorry-m5-package-selectors-check-contract-fixed.log`. The initial
editor-contract run (`/tmp/lorry-m5-package-selectors-check-contract.log`)
failed because the newly added no-path success probe ran at the repository
root, which has no Cargo.toml. The probe now runs in its fixture directory;
package IDs select within a discovered workspace and do not discover one.

The selector consumes a workspace and command options; it does not reload
configuration or resolve dependencies.

Repeated `-p`, `--workspace`, and `--exclude` now use that common selector.
Duplicate names/version aliases are deduplicated. Cargo's opt-in workspace
selection validates `-p` but selects all members; opt-out selection ignores
`-p`. Unmatched exclusions warn and quiet mode suppresses those warnings.
Run accepts only one selector and rejects patterns. Empty/multi-member
execution still fails explicitly. The focused manifest tests (23), CLI
tests (25), strict Clippy, and paired workspace contract passed in
`/tmp/lorry-m5-selection-set-unit-fixed.log` and
`/tmp/lorry-m5-selection-flags-{cli-final,clippy,contract}.log`.

- At a virtual root, defaults are `default-members` or all members.
- At a package root, defaults are `default-members` or that package.
- With a member manifest, that member is the default.
- `--workspace` selects all members. `--exclude` requires it.
- Repeated `-p` accepts member names, `name@version`, metadata package
  IDs, and Cargo's member-name patterns where the command permits them.
- Unmatched `-p` is an error; unmatched exclusion is a warning.
- Validate command-specific restrictions, including `run`'s single
  package option and rejection of package patterns.
- Parse repeated, comma- or space-separated feature lists, qualified
  `package/feature`, weak `dep?/feature`, `--all-features`, and
  `--no-default-features`. Reject invalid forms Cargo rejects.
- `metadata` has no package selector. It always describes the workspace;
  its feature options are handled by the metadata resolver mode.

The metadata interface now rejects package selectors, as Cargo does. Source
workspace loading never filters members, and the Git-patch metadata contract
uses the package-free interface. The 24 CLI tests, strict Clippy, paired
source metadata contract, and offline Git-patch contract passed in
`/tmp/lorry-m5-metadata-selection-cli.log`,
`/tmp/lorry-m5-metadata-selection-clippy.log`,
`/tmp/lorry-m5-metadata-selection-source-contract.log`, and
`/tmp/lorry-m5-metadata-selection-git-contract.log`.

Resolver-specific feature propagation belongs to milestone 6. Before a
command can execute a selected target or set of packages, reject unsupported
selections rather than reducing them to one package.

The shared CLI now preserves repeated comma/space lists, qualified names,
weak dependency features, and all/default feature flags. Cargo's early
syntax errors are rejected, while source-only metadata accepts feature
options without resolving them. Other readers explicitly reject nondefault
feature selection until milestone 6. The 26 CLI tests, strict Clippy, and
paired workspace contract passed in
`/tmp/lorry-m5-feature-syntax-{cli,clippy,contract}.log`.

### Patches and proof

Example and bench descriptions now include explicit tables, file and
directory discovery, auto flags, required features, crate types, test/doc
flags, harness settings, and per-target editions. Explicit names and paths
suppress inferred targets, and edition 2015 retains Cargo's legacy default.
Compilation remains deferred: all-targets prints one omission note, and
explicit example checking fails. The 23 focused manifest tests, strict
Clippy, and paired source/build contracts passed in
`/tmp/lorry-m5-described-targets-unit.log`,
`/tmp/lorry-m5-described-targets-clippy.log`,
`/tmp/lorry-m5-described-targets-source-contract.log`, and
`/tmp/lorry-m5-described-targets-build-contract.log`.

Land the common reader, inheritance, configuration, selection, and source
description in separate patches. Each carries an offline Cargo comparison.
Do not require all glob or target-description cases before the next
milestone starts.

`check -p MEMBER` from the workspace root selects that one member and uses
milestone 1's path rule. Selecting several members, or a target that Lorry
cannot build yet, is an error until milestones 7 and 8. It is never
reduced to one package, and never a silent no-op (finding 9).

`--all-targets` is the one exception, because rust-analyzer passes it on
every check. Until milestone 8 it covers the kinds of target that Lorry
builds today: the library, binaries, and tests. Lorry prints one note when
it leaves out examples or benches. Naming such a kind, as in `--examples`,
is an error.

Early fix 8 lands here: `metadata` prints `[package.metadata]` and
`[workspace.metadata]`. The package limit leaves every member out of its
count, also a member found through a path dependency (the open part of
early fix 2).

Early fix 8 is implemented. Package, dependency, and workspace metadata
retain nested tables, inline tables, arrays, scalar values, nonfinite floats,
and Cargo's TOML datetime wrapper. Empty virtual workspaces retain their
metadata too. Eight focused metadata tests, strict Clippy, and exact paired
source/resolved metadata comparisons passed in
`/tmp/lorry-m5-custom-metadata-unit.log`,
`/tmp/lorry-m5-custom-metadata-clippy.log`,
`/tmp/lorry-m5-custom-metadata-source-contract.log`, and
`/tmp/lorry-m5-custom-metadata-resolved-fixture-contract.log`.

Rerun the local 124-manifest scan after inheritance and descriptive loading
are complete. Also exercise the build-capable loader: unsupported
compilation must not be hidden behind a metadata-only success.

The manifest and selector APIs land before changes to editor discovery.
Activate member-manifest `metadata` and `locate-project --workspace`
together once the workspace check path can preserve the previously working
editor behavior. Milestone 9 owns that integration gate.

## Milestone 6: shared resolution, metadata, and admission

The resolver foundation records root declarations with their solver events.
Projecting the solved graph no longer needs one privileged manifest. The
existing single-root callers retain their behavior, and the snapshot test
also checks independent root declarations. Twenty-seven focused resolver
tests passed in `/tmp/lorry-m6-root-declarations-unit-fixed.log`. An initial
new assertion indexed the snapshot fixture's empty dependency list; the
fixture now supplies the declaration whose independence it checks.

The multi-root API now seeds every member into one solver, with all member
features, optional dependencies, development edges, and platform edges.
Members remain ordinary packages, including path patches, and all are
excluded from the outside-package cap. A final cycle check omits development
edges but rejects ordinary cycles that independently seeded roots can hide
from event ancestry. Command integration follows in separate patches.
Twenty-nine resolver tests passed in `/tmp/lorry-m6-multi-root-unit.log`;
strict Clippy passed in `/tmp/lorry-m6-multi-root-clippy-fixed.log` after
correcting the new API's unused import.

Complete workspace resolution now ranks unlocked versions by the number of
declared member Rust versions they support, matching pinned Cargo's
`version_prefs.rs`. Declared versions replace the compiler fallback; without
any declarations, compiler prerelease identifiers are ignored for MSRV
comparison. Existing locked versions remain preferred. Thirty-one resolver
tests and strict Clippy passed in
`/tmp/lorry-m6-msrv-{unit-callers-fixed,clippy-fixed}.log`. Initial compile
failures identified option constructors missed during the API migration;
all constructors are now migrated.

Complete graphs now have a shared lock renderer without a privileged root
package or preserved fragments from independently selected locks. The offline
Cargo oracle covers unselected members, optional features, platform edges,
and a legal development cycle; its generated lock matches byte-for-byte.
All four lockfile tests passed in `/tmp/lorry-m6-workspace-lock-unit.log`.
Lock-format selection and command wiring follow in separate increments.

Checking Cargo's lock encoder exposed an existing Git-reference parser bug:
qualified dependency references omit the commit, whereas package sources
retain it. The original rejection is preserved in
`/tmp/lorry-m6-git-reference-original.log`. The parser now handles that form
while rejecting a wrong branch, a wrong explicit commit, and ambiguity.
Five offline-validation tests passed in `/tmp/lorry-m6-git-reference-fixed.log`.

Workspace lock-format selection now uses the earliest declared member Rust
version, with Cargo's thresholds for formats 1 through 4. Legacy output uses
Cargo's checksum metadata and dependency-reference encoding, including Git
selector encoding and omission of commits from dependency references.
Five lockfile tests passed in `/tmp/lorry-m6-lock-formats-unit.log`, including
actual offline Cargo lock comparisons at all six threshold boundaries.
Strict Clippy passed in `/tmp/lorry-m6-lock-formats-clippy.log`.
Reading legacy formats follows next, before command integration.

The common lock reader now retains the detected format and accepts Cargo's
legacy versionless encodings and checksum metadata. Generic workspace loading
does not require a privileged root package. All five lock round-trip tests
and the manifest lock-validation test passed in
`/tmp/lorry-m6-lock-reader-{round-trip,manifest}.log`; malformed, absent, and
mistyped checksum evidence is rejected. Strict Clippy passed in
`/tmp/lorry-m6-lock-reader-clippy-fixed.log` after connecting the generic
reader to the existing unlocked loading path.
The final focused manifest run passed all 23 tests in
`/tmp/lorry-m6-lock-reader-manifest-final.log`.

Complete workspace validation now checks ordinary member nodes and all
dependency identities, checksums, and exact edges against the existing lock.
It shares the existing single-root validator, with no synthetic root edge
comparison. Five Cargo lock-oracle tests and five existing offline-validation
tests passed in `/tmp/lorry-m6-workspace-lock-{validation,legacy-validation}.log`.
The oracle checks formats 1 through 4, stale member edges, missing nodes,
and unchanged lock bytes after validation failures.

Selected workspace requests now recompute features and reachability over
the complete graph's exact dependency identities. Per-declaration edge
constraints prevent an unselected member's version constraint from being
lost. Development edges are enabled only for requested members, and locked
yanked registry versions remain usable. The focused cases also check optional
feature removal/activation and a selected development cycle. Thirty-one
resolver tests and strict Clippy passed in
`/tmp/lorry-m6-selected-workspace-{yanked-unit,clippy-final}.log`.
CLI routing and resolver-specific feature oracles follow before activation.

Named features and root dependency-feature requests now share expansion.
Weak requests remain deferred until an optional dependency is enabled;
renamed dependencies and hidden implicit features follow Cargo's rules.
The pinned Cargo unit-graph oracle covers six strong/weak/hidden/required
dependency cases. Thirty-two resolver tests passed in
`/tmp/lorry-m6-qualified-features-cargo-oracle-fixed.log`, and strict Clippy
passed in `/tmp/lorry-m6-qualified-features-clippy-final.log`. The first
oracle run exposed a test assumption about Cargo path IDs: Cargo omits a
package name when it matches the directory. Both ID forms are now handled.

Package selection now exposes a deduplicated set while existing execution
callers retain their single-package guard. Selected resolution can activate
a feature-only current-package root, then retain only units reachable from
the actual selected members. This preserves resolver 1's cross-package
feature unification without compiling an unselected root. Its actual Cargo
unit-graph oracle passed with all 33 resolver tests in
`/tmp/lorry-m6-feature-only-roots-cargo-oracle.log`; the focused member selector
and strict Clippy passed in `/tmp/lorry-m6-many-member-selection.log` and
`/tmp/lorry-m6-feature-only-roots-clippy.log`.

CLI feature routing now distinguishes Cargo's virtual-root behavior from
resolver 1's package-root behavior. Resolvers 2/3 match features against
selected members, with dependency-alias precedence; resolver 1 retains
current-package defaults and qualified selected-member features. Shared
all-feature expansion omits hidden implicit optional features. Thirty-three
resolver tests, including the routed Cargo feature oracles, passed in
`/tmp/lorry-m6-cli-feature-routing-unit.log`; strict Clippy passed in
`/tmp/lorry-m6-cli-feature-routing-clippy.log`.

The CLI routing oracle now adds 48 actual Cargo unit-graph comparisons:
resolvers 1/2/3, package/virtual roots, plain and qualified/weak member
features, default-feature suppression, all features, and an absent feature.
The focused matrix passed in `/tmp/lorry-m6-cli-features-cargo-matrix.log`;
strict Clippy passed in `/tmp/lorry-m6-cli-features-cargo-matrix-clippy.log`.

Metadata now has a distinct solver feature scope over the same fixed
identities. It unifies requests across dependency kinds and platforms,
including development edges, rather than exposing per-unit build features.
An actual Cargo metadata oracle checks unfiltered, Linux-filtered, and
Windows-filtered results: retained nodes keep the complete feature lists.
Thirty-four resolver tests and strict Clippy passed in
`/tmp/lorry-m6-metadata-features-{cargo-oracle,clippy}.log`.
Metadata command/source preparation integration remains pending.

### Command and admission integration, 2026-10-04

The foundation above now serves ordinary and locked vendor, fetch, tree,
resolved metadata, and workspace admission. Complete resolution includes every
member and retains Cargo's existing lock format on repair; unchanged inputs
preserve exact lock bytes. Upgrades protect every member's direct dependency
intent. Descriptive loading retains development targets and outside path/Git
workspace inheritance without imposing compilation restrictions on navigation.

Fetch acquires exact locked sources without execution admission, defaults to
the complete graph, and can project a target closure with host build-time
dependencies. A newly inspected registry procedural macro triggers host
projection before its child archives are chosen. Exact Git source trees are
resolution inputs before projection, matching Cargo's source query behavior.
Independent immutable index records retain the complete lock's resolution
inputs without authorizing compilation or requiring inactive archives.
Missing metadata sources name an explicit fetch instead of returning partial
results. Empty-workspace source metadata and fetch match Cargo and preserve
the existing empty lock. Configuration supplies metadata's target directory
without compiler discovery in the no-deps path.

One root compact record now carries review format 4 and normalized scope.
It commits to resolved outside identities, source evidence, contexts, features,
and grants, and omits members' raw declarations. Plain vendor repeats and
prints the stored scope; selectors replace it as a whole. Migration reports
the selected member records before confirmation and removes only those exact
records after durable root approval. Changed files, symlinks, and copied
legacy root approval fail closed. Explicit denials remain effective before
acquisition and on ordinary or cached compilation paths.

Human review groups each locked registry/Git package once and lists transitive
member users, evidence, dependencies, and feature contexts. Machine review
uses the approved `lorry-vendor-change` event, including source/capability
differences, prior-reconstruction status, and full canonical candidate.
The grouped workspace, registry, and Git contracts and approval unit tests
passed; strict Clippy passed after correcting argument count and restricting
the old single-package renderer to its legacy tests. The registry contract's
fresh phase initially retained independent index inputs from its preceding
machine phase. Resetting both resolution inputs and archives restored its
real sparse-request assertion. Original evidence is retained in
`/tmp/lorry-m6-grouped-review-registry-contract.log`; final contracts use
`/tmp/lorry-m6-grouped-review-{workspace,registry,git}-final.log`.

Actual Cargo unit graphs now cover another 18 resolver/platform/command
contexts. They exposed resolver-1 development/platform feature activation,
feature propagation into every compilation kind, and host cfg evaluation for
build dependencies. All 37 resolver tests then passed in
`/tmp/lorry-m6-selected-cross-context-resolver-final.log`.
Completed-profile reuse now follows scope reconstruction and coverage checks;
the script counter and corrupt-commitment contract passed in
`/tmp/lorry-m6-admitted-profile-contract-fixed.log`.
Native capability extraction now sorts roles by canonical name rather than
enum ordinal. Source-only fetch, review JSON, and Clippy contracts passed.

The locked Git contract advances its branch, disables curl, and proves both
locked vendor forms preserve the old commit and all state bytes. It exposed
a registry lookup attempted for a package already supplied by a locked Git
patch. The fixed contract passed in
`/tmp/lorry-m6-locked-git-patch-contract.log`.
Local Cargo Git locks also confirmed that V1/V2 omit `branch=master` from
dependency references while retaining it on package sources. Validation and
canonical review now share format-specific reference matching. Six offline
tests, five lock tests, 24 review tests, and strict Clippy passed in
`/tmp/lorry-m6-legacy-{master-reference-fixed,git-reference-lockfile,git-reference-admission,git-reference-clippy}.log`.
This changes no Git source-ID equivalence.

The developer-image and native fixture package limit is now 384. The approved
manual fetch uses an isolated tracked-source copy of `src/sys` and its outside
third-party paths at `/tmp/lorry-m6-sys-fetch-p0o_692n`, with separate HOME,
repository, and cache. Its first configured run exposed Lorry's conflation
of omitted path versions with explicit `*`, which rejects prereleases such
as `moto-netstack`. Actual offline Cargo locks distinguish those cases. The
resolver and selected projection now retain that distinction; all 38 resolver
tests, manifest tests, and strict Clippy passed. Original and fixed evidence
use `/tmp/lorry-m6-prerelease-*.log`.

The next manual fetch reached a separate stack overflow, preserved in
`/tmp/lorry-m6-sys-manual-fetch-prerelease-fixed.log`. An offline 321-package
graph of depth two reproduces it in
`/tmp/lorry-m6-wide-resolver-reproducer.log`. GDB counted 445 frames, 431 in
the recursive resolver or its closures. The dependency-depth bound did not
bound recursion through queued edges. Search now uses explicit backtracking
state and discards forced-choice frames. A second regression preserves lazy
candidate discovery after a reused selection's children fail; it passes with
the original recursive solver and the final iterative implementation. The
first iterative attempt queried those candidates too early and failed that
test. All 40 resolver tests and strict Clippy pass in
`/tmp/lorry-m6-iterative-resolver-{final,clippy-final}.log`. The final real
workspace fetch and full milestone validation follow this fix.

Strict workspace resolution now constrains each dependency by its parent's
locked edge set. Previously, a compatible package already selected by another
parent could replace that exact edge. An offline Cargo path-patch fixture
retains two versions after one requirement broadens to `*`; Lorry's strict
metadata now matches it exactly and ordinary vendoring preserves those edges
as preferences while allowing changed requirements to repair them. Explicit
upgrades override those preferences. Resolver tests, strict Clippy, and the
workspace admission/upgrade contract passed in
`/tmp/lorry-m6-parent-{edge-resolver-checked,preference-fixed,preference-clippy,preference-admission}.log`.

The next real fetch exposed a missing `jiff` weak dependency edge. Cargo's
package resolver follows weak dependency feature references unconditionally;
its compilation feature resolver narrows optional activation afterward. An
offline Cargo fixture with an optional normal alias and an inactive dev alias
confirms both behaviors, including when no other package selects that child.
All 42 resolver tests and strict Clippy pass in
`/tmp/lorry-m6-weak-complete-{fixed,clippy}.log`. The initial missing-edge
failure is preserved in `/tmp/lorry-m6-sys-manual-fetch-parent-edges.log`.

Acquisition then exposed `nom`'s declared example paths whose files are absent
from its published archive. Cargo source metadata permits explicit paths
without reading those unused targets. Descriptive loading now does likewise;
compilation still checks its library input. All 24 manifest tests, including
an actual offline Cargo missing-target comparison, and strict Clippy pass in
`/tmp/lorry-m6-missing-target-{manifest,clippy}.log`. The isolated locked fetch
then succeeded in 86.48 seconds with peak RSS 484,952 KiB, preserved the original
lock bytes, and created no admission record. Offline Lorry metadata also
succeeded, reporting 35 members and 234 resolved packages. Logs and JSON are
`/tmp/lorry-m6-sys-manual-fetch-target-fixed.log` and
`/tmp/lorry-m6-sys-metadata.{json,log}`. No external retries were needed.

The first full milestone gate passed 422 Rust tests plus ten explicitly
ignored native contracts, then failed the own-message metadata test. Its
fixture inherited a user configuration containing unsupported
`required-patches`; no-deps metadata now reads configuration to report the
correct target directory. Isolating that fixture's HOME/Cargo home fixes the
test without altering configuration validation. Original evidence is
`/tmp/lorry-m6-full-first.log`, and all three own-message tests pass in
`/tmp/lorry-m6-own-messages-isolated.log`.

The next gate stopped at the metadata contract's old vendor setup: reviewing
its member build script now correctly requires an explicit grant, while source
metadata requires none. The fixture now preserves an invalid admission record
and proves metadata ignores it. Its exact Cargo comparisons pass in
`/tmp/lorry-m6-metadata-source-only-setup.log`; the original rejection is in
`/tmp/lorry-m6-full-isolated-messages.log`.

An offline Cargo comparison of the fetched real workspace uses directory
sources made from the verified registry objects and an isolated copy of
retained Cargo Git sources. The initial ordinary Cargo cache lacked
`portable-atomic-util`; no extra network access was used for this oracle.
It exposed missing required test features and directory/main.rs test
inference, custom dependency library names, precise internal Git path sources,
noncanonical cfg formatting, and Cargo's optional hints field. Focused Cargo
oracles, golden wire checks, and strict Clippy pass after their fixes; evidence
uses `/tmp/lorry-m6-{test-target,dependency-crate-name,git-path-source,cfg,hints}-*.log`.
One old discovery test still expected nested targets to be omitted; the gate
preserved that failure in `/tmp/lorry-m6-full-metadata-fixed.log`, and its
expectation now includes the Cargo-compatible target. The metadata projection
helper also needed to normalize inner dependency-kind sets before sorting the
outer dependencies. Temporary comparison dumps were removed before validation.
The final real-workspace comparison passes the existing complete projection
oracle in `/tmp/lorry-m6-sys-metadata-projection-final-checked.log`. It compares
every package/node field after only the documented source-root and semantic-set
normalizations, and the original lock remains byte-for-byte unchanged.
The next full gate reached the Clippy contract and rejected unchanged `shared`
sources; the original failure is in `/tmp/lorry-m6-full-final.log`. A focused
regression proves that the transitional compilation-manifest reload discarded
the workspace root, changing the base used for source identity paths. The
projection now retains workspace ownership. The regression also proves that a
real source edit still fails evidence verification. Admission tests, the full
Clippy contract, and strict Clippy pass in
`/tmp/lorry-m6-source-identity-{fixed,contract,clippy}.log`; the original focused
failure is in `/tmp/lorry-m6-source-identity-original.log`.

The following gate passed Clippy and native/cross Cargo byte identity, then
stopped in the older workspace contract. Its captured `tool` error confirms
that the fixture reviewed only `app` before compiling other members. That
fixture now reviews `app`, `tool`, and `shared`, leaving its unused scripted
member outside the scope. Its next focused run exposed an obsolete freshness
assertion: the trace proves completed-profile reuse succeeded after mandatory
admission verification, with no dependency preparation or compiler. The
contract now requires that verification and still rejects preparation or
compilation on the warm shortcut. Original evidence is
`/tmp/lorry-m6-full-source-identity-fixed.log` and
`/tmp/lorry-m6-workspace-{original,scope-fixed}-trace.log`. The full focused
workspace contract passes in
`/tmp/lorry-m6-workspace-scope-and-freshness-fixed.log`.

The next full gate passed the host contracts and reached native self-build
preparation, then rejected complete dependency depth 20 against limit 16.
Original evidence is `/tmp/lorry-m6-full-workspace-contract-fixed.log` and
`target/lorry/native-self-tests/self-20261004T161438Z-67860/summary.txt`.
The unchanged Cargo.lock independently confirms the 20-edge source path:
`lorry -> gix -> gix-worktree -> gix-index -> gix-traverse -> gix-revwalk ->
gix-object -> gix-actor -> gix-date -> jiff -> jiff-static -> jiff-core ->
defmt -> defmt-macros -> defmt-parser -> thiserror -> thiserror-impl -> syn ->
quote -> proc-macro2 -> unicode-ident`.
Its identities are saved in `/tmp/lorry-m6-depth-complete-lock-path.json`.
The current offline Cargo build unit graph instead has maximum package depth
16, with the inactive defmt branch absent; evidence is
`/tmp/lorry-m6-depth-current-cargo-unit-graph.{json,log}`. This is a real
complete-graph bound failure, not transient networking or a depth-calculation
error. No retry or raised limit was used.

The owner approved Cargo's dependency-depth policy. The pinned Cargo resolver
(`src/resolver/mod.rs`, main resolution loop) uses explicit work stacks and has
no fixed dependency-depth cap. Lorry now defaults to no depth cap, while an
explicit `policy.limits.max-depth` still constrains resolution and review.
The shipped developer configuration and native test configuration omit the
inherited bound. The offline Cargo-paired regression constructs a 32-edge path
chain, compares exact lock bytes, verifies source and execution preflight, and
proves an explicit bound of 16 still rejects the graph. Its original rejection
and passing result are preserved in
`/tmp/lorry-m6-cargo-depth-default-{original,fixed}.log`. M6 remains incomplete
until its full milestone gate passes.

**Result.** A workspace has one Cargo-compatible lock and one admission
record. Exact metadata is available offline after explicit acquisition.
Reviewing an existing lock need not update it.

### Resolution modes

Use one resolver implementation with explicit multi-root inputs. Keep the
complete lock graph, reviewed graph, and selected build graph separate.

The complete lock graph includes all members, all their optional features,
all dependency kinds, and all platforms. Unselected members can constrain
versions. Resolve this graph before projecting command-specific features
onto locked identities; do not independently choose versions for each
selected package or union independently resolved locks.

For build and review graphs:

- Resolver 2/3 unify features across packages and targets built together,
  keep host and target feature contexts distinct, and ignore inactive
  platform edges.
- Dev-dependency features participate when tests, examples, or benches
  require dev units, including under `build` and `check`.
- Resolver 1 keeps Cargo's broader unification.
- Apply Cargo's CLI feature rules for the current package, virtual roots,
  and selected packages. A plain feature under resolver 2/3 applies to
  selected members that define it; a feature absent from all of them is
  an error. Preserve resolver 1's current-package behavior.
- Members are ordinary graph packages and can also supply crates.io patches.
- Skip dev edges for the package-cycle prohibition, while still constructing
  the correct acyclic unit graph later.
- A member used as a host build-dependency or proc-macro dependency must
  receive the appropriate host features.

Resolver 3 uses the members' declared Rust versions as Cargo does, with the
compiler version as fallback. Strip the compiler release's `-dev` suffix
for compatibility comparisons. Match Cargo's lock-format choice and
preserve unchanged existing locks.

### Limits and acquisition

The existing package cap is a resolution bound, not merely an archive
download bound. It excludes every workspace member by canonical directory,
including implicitly discovered members. It applies to the complete
resolution and to unions of acquired/reviewed contexts.

Counts recorded by the v1 review:

| Workspace | Motor graph | Default review targets | Complete lock |
|---|---|---|---|
| `src/sys` | 151 | 160 | 209 |
| Helix | 224 | 246 | 309 |
| sed | 142 | 155 | 181 |

A Helix review scoped to `helix-term --no-default-features` has 145 outside
packages for Motor and 156 for the default review targets. The complete
workspace lock still has 309. Scoped review does not bypass that resolution
bound.

The proposed developer-image limit is 384. Keep the 64-member workspace
limit and current depth/resource checks, and report actionable errors.
Implement the previously requested one-run override as `--max-packages N`,
obeying system constraints. A general configuration-overlay CLI is separate
work.

`lorry fetch`:

- Requires a present, usable `Cargo.lock`; it never repairs or writes it.
- By default acquires sources for the complete locked graph, across all
  platforms and optional member features.
- Accepts repeated `--target TRIPLE` to restrict acquisition to those
  platforms plus required host dependencies. This changes acquisition,
  not metadata semantics or lock resolution.
- Uses exact locked Git commits. It never refreshes branch tips.
- Reuses vendor's integrity checks, repositories, and Git materialization
  below workspace `.lorry/vendor/git/`.
- Obeys explicit denies, system constraints, and resource limits; it does
  not require allow rules for build execution and grants no capabilities.
- Leaves the lock and admission record byte-for-byte unchanged.
- Accepts `--locked`; acquisition is locked regardless.

The complete fetch is the simpler rule, and it is what `cargo fetch` does.
One cost is known. The developer image keeps both archives and unpacked
sources. For `src/sys`, the complete fetch therefore stores about 300 MB
of sources that Motor never compiles.

`fetch` and `vendor` write below `.lorry/` in the workspace. Add the
ignore rule for that local state to Motor OS's `.gitignore` in this
milestone, before the first fetch in `src/sys`.

Missing or stale locks point to `vendor`. Missing locked sources identify
what to fetch. No build, check, clippy, test, run, tree, or metadata command
starts an implicit network operation.

### Exact metadata

Resolved metadata uses all workspace members and Cargo's feature semantics.
The node feature lists include requests across platforms and dependency
kinds; they are not the per-unit feature sets of a selected build.

`--filter-platform` filters graph reachability as Cargo does. It does not
authorize incomplete feature lists. Unfiltered metadata describes all
platforms and is independent of `vendor.targets`.

If sources or verified resolution inputs needed for an exact answer are
missing, fail with an actionable `lorry fetch` instruction. Do not omit
packages or features and return a successful partial answer. A targeted
fetch may therefore suffice for a build but not for full metadata.

Pass through package/workspace metadata tables and all described targets.
Use the same package IDs in metadata and compiler messages.

Accept Cargo's feature options. Reject `-p`, `--workspace`, and
`--exclude` on metadata rather than adding selection semantics. At a
virtual root `resolve.root` is null; at a package/member manifest it names
the current package. Default-member reporting follows the current manifest,
while the returned workspace remains complete. Until milestone 9 a
member's manifest keeps today's answer. Milestone 9 switches it on
together with `locate-project --workspace`.

Under policy A, metadata reads verified sources without requiring
admission and runs no package code. Keep `--no-deps` available without
any dependency sources.

### Lock-preserving admission

Add `vendor --locked` and its `--offline` support before making an
admission record mandatory:

- Read the existing lock and verify that it can satisfy the complete
  workspace resolution without modification.
- Keep the lock's exact bytes and exact Git commits. Do not contact branch
  tips or invoke the ordinary branch-refresh path.
- Acquire missing sources only for their locked identities.
- Review and write admission using the normal prompt or `--accept-all`.
  `--locked` does not approve anything.
- With `--offline`, use local verified sources/index evidence only.
  Missing inputs produce an error naming them and the acquisition command.
- If the lock needs repair, fail before replacing the admission record.

Ordinary `vendor` retains its documented reconciliation behavior,
including Git refresh where applicable. The explicit locked mode separates
that operation from approving an existing checkout.

Compilation using outside crates.io or Git packages requires an admission
record under policy A. Enforce this in the shared build machinery for
build/check/clippy/run/test, including `check --compile-time-deps`, and
retain the requirement on cache hits and unchanged-build shortcuts. Keep
the explicit `--use-cargo-registry` compatibility mode as documented. A
path-only fixture still obeys build-script and proc-macro execution policy.

### Admission scope

Use one workspace-root record with a new review format, provisionally 4.
Keep grants explicit and per package.

The first version reviews all workspace members with default features and
all supported target kinds, for configured host/target review contexts.
Builds may use a covered subset of packages and features. A narrower build
must never alter the lock.

Under policy B, commit to resolved outside-package identities,
checksums or exact Git sources, host/target contexts, features, and grants.
Do not include members' raw dependency declarations or `[features]`
tables. An unused local feature declaration must not force readmission.
A source substitution, changed outside feature set, or capability change
must invalidate the relevant approval. Path-package execution remains
governed by policy.

Reconstruct and verify the committed review using the recorded scope,
then check that the requested build graph is covered. Do not compare a
smaller build's review hash directly with the whole-workspace hash.
Preserve source-integrity and policy validation on both normal and cached
build paths.

After the whole-workspace record works, add scoped review using the same
package and feature selector. It is useful for Helix, but is not required
for the initial workspace build:

- `vendor -p`, `--workspace`, `--exclude`, and feature options affect
  review/acquisition scope only.
- Store a normalized scope sufficient to reconstruct the review. With an
  existing record, plain `vendor` repeats that scope and prints it.
  With no record it uses the whole workspace and default features.
- Any package- or feature-selection option replaces the stored selection
  as a whole; unspecified fields use whole-workspace/default-feature
  defaults. Operational flags such as `--locked` and `--offline` do
  not reset scope. `vendor --locked --workspace` resets to the whole
  workspace with default features.
- Reject builds outside the approved packages/features and name a covering
  vendor invocation. Reducing defaults is covered by an appropriately
  broader review, not an unconditional exception to admission.
- Fetch and metadata remain independent of review scope.
- Complete lock resolution and its package cap remain unchanged.

Reject old per-member records with instructions to run workspace-root
`vendor --locked`. After an explicit successful review, remove only the
member records the new scope replaces, naming them. Do not silently turn
one member's approval into workspace approval.

Print one review: a summary of new packages and capabilities, followed by
each package once and its users. Keep human review and approval unchanged.

With the option from milestone 3, `vendor` also prints the change as a
message: packages added and removed, checksums, and capability changes.
`--accept-all` has the same meaning for a person and an agent
(decision 9), and a nonterminal must never hang waiting for approval.

### Patches and proof

Separate multi-root complete resolution, selected feature resolution,
exact metadata, fetch, lock-preserving admission, and the workspace record.
Do not create a special resolver for each command.

Offline fixtures must cover:

- Shared and weak features, renamed dependencies, member patches, host vs
  target features, and legal dev-dependency cycles.
- An unselected member that constrains a selected dependency's version.
- An inactive optional dependency that belongs in the lock but not the
  selected build; a cap exceeded only by the complete graph.
- A cross-platform feature request that affects a retained metadata node,
  with missing inputs causing an error instead of a partial answer.
- Several selections against one record, a covered feature subset, an
  uncovered package/feature, and a harmless local manifest edit.
- Fetched sources without admission, and capability failures before code
  executes, for build, check, Clippy, and the compile-time pass. Repeat the
  admission checks with artifacts already cached.
- A local Git fixture whose branch advances after locking:
  `vendor --locked` and `vendor --locked --offline` retain the old
  commit, preserve lock bytes, and use no branch-refresh network path.
- A stale lock and missing offline inputs leave existing admission intact.
- Migration of old records and the explicit scoped-review reset.

Use Cargo's lock and resolver outputs here. The unit oracle from milestone 1
covers effective profiles and graph wiring.

## Milestone 7: workspace builds

The first independent foundation accepts a slice of selected package identities
in compiler and executor options. Primary-package environment, Clippy
configuration, and cache input roles now use membership in that slice; the
existing engine still supplies one package until workspace execution lands.
Compiler tests prove two packages both receive `CARGO_PRIMARY_PACKAGE`, while
an unselected build-script compiler receives none, and an empty selection marks
none. Four focused compiler tests and strict Clippy pass in
`/tmp/lorry-m7-primary-selection-{unit-fixed,clippy}.log`. M6's depth-policy
decision is now implemented; its milestone gate has not passed.

The next foundation fixes effective dependency crate names in ordinary library,
build-script compiler, and selected-target edges. The original Cargo unit-graph
oracle fails with Lorry passing `shared` where Cargo passes the library name
`shared_crate` (`/tmp/lorry-m7-library-alias-original.log`). Plain dependencies,
renamed dependencies, and an explicit `package` key equal to the alias now match
Cargo for selected and dependency library units. Manifest loading retains that
explicit alias, and metadata reports it correctly too. The paired workspace
metadata oracle includes equal-name explicit aliases across normal, development,
and target dependencies. Nine unit-planner tests, twelve metadata tests, and
strict Clippy pass in `/tmp/lorry-m7-library-alias-{units-final,metadata,clippy}.log`.
Raw renamed aliases remain in graph edges; compiler rendering retains its
existing hyphen normalization.

**Result.** Ordinary libraries and binaries in several selected members
build and check together. This is the first working multi-member build.

`build` and `check` accept `--workspace`, repeated `-p`, `--exclude`, and
the default members. The selector of milestone 5 chooses the packages. The
resolver of milestone 6 gives their features. The planner of milestone 1
plans all of them as one unit graph. Milestone 2 publishes their outputs,
and milestone 3 reports them.

- A member may be selected, a dependency, or both. Deduplicate only
  equivalent units.
- Produce one acyclic unit graph even when the package graph contains a
  legal dev-dependency cycle.
- When two selected members have a binary of the same name, print Cargo's
  warning about the collision.
- Messages name every selected member, each with its own package ID.
  `--keep-going` continues past a failed member.
- `clippy` takes `check`'s options, so `clippy --workspace` works from
  here on.
- Do not finish examples, benches, or member build-time code first. They
  belong to milestone 8. Until then, selecting them is an error.

### Proof

The checkpoint exercises `build --workspace`, `check --workspace`,
repeated `-p`, `--exclude`, and default members, with two members sharing
a library. Run it through the Cargo and cross/native identity fixtures.
Extend the unit oracle to several selected members.

## Milestone 8: remaining targets and commands

**Result.** Member build-time code and all required targets use the shared
graph. Workspace `test`, `run`, `clean`, and `new` follow Cargo.

### Member build-time code

Replace the current rejection of a selected package's build script only
when that script actually runs through the common planner and executor.
Support build-dependencies on other members and on outside packages.

Compile scripts with Cargo's package variables, including
`CARGO_PRIMARY_PACKAGE` where Cargo sets it; do not pass that variable
to script execution. Give each script a private `OUT_DIR`, publish its
results as required by milestone 2, and forward the supported directives
to all appropriate consumers.

Apply the chosen policy C for member scripts, procedural macros, tool
grants, and caller environment variables. Retain the current execution
boundary until those grants are implemented. A path-only workspace does
not implicitly authorize build-time code.

Allow member scripts to read the workspace, including files outside the
member directory. On Linux, extend the read-only sandbox view accordingly;
do not grant writes to the workspace. Track those files and directories
for freshness if script results are reused.

Support `rustc-link-arg`. Keep target-specific `rustc-link-arg-*`
forms explicitly unsupported until needed on a supported target. An
inactive platform branch that emits none of them does not block a build.

Helix's static grammar build needs a C++ compiler role in addition to the
existing C compiler and archiver roles. Add it with that acceptance case;
identify the C++ standard library and serve the target-qualified variables
used by the `cc` crate. Do not grant ambient tool execution.

Do not add a `git` tool grant for scripts in this plan. Helix and ripgrep
scripts tolerate its absence; their version strings can therefore differ
from a Cargo build. Document that specific difference.

### Targets, dev-dependencies, and profiles

Add each target capability in a small patch with a paired Cargo fixture:

- A selected procedural-macro package and members used as procedural
  macros by other selected members.
- Explicit `rlib` and `staticlib`, with correct output naming and
  linkage. On Motor, follow Cargo's handling of unsupported dynamic crate
  types: warn and drop them, and fail when no usable crate type remains.
  Explicitly reject Linux `cdylib`/`dylib` until implemented.
- Explicit `[[test]]` tables, `autotests = false`, and
  `harness = false`.
- Examples and benches, including explicit tables and auto-discovery.
  A default bench uses the test harness; a harness-free bench is a plain
  program with Cargo's test configuration. Whether unstable `test`
  features compile is the compiler's decision.
- `required-features`: skip unavailable implicit targets and report
  Cargo's error for an explicitly requested unavailable target.
- `--lib`, plural target selectors, named selectors, and
  `--all-targets` for build/check/test. `run` also accepts
  `--example NAME`. An unsupported selection must never be a silent
  no-op.

Dev-dependencies participate for tests, examples, and benches under every
command that builds or checks those targets. Follow the selected resolver's
feature unification for the union of units built together. Test a
dev-dependency used by an example under both `build` and `check`,
and a legal cycle that returns to a member's ordinary library.

Support the profiles required by the real projects:

- `debug` and `opt-level` in addition to the existing supported keys.
- Named profiles with `inherits`, and `--profile NAME`.
  `check` also accepts `--release`.
- `CARGO_PROFILE_<NAME>_<KEY>` for supported keys, with Cargo's
  precedence. Unsupported active keys remain errors.
- Cargo's effective settings for host tools and build dependencies.

Per-package overrides remain deferred. An unused profile containing an
unsupported setting may be described; selecting it must fail clearly.
Ripgrep's release `debug = 1` follows the existing debug-information
identity exception, so the cross/native byte-identity fixture does not
use that profile.

### Tests

- Build the selected harnesses first, then run them in Cargo's order:
  packages by name, then library tests, binaries by name, and integration
  tests by name. Extend the comparison for any additional runnable target.
- Print Cargo-style `Running` lines identifying each target and program.
- Run each harness at its package root, with that package's environment
  from milestone 3, and any build-script `OUT_DIR`/`rustc-env` values.
  Keep `CARGO_BIN_EXE_*` within the corresponding package.
- Support named target selection and `--no-run` across selected members.
- Add `--no-fail-fast`: run all harnesses and report failed targets
  with exit 101. Without it, stop after the first failing harness with
  Cargo's exit behavior.
- Keep `test --keep-going` an error pointing to
  `--no-fail-fast`, as in the pinned Cargo 1.99.
- Keep the existing notice that documentation tests are not run.
- Produce one bundle per selected member. Keep the existing bundle
  format and its target-machine runtime rules.
- Compare the JSON of `test` and `test --no-run` over several selected
  members with Cargo's.

### `run`, `clean`, and `new`

For run, accept at most one `-p`, naming a member; otherwise use
default-member selection. Honor `default-run` with Cargo's ambiguity
rules, and require one runnable binary or an explicitly named
binary/example. There is no `run --workspace`. Keep the caller's
working directory and set the program's Cargo environment.

For clean, support repeated `-p` and the pinned Cargo's `--workspace`.
Use the ownership and locking rules in milestone 2; do not remove an
entire shared directory for one package.

Inside a workspace, `lorry new` must not create an unused member
lockfile. Tell the user how to add the package to `members`; retain
Lorry's rule against silently rewriting an existing manifest.

## Milestone 9: editor integration and native acceptance

**Result.** rust-analyzer works on a workspace as it does under Cargo. The
acceptance cases in the plan pass on Motor.

### The compile-time pass

Implement `check --compile-time-deps` as a filter on the common unit
graph, covering members' own build scripts, procedural macros, and
their dependencies. It must not be a dependency-only shortcut that
omits selected members' build scripts. Compare it with the pinned
Cargo's unstable option and record the required invocation.

Cargo's own pass succeeds on `src/sys`. A probe ran
`cargo check --workspace --compile-time-deps -Zunstable-options
--all-targets --keep-going --target x86_64-unknown-motor`, offline, on the
Linux host. It took about 8 seconds and ran 20 build scripts.

rust-analyzer does not infer this option from Lorry's version. Set
`cargo.buildScripts.overrideCommand` in the developer image's Helix
configuration. The pinned rust-analyzer executes this argument array
literally: it does not append configured features, default-feature
settings, target, target directory, manifest path, or extra arguments.
There is no automatic forwarding of those settings to an override.

The shipped override supplies a complete invocation for the image's
defaults: `--workspace`, `--message-format=json`, `--all-targets`,
`--keep-going`, `--compile-time-deps`, the Motor target, and the directory
selected by the shipped `cargo.targetDir` setting. It runs at each
workspace root. Verify the actual directory against rust-analyzer's
normal command rather than assuming its spelling.

Projects that change `cargo.features`, `cargo.noDefaultFeatures`,
`cargo.target`, `cargo.targetDir`, or other relevant arguments must also
provide a complete project override in `.helix/languages.toml`. Document
this requirement and a copyable invocation. The metadata and build-script
commands must use consistent feature and target settings; the override
must honor the configured build-script target directory. Do not
impersonate a Cargo version to enable unrelated version-dependent behavior.

Add an editor contract whose member script generates different code for a
nondefault feature. Configure that feature, disable default features, and
choose a custom target directory. Verify that metadata and generated-code
analysis agree, artifact messages name files under that directory, and
check on save uses the intended configuration. Also test the shipped
default override.

A fetched but unadmitted workspace may navigate sources, but its
build-time pass must report the admission requirement without executing
code.

### Discovery and check on save

Package discovery, full-workspace metadata, and the check/build-script
passes must become compatible together. Run the actual rust-analyzer
command sequence against a fixture before changing public member-manifest
discovery behavior. Then activate member-manifest `metadata` and
`locate-project --workspace` together.

Set `check.workspace = false` in the Motor OS checkout's own Helix
configuration, a new `.helix/languages.toml`, since `src/sys` cannot be
built as one Cargo workspace. Keep ordinary developer-image projects on
rust-analyzer's default workspace checks, and keep
`check.command = "check"`. With that setting, a saved file that belongs to
no member gets no check. The path packages in `src/third_party` are such
files.

Cargo configuration discovery has a visible consequence for
`motor-fs` and `tokio-tests`: a command started at `src/sys`
does not read their member-local `tokio_unstable` configuration.
Document this editor limitation; do not secretly load member
configuration for root-started commands or change the real build's flags.

### `src/sys` and the real projects

For `src/sys`, ignore local `.lorry/` state and keep admission
local initially. Under policy C, add named script grants in
`src/sys/lorry.toml`, starting with `moto-io` for `sysbox`.
Changes are configuration only; this plan does not change OS source.

Complete the real-project and native editor acceptance cases in the main
plan. Identify configuration changes in the external Helix, ripgrep,
and sed checkouts explicitly. Update the spec incrementally, then remove
obsolete single-selection wording from the README and `design.md`;
update `docs/helix.md` with the actual shipped behavior.

## Defect backlog and performance

### Early-fix identifiers

The identifiers are stable. Fixes 1 to 14 keep their v1 numbers. Fix 15 is
new in v3. Completed fixes are not new work. Four fixes land first (see
"First patches"). Fix 13 is optional. Each other open fix lands with the
milestone that touches its code.

| ID | Status / delivery | Contract |
|---|---|---|
| 1 | Done: `3939755d` | Reaching the package cap aborts resolution; it cannot backtrack into an older, smaller graph |
| 2 | Done: `3939755d`, follow-up `c3ba1745`; implicit-member counting in milestone 5 | One cap error names the effective setting and its source; exclude all workspace members from the count |
| 3 | Milestone 6 | A one-run `--max-packages N` override obeys system constraints |
| 4 | Done: `12793598` | Reject a selected package's build script until it is actually supported |
| 5 | Milestone 1 | Build a package inside the workspace root with Cargo's working directory, source path, package identity, and dep-info interpretation |
| 6 | Milestone 3; build-script values in milestone 8 | Give run/test Cargo's package and script environment; preserve run's caller working directory |
| 7 | First patches | Cap Git dependency lints as for registry dependencies |
| 8 | Milestone 5 | Preserve package and workspace metadata tables |
| 9 | First patches | Permit up to 1,024 described targets, retaining 64 for targets of a selected package |
| 10 | Milestone 6 | Match resolver 3's member MSRV rules and Cargo's lock-format selection |
| 11 | First patches | Accept Cargo's four manifest lint levels; reject `force-warn` as a manifest error without panicking |
| 12 | Milestone 2 | Lock the target artifact tree, retain completed units, and recover interrupted publication safely |
| 13 | Separate measured optimization | Track observed environment inputs and propagate changed identities through dependents |
| 14 | Milestone 2, extended in milestone 8 | Reject unsupported build-affecting environment settings; implement the target directory and required profile settings explicitly |
| 15 | First patches | Leave the three variables that Lorry removes from rustc's environment out of the cache key and the unchanged-build record |

Preserve the original cap regression fixture: `a 1.1.0` has dependencies
`x` and `y`; `a 1.0.0` has none. A low cap must fail, not silently
select `a 1.0.0`. Do not keep resolving beyond the resource bound only
to compute a nicer count.

Early fix 5's original probe compared a two-member release build:

| Property | Cargo | Current Lorry |
|---|---|---|
| rustc working directory | workspace root | member directory |
| Source argument / `file!()` | `app/src/main.rs` | `src/main.rs` |
| `-C metadata` | `125050f61cfc153f` | `a6dc71dc1b8d7610` |

The exact hashes belong to that fixture. The permanent assertion is Cargo
byte identity for a selected member, not those hard-coded hash strings.

The v1 environment-key proposal is revised: correctness does not require
narrowing a conservative key before workspaces build. If narrowed, the
test must rebuild the affected dependency **and its dependents**. The old
"that unit and nothing else" requirement was insufficient. Early fix 15 is
not such a narrowing. It removes only variables that rustc never sees.

### Measurements and optional optimizations

The v1 host probe measured a warm check of 33 dependencies at about
0.22 seconds, against Cargo's 0.03 seconds. About 0.18 seconds was fixed
work: compiling/running eight build scripts and copying 107 MB of cached
files, with syncs. Resolved metadata for 92 packages took about
0.32 seconds warm, against Cargo's 0.09 seconds, and maintained a second
unpacked source copy.

These are host measurements, not established Motor timings. The developer
image's data partition has 4 GB. Motor does not support hard links.
The `src/sys` graph has 17 dependency build scripts and 151 outside
packages on Motor.

Milestone 2 removes one of the measured costs, the copying. A published
unit is reused in place, so a command no longer copies every dependency
artifact. Milestone 1 also compiles the selected package's targets in
parallel.

Measure cold and warm `lorry -v check`, resolved metadata, target size,
and cache size on native `sysbox`, after milestone 2 and again when the
workspace path works. Record results at the milestone boundary. Fixed
work above roughly one or two seconds per editor command, or a working
set that does not fit the image, justifies a focused follow-up.

Candidates, with their correctness conditions:

- **Read cached artifacts in place.** Milestone 2 copies a unit from the
  cache once, into the target directory. This goes further and never
  copies. Do it only if cache cleanup cannot delete artifacts still being
  read or run. Do not introduce a second lifetime problem while fixing the
  profile-directory one.
- **Reuse build-script programs/results.** Track script inputs, allowed
  environment, tool identities, and generated output. Cargo's rerun
  rules apply: named directories include descendants; a missing named
  path reruns every time; no rerun directives means the package's file
  set is the default input. `moto-io` uses a directory input to enforce
  its forbidden-call guard.
- **Narrow environment keys.** Use milestone 2's transitive invalidation
  contract, including rustc `env-dep` input values.
- **Check dependencies without full compilation.** This may improve
  cold checks but creates separate artifacts from build. Keep today's
  intentional difference until native measurements justify it.
- **Reuse verified metadata source state.** Preserve source-integrity
  checks and exact results; do not substitute a partial graph.

None of these candidates is a prerequisite for any milestone.

## Separate work

These do not belong to the nine milestones and do not hold them up.

### Formatting

Formatting is optional. The native toolchain already builds
`cargo-fmt` (about 2.1 MB stripped in the v1 measurement). If pursued,
prefer staging that program and invoking it with `CARGO` set to Lorry,
then compare behavior against Cargo. Exact `metadata --no-deps`,
inheritance, and example/bench discovery provide its needed input.
Do not write a second formatting planner solely for workspace support.

### Other command features

- `clippy --fix` (decision 13).
- Inverse dependency trees.
- General `--lorry-config` overlays. The one-run package-limit override
  is the narrow `--max-packages N`.
- Additional JSON rendering modes.
- One test bundle for several members.

## Policy decisions

The recommended answers to A, B, and C are incorporated following the v3
review and the request to update the plan. They define implementation
requirements; this documentation revision changes no runtime behavior.

Other choices are specified in the milestones rather than left as
questions. The table under "V1 questions" says which of them the owner has
decided and which are still proposals.

### A. Source access and mandatory admission

This combines v1 questions 40 and 49.

**Decision:** allow resolved metadata to read verified sources without an
admission record. Require admission before compilation uses outside
crates.io or Git packages. Enforce this through the shared build machinery
for build/check/clippy/test/run and `check --compile-time-deps`, including
cache hits and unchanged-build shortcuts. Retain the explicit
`--use-cargo-registry` compatibility mode with its documented rules.

Metadata executes no package code. Fetch verifies source integrity,
obeys denies and system constraints, and grants no execution capability.
A stale record must not prevent source navigation after fetch; it must
still prevent an unapproved build.

This changes two current behaviors. Metadata would no longer require a
current record. A permissive policy alone would no longer allow an
ordinary build from fetched outside sources without admission. The
lock-preserving `vendor --locked` path and its `--offline` support must
exist before imposing the latter requirement.

The alternative is to retain policy-only builds. That preserves today's
permissive mode but does not guarantee that a fetch is followed by review
before compilation. A separate fetch-only source store would enforce
that distinction through storage, with additional duplication.

### B. What the record commits to

This is v1 question 53.

**Decision:** commit to exact outside-package and source identities, verified
content, host/target contexts, enabled features, and grants. Record the
review scope. Omit members' raw dependency declarations and feature tables.

A harmless declaration edit would not stale the whole workspace.
Changes to reviewed outside code, contexts, features, or capabilities
would. Validation must reconstruct the review scope, verify it, and then
check coverage of the requested build; a cached success cannot skip those
checks.

The record would no longer attest to the precise member declaration that
requested each package. The review display can still list users.
Path packages and their build-time code remain governed by policy C
and existing path rules, not by portable outside-package admission.

The alternative is to retain declaration hashes and require readmission
after even an unused feature edit. `vendor --locked --offline`
would make that safe from lock updates, but would not remove the
workspace-wide interruption.

### C. Editable member code, tools, and environment

This combines v1 questions 20, 21, and 56.

**Decision:** retain the existing trusted-project configuration model,
with grants scoped to the relevant package:

- Require a named `source = "path"` rule for a member build script or
  procedural macro, as for path dependencies. Suggest a package name,
  not a blanket rule covering all path packages.
- Let editable workspace members receive native-tool grants without a
  source-tree digest pin. Retain the existing rules for nonmember path
  dependencies. Add a C++ compiler role only when implementing Helix's
  grammar build.
- Put an explicit caller-variable allowlist on each relevant package
  rule; expose no caller variables by default. A grant for one package
  does not expose those variables to every dependency script. Passed
  values, including unset/empty distinctions, become script inputs.
  Keep tool-selection and Lorry-provided variables under their existing
  controls; an allowlist must not override those controls.
- When a script reports `rerun-if-env-changed` for a caller-set variable
  that was hidden, warn with the name and the required configuration.
  Do not print its value or rerun the script with newly exposed variables.

Project-local `lorry.toml` remains trusted input and may carry these
grants. The project must already be trusted before its build-time code
is allowed to execute. Named grants make capabilities visible in the
checkout; they do not make opening an arbitrary checkout safe. Motor does
not sandbox build scripts. A project-controlled environment allowlist
also cannot, by itself, protect the caller's secrets. Never print the
values of allowed or hidden caller variables in policy diagnostics.

An alternative would accept execution/tool/environment grants
only from user or system configuration, or from an explicit review of
the workspace. That would change the existing trust model and is not
part of this workspace plan. Refusing only unpinned project tool grants
would leave today's pinned self-grants available.

Keeping digest pins for editable members is another alternative, at the
cost of changing grants on every source edit. Automatically granting
member scripts all tools or the caller's entire environment is outside
this proposal.

## Decisions

### Decisions 1 to 14, 19, and 36

These are word for word as first recorded. The milestone numbers inside
them are v1's.

Milestone 1, workspace metadata:

- **1.** `lorry fetch` is acceptable as a download step that approves
  nothing.
- **2.** Match Cargo. A member's manifest gives the whole workspace in
  `metadata`, and `locate-project --workspace` returns the workspace root.
- **3.** Match Cargo: one resolver run for all members.
- **4.** The package limit counts only packages from outside the workspace.
  When the limit is reached, Lorry must say what happened and how to raise
  the limit. A command-line option should raise it for one run (early fixes
  2 and 3).
- **5.** One manual `lorry fetch` run with network access may validate
  milestone 1 on the real `src/sys`.

Milestone 2, structured output:

- **6.** Only `json` and `json-diagnostic-rendered-ansi` for now, as `check`
  has today.
- **7.** Lorry-only messages need a separate option, so rust-analyzer and
  Helix see only Cargo's messages. AI agents should use that option and
  learn Lorry's messages.
- **8.** Test results work as in Cargo. Lorry adds no test-result messages.
- **9.** `vendor` follows `--accept-all`, no matter who runs it.
- **10.** Structured output stays milestone 2.

Milestone 3, `lorry clippy`:

- **11.** Clippy may be added to the native toolchain build and staged in
  the developer image, with the repository's full debug and release gates.
- **12.** Helix keeps rust-analyzer's default check on save (`check`), as on
  Linux.
- **13.** `lorry clippy --fix` comes later (milestone 3, patch 8).
- **14.** Use the simplest option that matches Cargo. The driver finds
  `clippy.toml` itself. Lorry sets `CARGO_MANIFEST_DIR` and passes
  `CLIPPY_CONF_DIR` through.

Milestone 7, root package features:

- **19.** Fix the root `build.rs` defect right away. Done in `12793598`.

Early fixes:

- **36.** Fix the package cap and its error message right away. Done in
  `3939755d`.

Where each one lands in v3:

| Decision | V3 placement |
|---|---|
| 1 | Milestone 6 |
| 2 | Milestones 6 and 9, behind the editor integration gate |
| 3 | Milestone 6 |
| 4 | Milestones 5 and 6, with `--max-packages N` |
| 5 | Milestone 6, on a copy of `src/sys` |
| 6, 8 | Milestone 3 |
| 7 | Milestones 3 and 6 |
| 9 | Milestone 6 |
| 10 | Milestone 3. Replaced by a decision of 2026-10-02 |
| 11, 14 | Milestone 4 |
| 12 | Milestones 4 and 9 |
| 13 | Separate work, after milestone 4 |
| 19 | Done: `12793598` |
| 36 | Done: `3939755d`, follow-up `c3ba1745` |

### Decisions of 2026-10-02

Given after the review of v2. The quoted words are the owner's.

- **Cargo-like behavior.** "Keep the changes that make lorry behave more
  like cargo." This covers four changes to rules that the spec states
  today:
  - Lorry accepts `CARGO_TARGET_DIR` and `build.target-dir`.
  - Lorry accepts an `[alias]` table in Cargo configuration. It still does
    not run aliases.
  - Lorry looks for `Cargo.toml` in parent directories.
  - Lorry uses one output layout for every selection. The per-member
    `target/lorry/packages/<name>/` directory goes away.
- **Clippy and Lorry's own messages.** "Put them back in the plan." Clippy
  is milestone 4. Lorry's own messages are in milestones 3 and 6.
- **Order of work.** "Sequence milestones in a way that is the
  easiest/simplest to implement." The editor does not have to come first.
  The same answer covers the order of the engine work.
- **Sizes and risks.** "Don't bother; this does not add much to the plan."
  The plan carries no size estimates and no risk list.
- **First patches.** Early fixes 7, 9, and 11 land before milestone 1. So
  does the new early fix 15.
- **Fetch scope.** "Whatever is simpler." `fetch` downloads the complete
  lock by default.
- **Reuse in place.** A fresh unit in the target directory is reused where
  it is.
- **Structured output.** "Structured output as milestone 3 is ok." This
  replaces the timing in decision 10, which placed it second. It follows
  milestones 1 and 2, which it builds on, and comes before all workspace
  work. The last section gives the reason.

### V1 questions

V1 listed forty open questions. This table maps each one to v3 and gives
its status:

- **Decided** means that the owner answered it. The answers of 2026-10-02
  are listed above.
- Policies A, B, and C incorporate the answers from the v3 review
  follow-up, as requested for this revision.
- **Proposed** means that the milestones contain an answer that the owner
  has not confirmed by itself. Approving the plan approves it.

| V1 subject / question IDs | V3 disposition | Status |
|---|---|---|
| Order of work (16, 18, 35) | Nine milestones in the order that is simplest to implement | Decided |
| Early fixes (38) | Fixes 7, 9, 11, and 15 first; each other fix with the code it touches | Decided for the four first fixes; proposed for the rest |
| Gates, spec updates, acceptance (33, 34, 51) | "Validation"; the spec changes with each patch; "Acceptance" in the plan | Proposed |
| Membership globs (17) | Milestone 5; `*`, `?`, and `[...]`, no `**` | Proposed |
| Configuration (41) | Milestone 5 | Proposed. Reading Cargo configuration as Cargo does follows the Cargo-like decision; the error for a member's `lorry.toml` does not |
| Harmless tables and `[alias]`, parent-directory search (42, 48) | Milestone 5 | Decided |
| Cargo options and target directory (45) | Milestones 2 and 3 | Decided |
| Fetch scope (39) | Milestone 6; the complete lock by default | Decided |
| Cap override and default, deny rules (37, 50, 55) | Milestone 6; `--max-packages N`; image limit 384 | Proposed |
| Metadata without admission and mandatory build admission (40, 49) | Policy A | Answer incorporated after the v3 review |
| Record contents (53) | Policy B | Answer incorporated after the v3 review |
| Member execution, tools, caller environment (20, 21, 56) | Policy C | Answer incorporated after the v3 review |
| Feature syntax (25) | Milestone 5; Cargo's command-line forms | Proposed |
| Feature coverage, one record, review, migration, scoped review (24, 26–29, 54) | Milestone 6; scoped review follows the default record | Proposed |
| Artifact layout (30) | Milestone 2; one layout with retained per-unit outputs | Decided |
| Crate types, benches, profiles, test options and bundles (22, 23, 31, 32, 47) | Milestone 8 | Proposed |
| Editor defaults, compile-time pass, repository configuration (15, 44, 52) | Milestone 9 | Proposed |
| Performance (43) | Early fix 15, milestone 2, then measurements | Decided for fix 15 and reuse in place; the further speed-ups wait for measurements |
| Formatting (46) | Separate work | Proposed |

V1 milestone 6 becomes milestones 1 and 2. V1 milestones 2 and 3 are
milestones 3 and 4. V1 milestones 4 and 5 feed milestone 5. V1 milestones
1, 8, and 9 feed milestones 5 and 6. V1 milestone 10 is split between
milestones 7 and 8, and v1 milestone 7 is in milestone 8. V1 milestone 11
is milestone 9. V1 milestone 12 is separate work.

## Validation and completion

Use the repository-selected Cargo `1.99.0-dev`
(`eb98b54bc9f3c74519f43d066cb3fd02ebc88df0`) as the reference,
including behavior that differs from older stable Cargo. Pin fixtures
to the tested toolchain rather than relying on a moving online manual.

- **Manifest and command comparisons:** virtual/package roots, explicit
  and implicit members, inheritance, defaults, globs, invocation directory,
  feature syntax, target selection, and exact metadata. Exercise both
  descriptive and build-capable loading.
- **Resolution comparisons:** one complete lock, all optional member
  features, unselected version constraints, renamed/weak dependencies,
  resolver 1/2/3, host/target separation, dev edges, MSRV, and lock format.
- **Unit comparisons:** Cargo build/check/test `--unit-graph` with
  the required unstable flag, comparing nodes, dependency wiring,
  extern names, roots, profiles, and effective settings. Document the
  normalization for full-built check dependencies.
- **Admission:** complete vs scoped graphs, covered subsets, stale or
  missing records, denied acquisition, locked local-Git admission,
  offline failure, unchanged lock bytes, source mutation on cache hits,
  and migration/reset behavior. Cover Clippy and the compile-time pass,
  including runs with cached artifacts.
- **Artifact lifecycle:** overlapping selections, successful outputs
  after failure, all reported paths, generated code and embedded
  `OUT_DIR`, cancellation, surviving children, lock recovery, clean,
  and a test waiting while a different member builds.
- **Freshness:** edited/deleted external inputs, changed symlink targets,
  build-script inputs, and dependency-to-consumer invalidation when
  environment tracking changes. An unchanged build/run starts no script
  processes in the supported fast-path cases, while revoked grants and
  stale admission still fail.
- **Messages and execution:** warning replay, every selected package's
  identity, failure status, no-run harness paths, test ordering/filters,
  run/test working directories and environments.
- **Identity:** a selected-member fixture from milestone 1; a compact
  shared-member and multi-member fixture in milestone 7; both the Cargo
  identity and cross/native Motor suites. Preserve the documented
  debug-information exception.
- **Editor:** replay rust-analyzer's actual commands, including its
  tolerated `config get` failure. Verify member discovery, exact
  metadata, the compile-time pass, generated-code navigation, and
  diagnostics in a dependent member. Cover nondefault features, disabled
  defaults, and a custom target directory with the complete project
  override, as well as the shipped default override.
- **Clippy:** the output against `cargo clippy --message-format=json` on
  a fixture with a known lint, a changed `clippy.toml`, and a native run.
- **Lorry's own messages:** they appear only with their option, and the
  stream that rust-analyzer reads stays pure Cargo.

Keep all regular tests offline. Local registry/path/Git fixtures provide
network-independent coverage. One manual fetch on a copy of `src/sys`
retains prior approval; do not turn it into a regularly networked test.

The host's existing Cargo cache can also support a manual
`lorry --use-cargo-registry metadata` comparison with Cargo for
`src/sys`, including `--filter-platform x86_64-unknown-motor`.
Record missing cache prerequisites instead of downloading during a test.

Use focused contracts while developing and the complete Lorry
`tests/test-all.sh` for code patches, with its hard 30-minute budget.
Record wall time at milestone boundaries. Markdown-only documentation
changes require no tests under `AGENTS.md`.

Use `src/tests/full-test-dev.sh --release` for native editor behavior
changes and the native acceptance gates of milestones 2, 4, 7, and 9. Changes
to image construction, repository test infrastructure, or other broader
components follow that scope's repository gates. That includes the native
Clippy driver, which needs the full debug and release gates (decision 11).
Core OS changes would require the prescribed repeated debug and release
full-system runs. This plan does not authorize a core OS change.

Test drivers live under Lorry and are reached through the appropriate
existing entry points. `src/tests/full-test.sh` must not invoke a
Lorry-owned driver. Diagnose failures without retries, longer timeouts,
ignored errors, or weakened assertions.

Completion requires every acceptance case in the main plan, plus a
spec/README that describes the implemented behavior and its explicit
limits. Formatting and optional performance work do not delay that
completion.

## Reasoning for the revisions

### V3 review follow-up (2026-10-02)

The review retained the architecture and milestone order, with two
corrections. First, the existing engine returns early for an unchanged
build or run without executing dependency scripts. Per-unit publication
must preserve that behavior and its validation. General script-result
caching remains optional; an execution-count contract protects the
existing fast path without adding a timing threshold.

Second, rust-analyzer's build-script override is a literal command array.
It does not inherit the features, target directory, or other arguments
that rust-analyzer normally constructs. The image supplies a complete
default command, and projects with different settings supply a complete
project override. A feature-dependent generated-code fixture verifies
that configuration and output paths agree.

The recommended policy answers are also incorporated. Metadata source
access stays separate from execution admission; every compilation path
uses the same admission checks. The record commits to resolved content
and capabilities, avoiding readmission for harmless member declaration
edits. Member grants retain the existing trusted-project model, with
per-package caller-variable allowlists and no source pin for editable
members' native-tool grants. These are documentation requirements, not
implemented changes.

### V3 (2026-10-02)

V3 keeps v2's design: one workspace model, one resolver with three graphs,
one unit graph, per-unit publication, lock-preserving admission, and exact
metadata. It changes the order of work and puts two parts back.

The order follows one rule from the owner: do the work in the order that
is simplest to implement. The two engine changes come first, because
everything else builds on them.

- Moving the selected package's targets onto the unit graph first means
  that publication, messages, Clippy, build scripts, and multi-member
  builds are each written once, on one code path.
- Changing publication second means that every later feature reports and
  reuses files in their final place.

V2 did both inside its third milestone, together with the first
multi-member build. Apart, the first step is a refactor plus early fix 5.
Byte identity proves both: a single package keeps its bytes, and a
selected member gets the bytes that Cargo builds.

Milestone 1 does not store the selected package's units in the unit cache.
The cache key covers a package's own directory, and the selected package
may read files outside it. Milestone 2 adds freshness records that name
the real inputs. Only then are those units reused.

Structured output is milestone 3. The owner had placed it second
(decision 10), asked which option is best, and then approved milestone 3.
On today's engine it would
be written twice, because the code that compiles the selected package is
about to be deleted. It would also report file names that disappear when a
command fails, which is the defect that milestone 2 fixes. After
milestones 1 and 2, one writer serves `build`, `check`, `test`, and `run`,
and the workspace commands inherit it. It still lands before all workspace
work, so tools and agents get it early.

Clippy and Lorry's own messages are milestones again, as the owner asked.
Clippy is milestone 4. It reuses the check path and needs one rule: a unit
of a workspace member goes through the driver. That rule keeps working,
unchanged, as later milestones find more members, select several of them,
and add members' own build scripts. Lorry's own messages start in
milestone 3 with the option and the error message, which do not depend on
workspaces. The message for `vendor` changes waits for milestone 6, so
that it describes the workspace review and is written once.

Four small fixes land before milestone 1. Fix 15 is new. Lorry hashes the
whole environment into each cache key, and v2 keeps that for safety. But
three of those variables never reach rustc, because Lorry removes them
before it starts the compiler. Leaving them out of the key is safe. It
lets rust-analyzer's two kinds of check share what they build, which they
cannot do today.

`fetch` keeps v2's rule and downloads the complete lock by default. The
owner chose the simpler rule. A narrower design is possible: exact
metadata for one platform needs only the index records of the packages
for other platforms, not their sources. It was not chosen. The known cost
of the simple rule is in milestone 6.

The build-script override for rust-analyzer goes into the developer
image's Helix configuration, for every project. rust-analyzer picks the
compile-time pass by itself when it runs a current Cargo, so the override
selects that pass under Lorry. The review follow-up above specifies the
complete default and project arguments needed to match the configured
behavior. `check.workspace = false` stays a setting of the Motor OS
checkout, as in v2.

At the owner's request, the plan carries no size estimates and no risk
list, and the short plan is written in short plain sentences.

### V2 (2026-10-02)

V3 keeps the reasoning below, with two exceptions. Clippy and Lorry's own
messages are milestones again. There are nine milestones, in a different
order. Milestone numbers in this subsection are v2's.

The user's objective is Cargo workspace support. V1 spread that work
across twelve milestones and an estimated 85–100 patches, with
multi-member execution near the end. The four-milestone plan moves a
small real workspace build into the first executor increment.
Clippy, formatting, agent-specific messages, and speculative performance
work have value, but none is necessary to prove workspace membership,
resolution, or execution. Their approvals and useful implementation notes
are retained separately.

The main architectural simplification is one workspace model, one
resolver with explicit purposes, and one unit executor. A member is not a
new kind of compilation. Its role can change between invocations, and it
can be selected and depended on simultaneously. Treating membership and
selection as attributes avoids another root-specialized implementation.
The early ordinary library/binary fixture exercises the architecture before
the larger target matrix is added.

The output proposal needed a correctness change, not just a layout choice.
The current [engine](src/engine.rs) stages and swaps a whole profile and
discards check staging on failure, after successful artifact or
build-script messages may already have been emitted. V1 retained that
swap for multi-member builds and released its lock before tests ran.
A later selection could therefore remove an earlier binary, generated
directory, or not-yet-run harness. Per-unit publication with retained
outputs and publish-before-report messages addresses those cases.
One target-directory lock also gives clean a consistent exclusion rule.
The proposal avoids an immutable-generation or lease system; it promises
ordinary Cargo-style output lifetime, not survival of explicit clean or
same-unit replacement.

The freshness requirement follows from allowing workspace inputs outside
a member directory. [The cache](src/cache.rs) currently fingerprints
the package tree, while [the executor](src/executor.rs) validates
dep-info boundaries without retaining those external inputs in the cache
identity. A permitted `include_str!("../../languages.toml")` must
remain an input after members become cached units. Otherwise the newly
cached workspace path can silently return stale code.

Narrowing environment keys is a different problem and can wait. V1's
proposed test rebuilt only the unit that read a changed variable. A
consumer can embed that dependency's changed value, so the dependency's
final identity and affected dependents must also change. Keeping the
conservative environment key first avoids adding this cache redesign
to the minimum workspace implementation.

The three graph definitions correct an important sizing and admission
ambiguity. [Vendoring](src/vendor.rs) resolves the complete graph before
selecting a review, and [the resolver](src/resolver.rs) enforces the cap
while resolving. Cargo also resolves all optional member features for
the shared lock. Helix's 145-package Motor build therefore does not make
its 309-package complete lock fit a limit of 192. Scoped review reduces
what must be reviewed and granted; it does not reduce complete resolution
or exact metadata. The proposed limit of 384 covers the recorded complete
graphs. See Cargo's
[resolver feature rules](https://doc.rust-lang.org/cargo/reference/resolver.html#features).

Lock-preserving admission closes the gap between fetch and mandatory
review. Fetch deliberately retains exact locked commits, while ordinary
Lorry vendor refreshes branch-based Git dependencies. Requiring vendor
after fetch without a locked mode could change the very code being
approved. `vendor --locked` separates approval from updates, and
`--offline` makes repeated approval possible from verified local
inputs. Keeping lock bytes and prior admission intact on failure are
part of that contract.

Exact metadata is a contract with the editor and Cargo consumers.
Successful output that varies with which platform archives happen to be
cached is not exact metadata. The revised default fetch acquires the
complete lock; a targeted fetch remains available with an explicit
missing-input error when it cannot support a complete answer.
`--filter-platform` does not justify incomplete feature lists.
Cargo's [metadata command](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html)
also has feature options but no `-p` selector.

The review used the pinned Cargo 1.99 source and small offline Cargo
fixtures for command details. An example under `check` required its
dev-dependency; metadata rejected `-p`; and the complete lock retained
an inactive optional dependency. A failed workspace check with
`--keep-going` retained a successful member's generated file.
`--compile-time-deps` ran that member's own build script while
skipping its failing library. These checks support the revised
dev-dependency, artifact-lifetime, metadata, and editor-pass contracts.
Cargo's
[development-dependency documentation](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#development-dependencies)
also identifies tests, examples, and benchmarks as users of dev-dependencies.

The unit oracle must compare wiring and effective settings, not just
unit names and feature sets. Correct nodes can still link through the
wrong alias, host context, or profile. Build/check/test comparisons,
plus a small end-to-end identity fixture, provide stronger coverage
without compiling every real workspace in each host test run.
Lorry's full compilation of check dependencies remains a documented
difference rather than an unexplained oracle mismatch.

The editor workaround belongs to the project that needs it.
`src/sys` has build constraints that prevent a single workspace check.
Applying `check.workspace = false` to every developer-image project
would hide cross-member breakage in otherwise ordinary workspaces.
A Motor OS project setting preserves that workaround without changing
the general editor default. The compile-time pass must include members'
own scripts and be delivered with compatible discovery behavior, so the
metadata improvement does not temporarily remove generated-code support.

Finally, the forty-question checklist mixed Cargo semantics, sequencing,
optional products, and trust decisions. V2 specifies routine behavior
and retains three policy groups with explicit alternatives. In
particular, project-provided execution/tool/environment grants are not
a trust boundary against a hostile checkout; the document must not imply
otherwise. The current revision changes documentation only. Historical
v1 findings and measurements are retained as evidence, not presented as
new implementation results or as newly passed Lorry/Motor tests.
