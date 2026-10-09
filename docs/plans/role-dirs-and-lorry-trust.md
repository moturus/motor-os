# Per-role directories and user-owned Lorry trust

Status: reviewed; all questions answered. No code has changed.
Evidence, file lists, and per-patch detail are in
[role-dirs-and-lorry-trust-details.md](role-dirs-and-lorry-trust-details.md),
under the same section numbers.

## 1. Goal

- A cloned repo cannot make Lorry run anything you have not approved.
  Only your own configuration grants trust.
- Each process role (System, Interactive, NONE) has its own configuration
  and temporary directory. A lower role cannot read or plant files in a
  higher role's directories.
- `lorry vendor --accept-all` works for Helix on Motor. Lorry remembers the
  acceptance for that workspace.

## 2. Decisions

1. A workspace's `lorry.toml` grants nothing. It keeps only settings that
   cannot run code, change trust, or choose where Lorry writes:
   `cargo-compat-version`, vendor targets, and `keep-artifacts` /
   `keep-sources`. Everything else moves to the role's configuration.
2. Per-workspace settings live in the role's configuration directory:
   `/user/cfg` for Interactive and `/none/cfg` for NONE.
3. `vendor --accept-all` is recorded per workspace. It allows build scripts
   and procedural macros from crates.io, Git, and path packages, as Cargo
   does. Deny rules, checksums, and limits still apply.
4. A repo's `.cargo/config.toml` is honored after `--accept-all`. Without it,
   a dangerous setting asks you to allow or deny it.
5. New directories `/none`, `/none/cfg`, and `/none/tmp`. NONE may write
   `/none/cfg`.
6. `/system/tmp` is for System only and `/user/tmp` is closed to NONE.
   `/devtools/tmp` and `/devtools/cfg` go away.
7. `/devtools` holds only tool binaries, artifacts, sources, and Lorry's
   caches.
8. Clang's target configuration moves from `/devtools/cfg/llvm` to
   `/devtools/llvm/cfg`. NONE can read it, so NONE can run clang. The new
   path is compiled into the new assembly, as the old one was.

From your answers to the first review:

9. The admission record's grants apply only after you approve its exact
   review.
10. Linux's Cargo-cache mode does not ask about `.cargo` settings.
11. rt.vdso sets `TMPDIR` by role, but never changes a `TMPDIR` that the
    parent set explicitly, even for a lower-role child.
12. Lorry refuses to run as System.
13. Per-workspace settings are keyed by the workspace's absolute path. A
    moved repo needs approval again. A different repo cloned later to the
    same path inherits the approval.
14. Only `lorry vendor` asks questions. Other commands stop with a hint. A
    denied `.cargo` setting stops the command, and the denial is not
    remembered.
15. The standard image holds no test binaries. Tests stage them in
    `/user/tmp` or `/none/tmp`.
16. `lorry vendor` without `--accept-all` asks about missing build-script
    and procedural-macro grants in the same review it already shows.
17. Build scripts run in Lorry's own role.
18. On the standard image, tests stage all their binaries in
    `/none/tmp/motor-tests/tests`.
19. rt.vdso treats `TMPDIR` as explicit when it differs from the parent's
    own `TMPDIR`. No toolchain change.
20. Build scripts approved in an interactive review get the configured
    native tools, as with `--accept-all`. The review lists the tools each
    one gets.

## 3. Findings

1. **A repo can grant itself trust in three ways today.**
   - Its `lorry.toml` can hold any `[policy]` rule. It can also name the
     programs Lorry runs: `toolchain.rustc`, `network.curl`, and the
     `native-tools` compilers.
   - Its committed admission record, `.lorry/dependencies-v2.toml`, becomes
     allow rules at build time. A fresh clone that ships this file builds
     with the crates.io and Git build scripts, procedural macros, native
     tools, and caller variables listed in it. You never approved them.
   - Its `.cargo/config.toml` is read exactly like your own Cargo
     configuration. It can set a linker, a runner, any rustflags, and a
     target directory anywhere on disk.
2. **Lorry never checks its role.** A NONE process cannot read
   `/user/cfg` or `/devtools/lorry`, so Lorry does not work as NONE today.
   Lorry skips the unreadable `/user/cfg/lorry.toml` silently.
3. **Every role shares `/user/tmp`.** New files there start readable by
   lower roles, so NONE can read Interactive's temporary files. NONE can
   also create a name first that an Interactive program later writes into.
4. **`/user/tmp` is hard-coded as the default** in Rust std, mlibc, rush,
   and moto-rt. Children inherit `TMPDIR` from their parent.
5. **`/devtools/cfg` holds two things:** Lorry's system configuration, and
   clang's target configuration, whose path is compiled into clang.
6. **Tests pass files to NONE children through shared temporary
   directories.** The standard image keeps its test binaries in
   `/user/tmp/motor-tests`. Some systests start their own binary again as
   NONE, so NONE must be able to open it.
7. **Clang's configuration path and the `cc` and `c++` launchers are built
   into the toolchain assembly.** The launchers also force
   `TMPDIR=/devtools/tmp`. Moving the configuration therefore needs a new
   assembly, whichever way it is done.
8. **Smaller problems found on the way.**
   - An empty `CARGO_HOME` makes Lorry read `config` from the current
     directory as if it were your Cargo configuration.
   - The spec gives the Cargo configuration merge order backwards.
   - The artifact lock sits outside the `lorry/` part of the target
     directory, which the spec says Lorry never writes to.

   B1 to B3 fix the first one and the spec wording. The lock can wait.

## 4. Design

### 4.1 Directory layout

Modes are System / Interactive / NONE.

| Path | Mode | Purpose |
|---|---|---|
| `/system/tmp` | `rwx------` | System scratch |
| `/user/tmp` | `rwxrwx---` | Interactive scratch |
| `/none` | `rwxrwxr-x` | NONE's home |
| `/none/cfg` | `rwxrwxrwx` | NONE's configuration |
| `/none/tmp` | `rwxrwxrwx` | NONE scratch |
| `/devtools/llvm/cfg` | `rwxr-xr-x` | Clang target configuration |
| `/devtools/lorry` | `rwxr-xr-x` | Holds the two role trees below |
| `/devtools/lorry/user` | `rwxrwx---` | Interactive cache and repository |
| `/devtools/lorry/none` | `rwxrwxrwx` | NONE cache and repository |

`/devtools/tmp` and `/devtools/cfg` are removed.

Tests use these roots:

- On the standard image, `full-test.sh` stages the test binaries in
  `/none/tmp/motor-tests/tests`, so both Interactive and NONE children can
  run them. The harness creates that directory itself. NONE cannot add or
  replace files in a directory that Interactive created.
- The development image keeps its shipped `/devtools/tests`.
- Interactive test scratch is `/user/tmp/motor-tests` on both images.
- Scratch that a NONE child must reach is `/none/tmp/motor-tests/tmp`.

### 4.2 `TMPDIR` follows the role

rt.vdso already reads the child's capabilities when it starts a process.
It will also set the child's `TMPDIR`:

- If the parent passes no `TMPDIR`, the child gets its role's directory.
- If the parent set `TMPDIR` explicitly, the child keeps it, whatever its
  role.
- If the child only inherited `TMPDIR` and its role is lower than the
  parent's, the child gets its role's directory.

rt.vdso receives the complete environment: std merges inherited and
explicit values before the spawn call. So rt.vdso treats `TMPDIR` as
explicit when it differs from the parent's own `TMPDIR` (decision 19).

moto-rt gets the role-to-directory table. Rush stops choosing a default of
its own. The `cc`, `c++`, `rustc`, `rustfmt`, and `clippy-driver`
launchers stop forcing `/devtools/tmp`. Rust std and mlibc do not change.

### 4.3 Where Lorry reads trust

Lorry reads its role at startup. It refuses to run as System.

| Role | Configuration | Cache and repository |
|---|---|---|
| Interactive | `/user/cfg/lorry.toml` | `/devtools/lorry/user` |
| NONE | `/none/cfg/lorry.toml` | `/devtools/lorry/none` |
| Linux | `~/.config/lorry/lorry.toml` | `~/.cache/lorry`, as today |

Per-workspace settings come from two places, keyed by the workspace's
absolute path:

- **Rules you write** go in that `lorry.toml`, under a table such as
  `[workspaces."/user/helix".policy.rules.…]`. Lorry never writes this file.
- **Decisions Lorry records** go in a Lorry-owned file per workspace, in
  `/user/cfg/lorry-workspaces/` (for NONE, `/none/cfg/lorry-workspaces/`).
  It holds `accept-all`, the review you
  approved (4.5), and the `.cargo` settings you allowed (4.6). Deleting the
  file forgets them. Lorry writes it the way it already writes its redirect
  decisions: under a lock and atomically.

Only the workspace root's own `lorry.toml` counts as project
configuration. Today a `lorry.toml` in any parent directory counts too.

Paths and tools in `/devtools/cfg/lorry.toml` become Lorry's built-in Motor
defaults: curl and CA paths, vendor targets, the C and C++ compilers, and
the archiver. Policy stays in configuration: the image ships the default
policy and limits in `/user/cfg/lorry.toml` and `/none/cfg/lorry.toml`, and
the 25 exact grants for Lorry's own dependencies in `/user/cfg/lorry.toml`
only.

### 4.4 `--accept-all`

`vendor --accept-all` records `accept-all` for the workspace and then works
as it does now. From then on, every command in that workspace allows all
build scripts and procedural macros, and honors the repo's `.cargo`
settings. Scripts get the configured native tools. Later reviews in that
workspace are approved without asking. Caller variables stay hidden unless
a rule names them.

### 4.5 The admission record needs your approval

The committed admission record stays: it is the detailed list of what a
review allowed. But its grants apply only when your per-workspace file
approves that exact review, by its `review-sha256`, or has `accept-all`.

In a fresh clone, `lorry build` therefore stops and points to
`lorry vendor`. That command shows the recorded review and asks once. Your
"yes" records the review's digest.

### 4.6 `.cargo/config.toml`

The `CARGO_HOME` file is yours. Every other `.cargo` file that Lorry reads
is treated as the repo's.

A repo setting is dangerous when it can run a program or write outside the
workspace:

- `target.*.linker` and `target.*.runner`;
- rustflags outside a short safe list, such as `--cfg`, lint levels, and
  optimization flags (the full list is in the details file);
- `build.target-dir` outside the workspace root.

`lorry vendor` lists each repository file with dangerous settings and asks
once. It records the approved file by path and SHA-256, so any edit to that
file asks again. (Implemented per file rather than per setting: simpler, and
stricter.) Other commands stop
with a hint to run `lorry vendor`, because rust-analyzer runs them without a
terminal. A denied setting stops the command. Environment variables such as
`CARGO_TARGET_<T>_LINKER` are yours and need no approval.

### 4.7 Approving build scripts without `--accept-all`

`lorry vendor` without `--accept-all` already shows the dependency change
and asks once. A missing build-script or procedural-macro grant now joins
that review instead of stopping it. One "yes" approves what the review
shows, and nothing later:

- grants for crates.io and Git packages go into the admission record,
  which your approved review then covers (4.5);
- grants for workspace members go into the decisions file.

Approved build scripts get the configured native tools, as with
`--accept-all` (decision 20). Caller variables still need a rule. A later
change asks again, showing only what changed.

## 5. Patches

Lorry first, so Helix works soon. Then the OS layout, in an order that
never removes a directory something still uses. Lorry for NONE comes last.

| # | Patch | Gate |
|---|---|---|
| B1 | Workspace `lorry.toml` restricted; per-workspace rules in your `lorry.toml`; tests, fixtures, and `src/sys/lorry.toml` migrated | Lorry `tests/test-all.sh` |
| B2 | Decisions file; `--accept-all` recorded; admission record needs approval; interactive approval of build scripts | Lorry `tests/test-all.sh` |
| B3 | `.cargo` approvals | Lorry `tests/test-all.sh` |
| B4 | Built-in Motor defaults; `/devtools/cfg/lorry.toml` removed | Lorry `tests/test-all.sh`, `full-test-dev.sh --release` |
| A1 | `/none`, `/none/cfg`, `/none/tmp` added; nothing closed yet | `full-test.sh` 3× debug and release |
| A2 | moto-rt role table; rt.vdso sets `TMPDIR`; rush stops choosing one | `full-test.sh` 3× debug and release |
| A3 | New toolchain assembly: clang reads `/devtools/llvm/cfg`; launchers stop forcing `TMPDIR` | assembly build, `full-test-dev.sh --release` |
| A4 | `/user/tmp` and `/system/tmp` closed; `/devtools/tmp` and `/devtools/cfg` removed; tests moved | `full-test.sh` 3× debug and release, `full-test-dev.sh --release` |
| B5 | Lorry reads its role; `/devtools/lorry/user` and `/devtools/lorry/none`; refuses System | Lorry `tests/test-all.sh` |

Each patch updates its own docs.

## 6. Questions

None open. Your answers are decisions 9 to 20 in section 2.
