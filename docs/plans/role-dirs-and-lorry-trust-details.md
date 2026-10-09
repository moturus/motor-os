# Per-role directories and user-owned Lorry trust: details

Companion to [role-dirs-and-lorry-trust.md](role-dirs-and-lorry-trust.md).
Section numbers match. Line numbers are from `lorry` at `43f64c04` and may
drift; the named functions are the stable anchors. Lorry paths are relative
to `src/bin/lorry/`.

## 3. Findings: evidence

### 3.1 How a repo grants itself trust

**Workspace `lorry.toml`.** Only these keys are limited by layer
(`src/config.rs`):

| Key | Rule | Line |
|---|---|---|
| `cache.directory` | not from the project | 667 |
| `repositories.system` | Linux base or Motor system layer | 713 |
| `repositories.user` | Linux base or Motor user layer | 718 |
| `repositories.local` | project only | 723 |
| `system-constraints` | Linux base or Motor system layer | 1207 |

Everything else is accepted from the project. That includes
`merge_toolchain` (680), `merge_network` (796), `merge_test` (811),
`merge_native_tools` (824), `merge_policy` (903), and
`use-cargo-registry` (609). `nearest_file` (2179, called at 527) walks every
ancestor of the workspace root, so a `lorry.toml` in a parent directory
also counts as project configuration.

**Committed admission record.** `.lorry/dependencies-v2.toml` lives in the
workspace and is committed, for example `src/bin/lorry/.lorry/`.
`CompactState::apply_to_policy` (`src/admission_state.rs:749`) turns each
recorded package into an exact allow rule. The rule carries the recorded
build-script, procedural-macro, native-tool, and caller-variable grants. It
is applied at build time (`src/engine.rs:418`,
`src/dependency/workspace/admission.rs:85`). The check that follows
compares the result with the same record, so it cannot fail for a record
that is merely self-consistent. The commitment check (`admission.rs:79`)
only ties the record to the current lockfile and sources.

**`.cargo/config.toml`.** `load_cargo_layers` (`src/config.rs:1350-1387`)
reads `CARGO_HOME` first, then every `.cargo/` directory from `/` down to
the current directory. `merge_cargo_file` (1414) takes no layer kind, so
the repo's file and yours are treated alike.

| Setting | What Lorry does with it | Where |
|---|---|---|
| `target.*.linker` | `-C linker=` on every rustc unit and test bundle | `compile.rs:399-405`, `bundle.rs:184-188` |
| `target.*.runner` | runs it for cross-target `run` and `test` | `engine.rs:3214-3246` |
| rustflags | passed verbatim, after Lorry's own `-C linker=`, so a `-C linker=` in rustflags wins | `compile.rs:404`, `435` |
| `build.target-dir` | creates it anywhere and writes the artifact lock in it | `artifact_lock.rs:30-58` |

`build.rustc`, wrappers, `[env]`, `[source]`, `[patch]`, and `[profile]`
are already errors. `[http]`, `[net]`, and the registry tables are ignored
with a note.

### 3.2 Lorry and process roles

No file in `src/` uses `ProcessRole` or the capability word. On Motor the
layers are `/devtools/cfg/lorry.toml` and `/user/cfg/lorry.toml`
(`src/config.rs:542-557`). `load_lorry_files` (559) uses `is_file()`, which
is false when the directory cannot be traversed, so NONE silently loses the
user layer. `/devtools/lorry` and `/user/cfg` are `rwxrwx---` in
`src/imager/motor-os-permissions.yaml`.

The pattern to copy is
`ProcessRole::from_caps(ProcessStaticPage::get().capabilities)`, as in
`src/bin/rush/src/sys/motor.rs:87`. Lorry already depends on `moto-sys`
0.3.1, which has `ProcessRole`.

### 3.3 Shared temporary directories

`docs/fs-permissions.md:252`: runtime-created files start `rw-` for the
creator, `rwx` for higher roles, and `r--` for lower roles. Directories
start `r-x` for lower roles. So NONE can read Interactive's files in
`/user/tmp`. A name NONE creates first is writable by Interactive and
readable by NONE.

### 3.4 Hard-coded temporary directory defaults

| Place | Default |
|---|---|
| `src/sys/lib/moto-rt/src/fs.rs:22` | `TEMP_DIR = "/user/tmp"`, unused |
| `src/bin/rush/src/shell.rs:181-187`, `692-695` | sets `TMPDIR=/user/tmp` when unset |
| `src/build-motor-os.sh:631`, `641`, `719`, `728`, `737` | launchers export `TMPDIR=/devtools/tmp` |
| `../toolchain-src/rust/library/std/src/sys/paths/motor.rs:64-66` | `/user/tmp` fallback |
| `../toolchain-src/mlibc/options/posix/include/bits/posix/posix_stdio.h:22` | `P_tmpdir "/user/tmp"` |

rt.vdso passes `TMPDIR` through unchanged (`rt_process.rs:661-735`).

### 3.5 `/devtools/cfg`

- `lorry.toml`: network paths, vendor targets, `policy.default = "allow"`,
  limits, the C compiler and archiver, and 25 exact grants. It uses no
  key that needs the system layer.
- `llvm/x86_64-unknown-motor.cfg`: only `-resource-dir`. Its directory is
  compiled in by `-DCLANG_CONFIG_FILE_SYSTEM_DIR` (`build-motor-os.sh:536`).
  Clang searches the user directory, the compiled-in directory, then its
  own binary directory.

### 3.6 Tests that depend on the old layout

Broken once `/user/tmp` closes, because a NONE child opens a file there:

- systest `process_permissions.rs:77-120` and
  `spawn_wait_kill.rs:272-295` start `current_exe()` as NONE. On the
  standard image that is `/user/tmp/motor-tests/tests/systest`.
- `test-rush-script-caps.sh:22-80`: with `MOTOR_OS_CAPS=0`, rush must read
  a script in `$TEST_TMP`.

Still passing, but proving nothing, because the closed directory denies
first:

- systest `fs_permissions.rs:59`, `126-465`: the fixture is under `TMPDIR`.
- `test-sftp.sh:212-266`: NONE reads of private uploads in `$TEST_TMP`.
  These need a fixture in `/none/tmp` and a positive control.

Users of `/devtools/tmp`: `full-test.sh` through `MOTOR_TEST_ROOT/tmp` on
the development image, `test-dev-sources.sh:64-290`,
`test-rustfmt-native.sh`, `test-gix.sh:809`,
`test-rust-analyzer-crates.sh:14`, `rust-analyzer-smoke/src/native.rs`,
`stress-soak.sh`, `test-unwind.sh:79`, the rush and rmux
`vm-console-check.py` scripts, `src/sys/tests/native-temp.c` and
`native-temp.cpp`, Lorry's `test-native.sh:17`, `262`, and the Helix
configuration `img_files/motor-os-dev/user/.config/helix/languages.toml:10`.

Not affected: the rmux NONE client checks in `full-test.sh:1236-1252`, and
`test-system-tty.sh`, which uses `/user/tmp` only as System and
Interactive.

### 3.7 The toolchain assembly

The assembly key (`src/toolchain-assembly.sh:60-78`) covers the toolchain,
mlibc, and a native configuration digest. Editing `build-motor-os.sh` does
not change it, and the imager adds assembly files after `img_files`
(`src/imager/src/main.rs:593-599`). The existing assemblies still contain
`devtools/cfg/llvm` and launchers that set `/devtools/tmp`.

### 3.8 Smaller problems

- Empty `CARGO_HOME`: `src/config.rs:1355-1367` uses `PathBuf::from("")`
  and reads `./config` or `./config.toml`. Cargo, and Lorry's own
  `cargo_registry.rs:59-61`, treat empty as unset.
- `spec.md:671-672` says "invocation directory and its parents, then
  CARGO_HOME". The code merges `CARGO_HOME` first, at lowest priority,
  as Cargo does.
- `spec.md:348` says Lorry writes only below the target directory's
  `lorry/`. The artifact lock is `<target>/.lorry-artifacts.lock`.

## 4. Design details

### 4.1 Image policy and manifests

New tree rules in `motor-os-permissions.yaml`:

| Path | Directories | Files | Scripts | ELF |
|---|---|---|---|---|
| `/system/tmp` | `rwx------` | `rw-------` | `rwx------` | `r-x------` |
| `/user/tmp` | `rwxrwx---` | `rw-rw----` | `rwxrwx---` | `r-xr-x---` |
| `/none` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` |
| `/none/cfg`, `/none/tmp` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` |
| `/devtools/lorry` | `rwxr-xr-x` | `rw-r--r--` | | |
| `/devtools/lorry/user` | `rwxrwx---` | `rw-rw----` | `rwxrwx---` | `r-xr-x---` |
| `/devtools/lorry/none` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` |

`/devtools/llvm/cfg` uses the default public-read rule. The `/devtools/tmp`
rule is removed.

The new `/none` directories go in all five manifests:
`motor-os-base.yaml`, `motor-os.yaml`, `motor-os-dev.yaml`,
`motor-os-system-tty.yaml`, and `motor-os-vsock-test.yaml`. A4 removes
`/devtools/tmp`, `/devtools/cfg`, and `/devtools/cfg/llvm` from
`motor-os-dev.yaml`. B5 replaces the `/devtools/lorry/{cache,vendor,...}`
entries.

Imager tests to update: `main.rs:1014-1023` and `permissions.rs:491-499`.

Test roots in `full-test.sh:398-405`:

- Standard image: `MOTOR_TEST_ROOT` becomes `/none/tmp/motor-tests`, so
  binaries land in `/none/tmp/motor-tests/tests`. Uploaded programs are
  finalized `r-xr-xr-x`, so NONE can run them.
- The harness removes a leftover root and then creates it (618-635). After
  creating it, it checks that the directory is new. A directory that NONE
  created first would be writable by NONE.
- `TEST_TMP` becomes `/user/tmp/motor-tests` on both images. A new
  `NONE_TEST_TMP`, `/none/tmp/motor-tests/tmp`, holds fixtures that a NONE
  child must reach.
- Scripts that default `MOTOR_TEST_ROOT` themselves (`test-sftp.sh:28`,
  `test-ssh-client.sh:11`, `test-udp-fragmentation.sh:15`,
  `test-unwind.sh:79`) follow the same split.

### 4.2 `TMPDIR` in rt.vdso

In `rt_process.rs`, after the child's capabilities are known (670-705):

1. Work out the child's role and the parent's role with
   `ProcessRole::from_caps`.
2. If the child's environment has no `TMPDIR`, set it to
   `moto_rt::fs::temp_dir(child role)`.
3. Otherwise, if the child's role is lower and its `TMPDIR` equals the
   parent's own `TMPDIR` (read with `moto_rt::process::getenv`), treat it
   as inherited and replace it the same way.
4. Otherwise keep it: the parent set it explicitly.

std builds the child environment with `CommandEnv::capture()`
(`../toolchain-src/rust/library/std/src/sys/process/motor.rs:128-130`),
which merges the inherited and explicit values. That is why step 3 compares
values.

moto-rt gets `temp_dir(role)`, returning `/system/tmp`, `/user/tmp`, or
`/none/tmp`. The unused `TEMP_DIR` constant goes away.

Processes the kernel starts directly (sys-io) do not pass through rt.vdso.
They use no temporary files.

Follow-up edits: rush's `default_tmpdir` and its test; `full-test.sh:733-736`;
the Rust temporary-directory check in `test-dev-sources.sh:262-267`; and
`native-temp.c` and `native-temp.cpp`, which assert today's defaults.

### 4.3 Lorry configuration

**Layers after the change.**

| Platform | Global | Per workspace, written by you | Per workspace, recorded by Lorry |
|---|---|---|---|
| Motor, Interactive | `/user/cfg/lorry.toml` | `[workspaces."<root>"]` in that file | `/user/cfg/lorry-workspaces/` |
| Motor, NONE | `/none/cfg/lorry.toml` | same, in that file | `/none/cfg/lorry-workspaces/` |
| Linux | `~/.config/lorry/lorry.toml` | same, in that file | `~/.config/lorry/workspaces/` |

Motor loses its system layer, so `repositories.system` and
`system-constraints` remain only on Linux. Nothing shipped uses them on
Motor.

**Workspace `lorry.toml`.** Only the workspace root's file is read.
Allowed keys: `config-version`, `cargo-compat-version`, `vendor.targets`,
`vendor.include-host`, `repositories.keep-artifacts`, and
`repositories.keep-sources`. Any other key is an error that names the key
and the file where it belongs.

**`[workspaces."<root>"]` tables.** The key is the canonical absolute
workspace root. At first a table may hold only `policy.rules`. Rule IDs
must still be unique across the whole configuration.

**Decisions file.** Named by the first 32 hex digits of the SHA-256 of the
root path. Lorry checks the `workspace` field against the real root.

```toml
# Generated by Lorry. Delete this file to forget these decisions.
format-version = 1
workspace = "/user/helix"
accept-all = true
approved-review-sha256 = "…"

[[cargo-setting]]
file = "/user/helix/.cargo/config.toml"
key = "target.x86_64-unknown-motor.linker"
value = "/devtools/bin/cc"
```

The writer follows `redirect.rs` `TrustStore::save`: a lock file in the
same directory, re-read under the lock, then `AtomicFile`. Size and count
limits match the redirect store.

**Built-in Motor defaults**, replacing `/devtools/cfg/lorry.toml`:
curl `/system/bin/curl` and CA `/system/cfg/ssl/ca-certificates.crt`
(already the defaults in `curl.rs`); vendor targets
`x86_64-unknown-linux-musl` and `x86_64-unknown-motor` with the host;
`keep-artifacts` and `keep-sources`; the C compiler `/devtools/bin/cc` with
`--target=x86_64-unknown-motor`; the C++ compiler `/devtools/bin/c++` with
`stdlib = "c++"`; the archiver `/devtools/llvm/bin/llvm ar`. The cache and
repository follow the role. The redirect file becomes
`<role cfg>/lorry-redirect-sites.toml`. The test extraction root moves
from `/user/tmp/lorry/test-extraction` to the role's temporary directory.

**Shipped configuration.** `/user/cfg/lorry.toml` and
`/none/cfg/lorry.toml` carry `cargo-compat-version`, `policy.default`,
`path-roots`, and the limits. `/user/cfg/lorry.toml` also carries the 25
exact grants and the `moto-io` rule for `/devtools/src/motor-os/sys`.

### 4.4 `--accept-all`

Policy gets one flag that means "trust build-time code": it is set for
Cargo-cache builds, as today, and for a workspace whose decisions file has
`accept-all`. The capability checks at `policy.rs:200`, `214`, and `283`
already use such a flag (`trust_cargo_cache`). Admission is still
required: unlike Cargo-cache mode, an accepted workspace still needs a
vendored, reviewed lock. Later vendor runs in that workspace use
`Mode::AcceptAll`.

### 4.5 Approving the admission record

`apply_to_policy` runs only when the decisions file approves
`compact.review_sha256`, or has `accept-all`. Otherwise `build`, `check`,
`run`, and `test` stop with a hint to run `lorry vendor`.

`vendor_workspace` today skips approval when nothing changed. It will also
ask when the record exists but is not approved. Approval, interactive or
by `--accept-all`, records the new digest.

Tests affected: anything that builds from a committed record without
vendoring first, mainly `test-native.sh` (Lorry's own record and
`native-fixture/.lorry`) and the development image's source builds.

### 4.6 `.cargo/config.toml`

- **Yours:** the file in `CARGO_HOME`. An empty `CARGO_HOME` counts as
  unset. Environment variables are also yours.
- **The repo's:** every other `.cargo` file Lorry reads.

**Safe rustflags**, which need no approval: `--cfg`, `--check-cfg`,
`-A`/`-W`/`-D`/`-F`, `--cap-lints`, `--remap-path-prefix`, and these `-C`
options: `opt-level`, `debuginfo`, `debug-assertions`, `overflow-checks`,
`codegen-units`, `target-cpu`, `target-feature`, `panic`,
`force-frame-pointers`, `link-self-contained`, `default-linker-libraries`.
Both `-Cname=value` and `-C name=value` forms count. Any other flag,
including `-C linker`, `-C link-arg`, `-L`, `-l`, `-Z`, `--extern`, and
`@file`, needs approval.

An approval names the file, the key, and the exact value. For rustflags,
the value is that key's whole list. Lorry records only approvals.

Repos in this tree would see no prompt: Helix sets only
`--cfg tokio_unstable`; Lorry and gix set `-Clink-self-contained=no` and
`-Cdefault-linker-libraries=yes`; the imager sets `--cfg tokio_unstable`.
Some Lorry contracts set a linker or runner and will need approvals.

### 4.7 Approving build scripts without `--accept-all`

Today `preflight_workspace` and `inspect` (`policy.rs:157-224`,
`283-294`) return an error for the first package whose build script or
procedural macro has no grant. In `vendor`, these become proposed
capabilities instead:

- `vendor_workspace` runs the policy checks in a mode that collects the
  missing grants rather than failing on the first one.
- The review lists them with the other capability changes. One prompt
  covers the whole review, as now.
- On "yes", crates.io and Git grants are written into the new admission
  record, and its digest goes into the decisions file. Member grants go
  into the decisions file as `[[member-grant]]` entries holding the name,
  `build-script`, and `proc-macro`.
- Each approved build script gets the configured native tools. The review
  prints them next to the script, for example
  `build script (c-compiler, cxx-compiler, archiver)`.
- A declined review or a run without a terminal fails as it does today.
  The help text then names `--accept-all` and the `[workspaces]` rules.

Outside `vendor`, a missing grant is still an error.

## 5. Patches

**B1. Workspace `lorry.toml` restricted.**
- `src/config.rs`: project key allow-list, `nearest_file` replaced by a
  root-only check, `[workspaces]` parsing.
- `policy.rs:65-84` and `1049-1091`: help text names the user file and the
  `[workspaces."<root>"]` table.
- Tests: 15 contract scripts and `tests/editor-workspace/src/main.rs`
  move their project rules into the test `HOME` configuration. Fixtures
  `tests/proc-macro-fixture/lorry.toml`, `tests/native-fixture/lorry.toml`,
  and `src/tests/rust-analyzer-smoke/fixtures/lorry/lorry.toml` go the same
  way. `src/sys/lorry.toml` is removed;
  `editor-workspace-contract.sh:19` and `docs/helix.md:111` change.
- A contract case: a workspace `lorry.toml` with `[policy]` is rejected.
- Docs: `spec.md` around 1101-1135 and 1271-1280, `README.md` around 557.

**B2. Decisions file and `--accept-all`.**
- New module next to `redirect.rs` for the decisions file.
- `vendor/workspace.rs:388-436`: record `accept-all` and the approved
  digest.
- `policy.rs`: the trust flag. `engine.rs:418` and `admission.rs:85`:
  approval check.
- New `tests/workspace-trust-contract.sh`, run from `test-all.sh`:
  - a fresh copy with a committed record is refused, then
    `vendor --accept-all` lets it build;
  - deleting the decisions file revokes it;
  - a missing build-script grant is accepted only with `accept-all`.
- `registry-contract.sh` checks that `--accept-all` covers a
  build-script package.
- Interactive approval (4.7), driven through `script -qefc` as in
  `git-patch-contract.sh:284`:
  - a missing grant is shown and approved;
  - a declined review leaves no record;
  - a later version of the same package asks again.

**B3. `.cargo` approvals.**
- `src/config.rs`: remember which file set each value; the empty
  `CARGO_HOME` fix.
- A classifier for dangerous settings, the prompt in `vendor`, and the
  check in other commands.
- Contract cases: a repo linker asks and is recorded; a changed value asks
  again; no terminal fails with the hint; `--accept-all` skips the
  question; a `CARGO_HOME` linker never asks.
- Spec: the trust rules and the corrected merge-order sentence.

**B4. Built-in Motor defaults.**
- Remove `img_files/motor-os-dev/devtools/cfg/lorry.toml`. Grow
  `img_files/motor-os-dev/user/cfg/lorry.toml` and add
  `img_files/motor-os-dev/none/cfg/lorry.toml`.
- `test-native.sh:250-255` reads the user file. `test-dev-sources.sh:208`
  and the dev-image web page `lorry.html` change.

**A1. `/none` tree.** Policy rules and the five manifests. No test moves
yet.

**A2. `TMPDIR` by role.** moto-rt, rt.vdso, rush, and the follow-up edits in
4.2. moto-rt is a core change, hence the full gate.

**A3. New assembly.**
- `build-motor-os.sh`: `CFG_LLVM="devtools/llvm/cfg"`, and the five
  launchers drop their `TMPDIR` export.
- Add the clang configuration directory to the native configuration
  digest in `toolchain-assembly.sh`, so the key changes.
- Docs: `docs/build-llvm.md`, `docs/libc.md`, `docs/toolchain.md`.

**A4. Close and remove.**
- Policy modes for `/user/tmp` and `/system/tmp`. Remove `/devtools/tmp`
  and `/devtools/cfg` from the dev manifest.
- Move the test roots (4.1) and every user listed in 3.6. The systest NONE
  checks and `test-sftp.sh` get fixtures in `/none/tmp` with positive
  controls.
- Helix's rust-analyzer `TMPDIR` line is removed. rt.vdso now provides it.
- Docs: `docs/fs-permissions.md` (table and notes), `docs/caps.md`,
  `docs/build-rustc.md`, `docs/helix.md`, rmux `details.md`, and the web
  pages `filesystem.html`, `processes.html`, `devtools.html`,
  `toolchain.html`, `c-cpp.html`, `capabilities.html`.

**B5. Lorry and roles.**
- Role detection, the role's paths, and refusing System with a clear
  error.
- Manifest and policy entries for `/devtools/lorry/user` and
  `/devtools/lorry/none`.
- `test-native.sh` and `test-dev-sources.sh:193-205` paths.
- A native check: a NONE `lorry vendor --accept-all` uses `/none/cfg` and
  `/devtools/lorry/none`, and cannot read `/user/cfg`.

## 6. Question background

All questions are answered; see decisions 9 to 20 in the plan. Two
notes on the choices:

- Decision 19: the explicit-`TMPDIR` test is a comparison because std hands
  rt.vdso the merged environment (`CommandEnv::capture()`). An exact test
  would need std, mlibc, and libc++ changes, a new moto-rt release, and a
  toolchain rebuild.
- Decision 20: without it, Helix's two grammar packages would need
  hand-written `native-tools` rules even after their build scripts were
  approved.
