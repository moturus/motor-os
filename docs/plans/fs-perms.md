# Filesystem permissions for Motor OS images

Status: **proposed (v4: v2/v3 review fixes plus the `sysbox cp` mode-propagation
test gap); stop for review before implementation**.

## Goal

Build every Motor OS image with deliberate Motor FS permissions instead of
granting every role write access to all shipped content. The development image
is the complete policy surface; the base, standard, and System-tty images
contain subsets of the same destination paths and must apply the same permission
to every shared entry.

Today the imager derives modes purely from the host executable bit
(`image_file_permissions` in `src/imager/src/main.rs`): every shipped file is
`rw-rw-rw-` or `rwxrwxrwx`, and every directory — listed, implicit, and the
root — is `rwxrwxrwx`. Any role, including None, can therefore rewrite
`/system/cfg/sys-init.cfg`, which assigns System-role capabilities at the next
boot, and can read the sshd host key and password verifier in
`/system/cfg/sshd.toml`. The chmod plan (`docs/plans/chmod.md`) explicitly
deferred configuration hardening as a follow-up; this plan is that follow-up
for shipped image content.

This plan changes only permissions in newly built images. It does not migrate an
existing image. Its ELF W^X guarantee is correspondingly an image-build
guarantee; the separate runtime-creation gap is recorded under non-goals rather
than hidden by claiming an OS-wide guarantee.

## Permission model and policy principles

A mode contains three triplets in **System, Interactive, None** order. The only
legal triplets are `rwx`, `rw-`, `r-x`, `r--`, and `---`; every mode must remain
monotonic:

```text
None ⊆ Interactive ⊆ System
```

Directory `x` controls listing, traversal, and lookup, while directory `w`
controls creation, deletion, and rename of children. In particular, making a
file non-writable does not protect it from replacement when its parent directory
is writable. The directory policy below is therefore the integrity boundary.
W^X applies to compiled executable ELF binaries, not directories, ELF object
files, or scripts. Directory `x` is traversal authority and does not make bytes
executable. A script remains source text interpreted by another executable, and
may deliberately be both writable and executable in an Interactive-owned
location.

At the completed-image boundary, every executable ELF follows W^X: if any role
may execute the ELF, no role may write it. This prevents, for example, a
System-writable ELF that Interactive can run. Scripts below `/user/bin` and
`/devtools/bin` are the intentional writable/executable cases requested for
user customization. Regardless of type, every executable directly below
`/system/bin` is `r-xr-xr-x`.

The image policy follows these rules:

- System owns installed OS and toolchain content. It retains write access to
  installed files other than executable ELFs and to parent directories, but
  executable ELF entries are read/execute-only as required by W^X.
  `/system/bin` scripts are also read/execute-only as an explicit
  system-integrity rule.
- Interactive may read and run installed programs but may not replace content
  in `/system` or the installed parts of `/devtools`.
- `/user` is Interactive-owned. Interactive may install programs, edit
  configuration, and create work there.
- Scripts directly below `/user/bin` and `/devtools/bin` are writable by
  Interactive; executable ELFs in those directories are not writable by any
  role.
- `/devtools/src` is an Interactive-writable development workspace. The
  dev-sources suite (`src/tests/test-dev-sources.sh`) builds the shipped
  sources in place there, creating `.lorry` and `target` trees below them; the
  native Lorry self-test (`src/bin/lorry/tests/test-native.sh`) works under
  `/devtools/tmp` instead.
- None may read and execute public installed content, but may write only the
  explicitly shared log and scratch trees. None cannot traverse `/user/cfg`, so
  credentials placed there are not exposed to least-privileged processes.
- Host owner/group/other read and write bits do not define Motor roles. Among
  host-executable sources, the imager distinguishes an ELF by its header and a
  script by a shebang; the image policy supplies all three complete Motor
  permission triplets.

## Required development-image permissions

The following table is exhaustive by longest matching destination-tree rule.
"Regular" means a file without a host executable bit (including ELF object
files), "script" means a host-executable file starting with `#!`, and "ELF"
means a host-executable ELF of executable type (`ET_EXEC` or `ET_DYN`). Reject a
host-executable source that is neither a script nor an executable ELF rather
than guessing. An exact-entry rule after the table takes precedence over every
tree rule.

| Destination tree | Directories | Regular files | Scripts | ELF binaries | Purpose |
|---|---|---|---|---|---|
| `/` and all otherwise unmatched paths | `rwxr-xr-x` | `rw-r--r--` | `rwxr-xr-x` | `r-xr-xr-x` | System-owned installed content; public read/execute |
| `/system/bin` | `rwxr-xr-x` | `rw-r--r--` | `r-xr-xr-x` | `r-xr-xr-x` | every system command is non-writable and executable by all roles |
| `/system/logs` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` | strobe is None-role and creates/rotates logs; systest also writes a log |
| `/system/tmp` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` | shared system scratch |
| `/user` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | Interactive-owned programs and work, readable by None by default |
| `/user/bin` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | user scripts remain editable; compiled programs follow W^X |
| `/user/cfg` | `rwxrwx---` | `rw-rw----` | `rwxrwx---` | `r-xr-x---` | Interactive configuration and credentials; hidden from None |
| `/user/tmp` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` | scratch for every role; also the platform default `TMPDIR` |
| `/devtools/bin` | `rwxr-xr-x` | `rw-r--r--` | `rwxrwxr-x` | `r-xr-xr-x` | installed ELF tools are fixed; launcher scripts are user-editable |
| `/devtools/src` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | editable sources and project-local Lorry state |
| `/devtools/tmp` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` | native build and test scratch |

Trees that intentionally stay on the default rule, for the record:

- `/system/services`: service ELFs keep public read/execute. This is
  load-bearing, not an oversight: the full-test suites run
  `/system/services/dns-resolver --self-test` from an Interactive SSH session
  and respawn it with `MOTOR_OS_CAPS=0x8` (a None-role child), and spawn reads
  the program file with the spawning process's own role
  (`rt.vdso/src/rt_process.rs`).
- `/system/cfg`, including the implicit `/system/cfg/ssl` subtree: the default
  rule already reduces these files from `rw-rw-rw-` to System-writable-only,
  which is the hardening this plan needs; the two secrets below additionally
  lose None read. Narrowing None's read access to the remaining configuration
  is deferred — None-role services (dns-resolver is None: `svc:8:` grants only
  `CAP_LOG`) have not been audited for configuration reads through mlibc.
- The installed `/devtools` trees (`cfg`, `llvm`, `lorry`, `rust`, `tests`,
  `www`): the suites only read and execute there; guest writes go to
  `/devtools/tmp` and `/devtools/src`. `/devtools/lorry` ships empty; leave it
  and the rest of the image contents unchanged in this permissions-only work.

Two shipped secrets need exact modes:

| Entry | Mode | Reason |
|---|---|---|
| `/system/cfg/sshd.toml` | `rw-r-----` | Contains the development host private key and password verifier; russhd runs as Interactive |
| `/system/cfg/ssl/ssl-key.pem` | `rw-r-----` | The Interactive development web-server command needs the key; None does not |

Both files ship from `img_files/motor-os-base`, which every image includes, so
the exact entries exist in all four images. `/system/cfg/ssl` appears in no
`directories:` list — it exists only through the static-dir walk — so exact
entries and directory-mode resolution must work for implicitly created
directories. The key's one consumer is the `/devtools/bin/www` script, which
starts `httpd-axum` with `--ssl-key /system/cfg/ssl/ssl-key.pem`; russhd takes
its config path from a `svc:` argument in `sys-init.cfg`.

All modes above are valid Motor modes and satisfy cross-role monotonicity. Every
executable ELF satisfies W^X. Writable/executable `rwx` file triplets occur only
for scripts in trees where the table permits them.

## Image configuration format

Add one shared `src/imager/motor-os-permissions.yaml` policy and reference it
from `motor-os-base.yaml`, `motor-os.yaml`, `motor-os-dev.yaml`, and
`motor-os-system-tty.yaml`:

```yaml
permission_policy: "motor-os-permissions.yaml"
```

Resolve the policy path relative to the image configuration file, not the
process working directory. `permission_policy` is a required `Config` field: a
configuration without it fails to parse, so an image cannot silently build with
the old fully permissive modes. Keeping one policy is important: content
overlays may replace a source file, but a destination path must have the same
permission in every image that contains it.

Use a small, non-glob schema:

```yaml
default:
  directory: "rwxr-xr-x"
  file: "rw-r--r--"
  script: "rwxr-xr-x"
  elf: "r-xr-xr-x"

trees:
  - path: "/system/bin"
    directory: "rwxr-xr-x"
    file: "rw-r--r--"
    script: "r-xr-xr-x"
    elf: "r-xr-xr-x"
  - path: "/user/bin"
    directory: "rwxrwxr-x"
    file: "rw-rw-r--"
    script: "rwxrwxr-x"
    elf: "r-xr-xr-x"
  - path: "/devtools/bin"
    directory: "rwxr-xr-x"
    file: "rw-r--r--"
    script: "rwxrwxr-x"
    elf: "r-xr-xr-x"
  # The remaining tree rows from the table above follow.

entries:
  - path: "/system/cfg/sshd.toml"
    mode: "rw-r-----"
  - path: "/system/cfg/ssl/ssl-key.pem"
    mode: "rw-r-----"
```

Paths are normalized absolute image paths. Tree matching is by complete path
component, not string prefix (`/user` must not match `/username`); the longest
matching tree wins. An exact entry wins over a tree. Duplicate exact paths,
duplicate tree paths, invalid paths, invalid modes, and non-monotonic modes are
configuration errors. Regular-file profiles may not grant `x`. Directory
profiles must grant System `rwx`: the builder creates children inside every
directory it makes, and System directory sealing is out of scope. ELF profiles
must grant System `x` and may not grant `w` to any role. Script profiles must
grant System `x`, but may also grant `w`; `/system/bin` is additionally
validated to resolve every script and ELF to exactly `r-xr-xr-x`. Validate an
exact entry against the kind and file classification of its matched
destination. A tree may be absent from a subset image. Exact entries must exist
in every image using the policy, which is true for the two entries above and
catches misspelled security-sensitive paths.

The policy is based on the final destination. A later `static_dirs` overlay can
replace `/system/cfg/sshd.toml`'s contents without replacing its permission.

## Imager changes

1. Parse and validate the policy.
   - Add deserializable policy, tree-rule, entry-rule, and four-kind permission
     structs next to `Config` in `src/imager/src/main.rs` (or a small dedicated
     module if the implementation no longer fits cleanly there).
   - Reuse `chmod::parse_mode` so the image builder and offline `imager chmod`
     accept exactly the same modes and monotonicity rules.
   - Add a separate ELF W^X and file-class validator; `chmod::parse_mode` must
     continue to accept `rwx` because directories and writable scripts
     legitimately require it and the general offline command is not
     image-policy-specific.
   - Store parsed `RolePermissions`, not mode strings, after validation.

2. Resolve permissions from image destinations.
   - Replace `image_file_permissions(source)`, which currently grants either
     `rw-rw-rw-` or `rwxrwxrwx`, with a resolver taking `(destination,
     FileClass)` where `FileClass` is `Regular`, `Script`, or `Elf`.
   - Read the source prefix once while constructing the manifest. A file without
     a host executable bit selects `Regular`, even if it is an ELF object. For a
     host-executable file, a `#!` prefix selects `Script`; a valid ELF header
     with `e_type` equal to `ET_EXEC` or `ET_DYN` selects `Elf`. Reject any
     remaining host-executable source. Do not translate host read/write bits or
     map host owner/group/other classes to Motor roles.
   - Resolve after all overlays have selected the winning source so permissions
     cannot depend on which overlay supplied the content.

3. Create files with writable final modes directly; finalize non-writable
   executables after writing.
   - Pass the policy into `motor_fs_create_dir_all`; when it creates an implicit
     or explicitly listed directory, resolve the directory mode from its full
     destination path instead of using `RolePermissions::all(Rwx)`.
   - Create regular files and writable scripts with their final policy modes and
     write them normally.
   - Any file whose resolved final mode denies System `w` — under this policy,
     every ELF plus the `/system/bin` scripts — is created temporarily as
     `rw-------`, its bytes written, then changed to the resolved read/execute
     mode with the existing host-only `set_all_permissions_image_admin` API.
     Key the staging path on the resolved mode, not on the file class, so a
     future policy edit cannot produce a file the builder is unable to write.
     The exact permission update is atomic, so the file is never writable and
     executable at the same time. The image is offline and unpublished during
     this transition. Do not use the
     runtime setter: `rw-` to `r-x` is not a narrowing operation and is
     correctly rejected there.
   - Set `ROOT_DIR_ID` to the policy's root-directory mode through the existing
     host-only `set_all_permissions_image_admin` API. Motor FS format otherwise
     leaves the root at its all-zero, fully permissive default.
   - Keep the existing `required_executables` host checks. They catch staging
     mistakes before the destination is classified as a script or ELF.

4. Fail safely and visibly.
   - Validate the complete policy before creating the scratch filesystem.
   - Report the config path, policy path, destination, and offending mode in
     errors; avoid the current context-free `unwrap` behavior for new policy
     failures.
   - Assert during manifest construction that every exact-entry rule matched
     once. Tree rules may match zero entries because smaller images omit the
     development trees.
   - Do not implement the policy by running `imager chmod` repeatedly after the
     image is built. Finalize ELFs and read-only scripts on the open scratch
     Motor FS before `flush`; this avoids repeated qcow2 conversion, cannot
     publish a partially hardened image, and also covers implicit directories
     and the root.

5. Move standard-image test injection below a writable tree.
   - The current standard-image harnesses create `/devtools` through an
     Interactive session: `full-test.sh`, `full-test-networking.sh`, and
     `test-tui.sh` via SFTP `mkdir` batches, `test-terminal-size.sh` via SSH
     `mkdir`. That correctly fails once `/` is `rwxr-xr-x`; making the root
     Interactive-writable would permit replacing `/system` and is not
     acceptable.
   - Define one guest test root across those four scripts and their shared
     helpers: use shipped `/devtools` on the development image and
     `/user/tmp/motor-tests` for standard-image uploads. Apply it consistently
     in `full-test.sh`, `full-test-networking.sh`, `test-tui.sh`,
     `test-terminal-size.sh`, `test-sftp.sh`, and
     `test-udp-fragmentation.sh`. The last helper is sourced by both full-test
     scripts and must execute systest from `<test-root>/tests/systest` rather
     than its current hard-coded `/devtools/tests/systest`.
   - `test-sftp.sh` defaults its upload and phase-0 fixture paths below
     `/devtools/tmp` and explicitly creates `/devtools/tmp/lorry`. Derive all
     three paths, including that prerequisite `mkdir`, from the selected test
     root. It runs after `full-test.sh` and `full-test-networking.sh` have
     created `<test-root>/tmp`; its standalone development-image callers keep
     the `/devtools` default. Keep the standard-image assertion that no
     `/devtools` ships — it lives in all four creating scripts and in the
     imager unit test `production_image_requires_ripgrep`.
   - Uploads below `/user/tmp/motor-tests` keep working because runtime-created
     entries still start `rwxrwxrwx`, and the relocated tree stays reachable by
     a None-role child (systest's permission tests re-execute the systest
     binary with `MOTOR_OS_CAPS=0x0`): every path component grants None `r-x`.
     A root below `/user/cfg` would not.
   - `sysbox cp` propagates permissions: it applies the source's caller-role
     mode to the new copy through the runtime single-role setter, which narrows
     the caller's own byte and cascades the narrowing onto None. The `sysbox
     ls` long-listing fixture in `full-test.sh` copies `/system/bin/ls` and
     asserts the copy lists as `-rwxrwxrwx`; once `/system/bin/ls` is
     `r-xr-xr-x`, an Interactive copy resolves to `-rwxr-xr-x`. Update that
     expectation. The executable-color checks in the same fixture keep passing
     because Interactive retains `x`, and no other suite asserts the exact mode
     of a file copied from shipped content (`stress-soak.sh` copies
     `/devtools/www` content but checks only success, and deleting the
     read-only copy stays legal because deletion is gated by the parent
     directory's `w`).
   - The dev-image-only suites (`test-dev-sources.sh`, `gears-test.sh`,
     `stress-soak.sh`, `test-native.sh`) already confine guest writes to
     `/devtools/src` and `/devtools/tmp` and need no changes.

No async-fs, motor-fs, sys-io, Rust stdlib, or moto-rt change is planned. The
existing full-state creation API and imager-only administrative root setter are
sufficient.

## Tests and acceptance criteria

Add focused imager tests that:

- parse every policy mode and reject malformed, non-monotonic, duplicate, and
  non-normalized rules, plus writable ELF profiles while continuing to accept
  `rwx` directory and script profiles;
- prove exact-entry precedence, longest component-tree precedence, and that
  `/user` does not match `/username`;
- classify executable ELF headers, shebang scripts, regular data, and a
  non-executable ELF object; reject an unrecognized host-executable file; and
  prove host read/write bits do not affect Motor roles;
- prove a later content overlay does not change destination permissions; and
- build and reopen a small temporary Motor FS fixture whose files are limited to
  `/system/bin`, `/user/bin`, and `/devtools/bin`, checking writable scripts,
  staged-then-finalized ELFs and `/system/bin` scripts, and the root
  directory's own mode (the format default would otherwise leave it
  `rwxrwxrwx`).

Add image-level assertions transitively through `src/tests/full-test.sh`, but
limit exhaustive file-mode verification to entries matching `/*/bin/*`:

- Every `/system/bin/*` file is executable and exactly `r-xr-xr-x`, whether it
  is an ELF or a script.
- Every ELF in `/user/bin/*` and `/devtools/bin/*` is `r-xr-xr-x`.
- Every script in `/user/bin/*` and `/devtools/bin/*` is `rwxrwxr-x`. On the
  development image, verify an Interactive session can edit a `/devtools/bin`
  script in place but cannot delete or rename it — the directory denies
  Interactive `w`. In-place editing is the workflow that matters: `red` saves
  with a truncating write, not a replace-by-rename. The standard image ships no
  scripts outside `/system/bin`, so this check is dev-image-only.
- Reject an unexpected regular data file in any of these three `bin`
  directories. Do not walk or assert the modes of every file elsewhere in the
  image.

Retain functional acceptance checks needed by the suites, such as an
Interactive session being unable to create a root-level tree while being able
to write the selected scratch and source trees. These are behavior checks, not
a whole-image permission audit.

Format Rust changes with `cargo +nightly fmt`, run imager tests and clippy
without new warnings, then run `src/tests/full-test.sh`,
`src/tests/full-test-dev.sh`, and `src/tests/full-test-networking.sh` in both
debug and release modes. The networking suite is a separate gate: neither of
the other full-test scripts invokes it, and this work changes its upload root.
This plan does not touch `src/sys`; if implementation reveals that a core
component must change, stop for review and apply the repeated-test requirements
for core components from `AGENTS.md`.

## Explicit non-goals and follow-ups

- Runtime-created files and directories still start as `rwxrwxrwx` in sys-io
  unless their creator narrows them; the create message carries no permission
  value, so runtime narrowing is inherently a second, non-atomic step. A
  runtime-created ELF therefore violates ELF W^X, so this plan must not be
  described as enforcing W^X after boot or across Motor OS. A separate design
  must cover the otherwise-forbidden `rw-` to `r-x` transition, open writable
  handles, SFTP uploads, native compiler output, and executable loading before
  changing sys-io's creation default.
- `/system/logs` stays writable by every role because strobe runs as None and
  rotates logs by delete-and-rename, and Interactive systest deletes its own
  log. Lower roles can therefore tamper with logs; protecting log integrity
  needs a strobe or sys-io change and is out of scope.
- The default rule leaves the remaining `/system/cfg` content (for example
  `sys-init.cfg` and `sys-net.toml`) readable by None. This plan locks down
  writes there; narrowing None reads is a follow-up that first requires
  auditing None-role services for configuration reads.
- This plan does not add users, ownership, groups, ACLs, sticky directories,
  symlinks, numeric Unix modes, or recursive chmod.
- W^X makes shipped ELF entries non-writable, but does not make their writable
  parent directories immutable. `/system/bin` additionally makes scripts
  non-writable. Broader System sealing, including parent directories and other
  non-ELF content, needs separate update/recovery review.
