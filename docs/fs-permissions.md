# Filesystem permissions in Motor OS images

Motor OS images are built with a declarative Motor FS permission policy. The
development image contains the complete policy surface; the base, standard,
and System-tty images contain subsets of the same destination paths and apply
the same mode to every shared entry.

This document describes permissions on newly built images. It does not define
a migration for existing images and does not impose an OS-wide W^X rule on
files created after boot.

## Permission model

A Motor FS mode contains three permission triplets in **System, Interactive,
None** order. For example, `rw-r-----` grants System read/write, Interactive
read, and None no access. The legal triplets are `rwx`, `rw-`, `r-x`, `r--`,
and `---`. Permissions are monotonic:

```text
None ⊆ Interactive ⊆ System
```

Directory `x` controls listing, traversal, and lookup. Directory `w` controls
creation, deletion, and rename of children. A non-writable file can therefore
still be replaced when its parent directory is writable; directory modes form
the image's integrity boundaries.

W^X applies to compiled executable ELF files in an image: when an ELF can be
executed, no role may write it. Directory `x` is traversal authority and does
not make directory bytes executable. Scripts are source text interpreted by an
executable and may intentionally be writable and executable in
Interactive-owned locations.

The policy follows these principles:

- System owns installed OS and toolchain content. Installed executable ELFs
  are read/execute-only. Files directly under `/system/bin` are also
  read/execute-only when they are scripts.
- Interactive may read and run installed programs, but cannot replace content
  in `/system` or the installed parts of `/devtools`.
- `/user` is Interactive-owned. Interactive may install programs, edit
  configuration, and create work there.
- Scripts directly under `/user/bin` and `/devtools/bin` are writable by
  Interactive. Compiled programs in those directories remain non-writable.
- `/devtools/src` is the Interactive-writable development workspace.
- None may read and execute public installed content, but may write only the
  explicitly shared log and scratch trees. None cannot traverse `/user/cfg`.
- Host owner/group/other read and write bits do not map to Motor roles. Host
  execute bits select which files require script or ELF classification; the
  image policy supplies all three complete Motor permission triplets.

## Development-image policy

The following table is exhaustive. A destination uses the longest matching
tree rule, with an exact-entry rule taking precedence. Images smaller than the
development image simply omit some of these destinations.

"Regular" means a file without a host execute bit, including an ELF object or
even an executable-type ELF stored as non-executable on the host. "Script"
means a host-executable file beginning with `#!`. "ELF" means a host-executable
ELF whose type is `ET_EXEC` or `ET_DYN`.

| Destination tree | Directories | Regular files | Scripts | ELF binaries | Purpose |
|---|---|---|---|---|---|
| `/` and otherwise unmatched paths | `rwxr-xr-x` | `rw-r--r--` | `rwxr-xr-x` | `r-xr-xr-x` | System-owned installed content with public read/execute access |
| `/system/bin` | `rwxr-xr-x` | `rw-r--r--` | `r-xr-xr-x` | `r-xr-xr-x` | Non-writable system commands executable by every role |
| `/system/logs` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` | Logs written and rotated by None-role strobe and test processes |
| `/system/tmp` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` | Shared system scratch |
| `/user` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | Interactive-owned programs and work, readable by None by default |
| `/user/bin` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | Editable user scripts and W^X compiled programs |
| `/user/cfg` | `rwxrwx---` | `rw-rw----` | `rwxrwx---` | `r-xr-x---` | Interactive configuration and credentials hidden from None |
| `/user/tmp` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` | Scratch for every role and the default `TMPDIR` |
| `/devtools/bin` | `rwxr-xr-x` | `rw-r--r--` | `rwxrwxr-x` | `r-xr-xr-x` | Fixed installed tools and Interactive-editable launcher scripts |
| `/devtools/src` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | Editable sources and project-local Lorry state |
| `/devtools/tmp` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` | Native build and test scratch |

Important consequences of the directory modes are:

- Interactive cannot create a new root-level tree or replace `/system`.
- Interactive can create and replace entries throughout `/user`, except where
  a longer tree rule restricts access.
- Interactive can edit a script in `/devtools/bin` in place, but cannot add,
  delete, or rename entries there because the directory is `rwxr-xr-x`.
- Every role can create and replace entries in `/system/logs`, `/system/tmp`,
  `/user/tmp`, and `/devtools/tmp` when that tree exists.

Several installed trees deliberately use the default rule:

- `/system/services` remains public read/execute. Interactive tests execute
  `/system/services/dns-resolver --self-test` and spawn a None-role resolver;
  the spawning role must be able to read the program file.
- Most of `/system/cfg`, including the implicit `/system/cfg/ssl` directory,
  is System-writable and publicly readable. None-role services have not yet
  been audited for configuration reads.
- `/devtools/cfg`, `/devtools/llvm`, `/devtools/lorry`, `/devtools/rust`,
  `/devtools/tests`, and `/devtools/www` are installed content. Guest build and
  test writes belong under `/devtools/src` or `/devtools/tmp`.
- `/devtools/crossterm` and `/devtools/rust-ctrlc` are staged dependency source
  trees. They are consumed read-only; project build output belongs under
  `/devtools/src` and scratch output under `/devtools/tmp`.

### Exact entries

Two secrets override their matching tree mode:

| Entry | Mode | Reason |
|---|---|---|
| `/system/cfg/sshd.toml` | `rw-r-----` | Contains the development host private key and password verifier; russhd runs as Interactive |
| `/system/cfg/ssl/ssl-key.pem` | `rw-r-----` | The Interactive development web-server command needs the key; None does not |

Both files are supplied by `img_files/motor-os-base`, which is included in all
four images. `/system/cfg/ssl` is an implicit directory created while walking
static content, so exact rules and directory rules apply equally to implicit
and explicitly listed paths.

## Policy configuration

The authoritative policy is
`src/imager/motor-os-permissions.yaml`. Every image configuration requires the
same relative reference:

```yaml
permission_policy: "motor-os-permissions.yaml"
```

The imager resolves the reference relative to the image configuration file,
not its current working directory. An image configuration without the field
does not parse, preventing a fallback to permissive legacy modes.

The policy has a non-glob schema:

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

entries:
  - path: "/system/cfg/sshd.toml"
    mode: "rw-r-----"
```

Policy paths are normalized absolute image paths. Tree matching uses complete
path components, so `/user` does not match `/username`; the longest matching
tree wins, and an exact entry wins over a tree. A content overlay may replace a
source file but cannot replace the destination's permission.

The imager rejects:

- unknown policy fields, invalid or non-monotonic modes, non-normalized paths,
  and duplicate tree or exact paths;
- regular-file profiles that grant execute;
- directory profiles that do not grant System `rwx`, because the builder must
  create children in every directory it constructs;
- script profiles that do not grant System execute;
- ELF profiles that do not grant System execute or that grant write to any
  role;
- any script or ELF directly under `/system/bin` whose resolved mode is not
  exactly `r-xr-xr-x`;
- an exact entry that is absent from an image using the policy, or whose mode
  is invalid for the actual directory or file class; and
- a host-executable source that is neither a shebang script nor an executable
  ELF.

A tree rule may match nothing because subset images omit development trees.
Exact rules must match because they protect named, security-sensitive entries
and a misspelled exact path must fail closed.

## Imager enforcement

The imager builds a final destination manifest after all static and source
overlays have selected their winning source. It classifies each source and
resolves each file mode from the final destination. It then constructs the
conceptual image directory set, including `/`, configured empty directories,
and every implicit parent, and validates the complete policy before creating
the scratch filesystem.

Source classification uses the host execute bits only as a gate:

1. A source with no host execute bit is Regular without examining its header.
2. An executable source beginning with `#!` is a Script.
3. An executable source with a valid ELF class, byte order, version, and an
   `ET_EXEC` or `ET_DYN` type is an ELF.
4. Any other executable source is rejected.

Host read/write bits and host owner/group/other classes never influence the
Motor mode.

The Motor FS root and every explicit or implicit directory are created with
their resolved policy modes. Files whose final mode lets System write are
created with that final mode. Files whose final mode denies System write are
created temporarily as `rw-------`, populated, and atomically changed through
the image-administration API to their final mode before the image is flushed.
Consequently, a shipped ELF is never writable and executable at the same time,
even during image construction. The transition happens only in the offline,
unpublished scratch filesystem.

The builder retains the host checks for named required executables. These catch
missing or non-executable generated inputs independently of policy
classification.

## Verification and test artifact locations

Imager tests cover policy parsing and validation, rule precedence, source
classification, content overlays, the root mode, and file finalization by
building and reopening a small Motor FS image.

Guest acceptance tests intentionally limit exhaustive mode checks to direct
entries matching `/*/bin/*`:

- every `/system/bin/*` entry is exactly `r-xr-xr-x`;
- every `/user/bin/*` and `/devtools/bin/*` entry is either an ELF at
  `r-xr-xr-x` or a script at `rwxrwxr-x`; and
- any regular data file or unexpected mode in those directories fails the
  suite.

The development-image suite also proves that Interactive can edit
`/devtools/bin/www` in place but cannot delete or rename it. Functional checks
prove that Interactive cannot create a root-level directory and can write the
appropriate scratch and source trees. Tests do not walk and assert the modes of
every other image file.

The full-test harnesses use a shared `MOTOR_TEST_ROOT` convention. Development
images use their shipped `/devtools`, while standard-image uploads use
`/user/tmp/motor-tests`. Standard tests continue to assert that `/devtools` is
absent. The standard root is reachable by None-role test children because
every component grants None traversal; `/user/cfg` would not be suitable.

## Limits and follow-up work

- Runtime-created files and directories still start as `rwxrwxrwx` in sys-io
  unless their creator narrows them. Runtime narrowing is a separate,
  non-atomic operation, so this image policy must not be described as enforcing
  W^X after boot or across Motor OS. A runtime design must address creation
  modes, writable handles, uploads, compiler output, and executable loading.
- `/system/logs` remains writable by every role because None-role strobe
  rotates logs and Interactive tests write and delete logs. Protecting log
  integrity requires a service or sys-io change.
- The remaining `/system/cfg` content, including `sys-init.cfg` and
  `sys-net.toml`, remains readable by None. Narrowing those reads requires an
  audit of None-role services.
- The model has no users, ownership, groups, ACLs, sticky directories,
  symlinks, numeric Unix modes, or recursive chmod.
- Non-writable shipped ELF files can still be replaced where their parent
  directory is writable. `/system/bin` additionally protects scripts, but
  broader System sealing requires an update and recovery design.

## Non-obvious implementation decisions

This section records implementation judgments for review and can be removed
after they are accepted.

1. **Unknown YAML fields fail parsing.** Ignoring a misspelled security rule is
   more dangerous than rejecting a future field understood by a newer imager.
   Strict parsing also keeps all four image configurations on one auditable
   schema.
2. **ELF recognition is deliberately minimal and dependency-free.** The imager
   checks the ELF magic, class, byte order, version, and `e_type` in the common
   header. It needs only to distinguish `ET_EXEC`/`ET_DYN` from data and object
   files; adding an ELF parser would expand a security-sensitive build tool for
   no additional policy information.
3. **Host execute remains the classification gate.** A non-executable host
   file is Regular even when it contains executable ELF bytes. This preserves
   the existing explicit staging signal and prevents arbitrary data from
   becoming executable merely because of its contents. Executable files with
   unknown formats fail instead of inheriting an unsafe guess.
4. **Finalization is keyed by the resolved mode, not the file class.** Any file
   that System cannot write is staged as `rw-------` and finalized through the
   image-only administrative setter. This handles `/system/bin` scripts as
   well as ELFs and remains correct if later exact rules introduce another
   non-writable file.
5. **Exact entries must exist in every image.** Allowing an absent exact rule
   would make a typo in a secret path indistinguishable from an intentional
   subset omission. Tree rules, which describe optional subtrees, may remain
   unmatched.
6. **Rebased dependency source trees remain read-only.** The newly staged
   `/devtools/crossterm` and `/devtools/rust-ctrlc` trees are consumed as build
   dependencies. Cargo writes project targets below `/devtools/src` and uses
   `/devtools/tmp` for scratch, so there is no demonstrated need to make these
   separate dependency roots Interactive-writable.
7. **Standard test artifacts live under `/user/tmp`, not a newly created
   `/devtools`.** Making `/` Interactive-writable solely to preserve the old
   upload path would also permit replacement of `/system`. The shared
   `MOTOR_TEST_ROOT` convention keeps the image boundary intact and lets helper
   scripts retain `/devtools` as their standalone development-image default.
8. **Guest mode enumeration is restricted to `/*/bin/*`.** Policy unit tests
   validate all configured modes and image construction validates every
   resolved entry. Guest tests concentrate on executable installation
   boundaries and functional access checks, avoiding a brittle duplicate of
   the complete image manifest.
9. **`rmux` creates its port directory only when it is absent.** A detached
   server spawned by a System-role client deliberately receives the default
   None role. `/user/tmp` permits that role to create the port file, but
   blindly calling `create_dir_all("/user/tmp")` first asks Motor FS to create
   the already-existing child of `/user`; Motor FS checks write access to the
   non-None-writable parent before detecting the existing child. Preserving
   System authority in the server or making `/user` None-writable would grant
   unnecessary authority. Testing whether the shipped scratch directory
   exists before creating it preserves the role boundary and still supports a
   caller-selected, absent `TMPDIR`.
10. **Denial acceptance tests assert filesystem postconditions.** The current
    sysbox `mkdir`, `mv`, and `rm` applets print a permission diagnostic but
    may still return success. The tests therefore verify that a forbidden root
    entry or renamed script is absent and that a forbidden deletion leaves the
    script present. This tests the filesystem authority boundary directly
    without making this image-policy change depend on the separate applet exit
    status defect.
11. **The PID-kill systest identifies its child by PID.** Process debug names
    are limited to 32 bytes, and the standard-image test path
    `/user/tmp/motor-tests/tests/systest` is longer than that limit. The old
    search for a process whose truncated display name contained `systest`
    therefore missed the child and waited indefinitely. Looking up the PID
    returned by `std::process::Child` in `ProcessInfoV1` still verifies process
    enumeration, the parent relationship, and PID-based killing without
    depending on a diagnostic-name representation.
12. **The rebased Gears lockfiles keep the locked offline build valid.** The
    rebase changed Gears from a local crossterm patch to the Git crossterm fork,
    which removed crossterm's `ctrlc` dependency, while Gears retained its own
    direct path dependency on the `motor-os-rustc` ctrlc fork. The independent
    Gears and Gears mock-provider lockfiles retained a stale `moto-rt` edge on
    that ctrlc package even though the fork has no such dependency, causing
    `make dev.img` to reject both lockfiles in turn. Removing only those stale
    edges preserves the documented fork and the `--locked --offline` image
    build instead of weakening reproducibility or selecting a different
    dependency checkout.
13. **Systest creates its temporary directory only when it is absent.** The
    development image ships `/devtools/tmp` writable by every role while its
    `/devtools` parent remains System-owned. Unconditionally calling
    `create_dir_all` for that existing directory asks Motor FS for create
    permission on the sealed parent before it observes the child, so an
    Interactive systest receives `PermissionDenied`. Making `/devtools`
    writable would weaken the installation boundary, and changing
    `create_dir_all` semantics is outside image-policy scope. A shared systest
    helper therefore skips creation when `TMPDIR` is already a directory and
    retains creation for standalone runs that select an absent path.
14. **Lorry likewise preserves a sealed parent of an existing staging
    directory.** Lorry's atomic-output helper used `create_dir_all` on every
    staging parent, including the existing `/devtools/tmp` used for admission,
    review, and vendoring scratch. Motor FS consequently required Interactive
    create permission on `/devtools` before Lorry could create a private child
    inside the writable scratch directory. The helper now creates the parent
    only when it is not already a directory. This preserves absent custom
    staging paths, Lorry's private-child and atomic-publication behavior, and
    the System-owned `/devtools` boundary.
