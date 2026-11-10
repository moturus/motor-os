# Filesystem permissions in Motor OS images

Motor OS images are built with a declarative Motor OS filesystem permission policy. The
development image contains the complete policy surface; the base, standard,
and System-tty images contain subsets of the same destination paths and apply
the same mode to every shared entry.

This document describes permissions on newly built images. It does not define
a migration for existing images and does not impose an OS-wide W^X rule on
files created after boot.

`/system/tmp`, `/user/tmp` and `/none/tmp` are volatile memfs mounts, created
empty at each boot by `/system/cfg/sys-fs.toml`. sys-io then publishes its DHCP
snapshot under `/system/tmp`. Each root inherits
its directory's image mode; only System may change a mounted root's mode.
Tests that need Motor FS storage, or data that survives a reboot, use
`/user/test-tmp` instead. Memfs charges live data and metadata against each
mount's configured capacity. With
the default configuration the cap is guest RAM rounded down to 16 MiB, minus
16 MiB, with an 8 MiB minimum. Allocating requests return `StorageFull` below
4 MiB of actual free physical
memory, after reclaiming unused cached blocks and checking again. Reads, stat,
list, sparse resize, and delete remain allowed. A large explicit capacity does not reserve RAM.
Sparse logical length and holes do not consume data storage.

Copies between disk and memfs work normally. Renaming between them returns
`CrossesDevices` (`EXDEV` in libc); moving or deleting a mount root, or replacing
one by rename, returns `PermissionDenied`. `remove_dir_all("/none/tmp")` can
empty the mount before failing to remove its root. Prefer a private subtree
for temporary work. The native `FsClient::mounts()` API lists all mounts,
configured paths, capacities and sampled usage for every role. sys-io's
`fs.capacity_bytes` and `fs.available_bytes` metrics describe only the root
filesystem; memfs usage appears in the listing and the `fs.memfs.*` totals.

Additional Motor FS filesystems can be mounted at boot by adding entries to
`/system/cfg/sys-fs.toml`:

```toml
[[mount]]
path = "/user/data" # an existing directory
type = "motor-fs"
device = 1
partition = 2      # MBR slot 1–4; omit for a whole-device Motor FS image
# read_only = true
# cache_mb = 8     # optional LRU cache size in MiB
```

Device numbers follow the PCI scan order shown in sys-io's boot log; failed
devices keep their numbers. Partitions retain their MBR slot numbers. Omitting
`partition` requires a bare Motor FS image and does not search for an MBR.
`imager mkfs` creates such an image, and `imager mkdir` and `imager put` add
a mount target and configuration offline
([imager.md](imager.md#create-a-data-filesystem)).
Mounts are applied in file order, so a later target can be inside an earlier
mount. Motor FS preserves the mounted filesystem's stored permissions.

Root keeps its usual cache budget; additional Motor FS mounts share another
budget of the same size equally, in whole 4 KiB blocks. A positive integer
`cache_mb` overrides only that mount's share and may exceed this default budget.
Every cache must be at least 1 MiB. Invalid configuration or a missing,
malformed or repeated source aborts startup before filesystem services become
available. `findmnt` shows `virtio1p2` for a partition or `virtio1` for a
whole device.

## Permission model

Motor FS mounts may set `read_only = true` in `/system/cfg/sys-fs.toml`.
Every modifying request, including permission changes and either side of a
rename, then returns `NotAllowed` (`PermissionDenied` in std) for every role,
including System. Reads, listing, locks, copies out and execution remain
available. `findmnt` and `df` show each mount's state and sampled usage.

`[root] read_only = true` requires a writable mount at exactly `/system/logs`.
strobe reclaims old logs against that mount's capacity. The default image keeps
root writable; on a read-only root, writes such as SSH key generation and
editor configuration fail unless their destinations have writable mounts.
Opening a mount can recover a journal on writable backing before enforcing
the mount flag. VMM read-only backing requires a clean journal and an explicitly
read-only configuration; it never receives recovery writes.

Networking also requires writable `/system/tmp` for the atomic
`sys-io/dhcp.toml` snapshot. The standard memfs mount supplies this. DNS reads
`sys-net.toml` and the snapshot; it no longer creates `resolv.conf` or writes
under `/system/cfg/libc`, so that directory may live on a read-only root.

A Motor OS filesystem mode contains three permission triplets in **System, Interactive,
None** order. For example, `rw-r-----` grants System read/write, Interactive
read, and None no access. The legal triplets are `rwx`, `rw-`, `r-x`, `r--`,
and `---`. Permissions are monotonic:

```text
None ⊆ Interactive ⊆ System
```

Directory `x` controls listing, traversal, and lookup. Directory `w` controls
creation, deletion, rename, and permission changes of children. A non-writable
file can therefore still be replaced when its parent directory is writable,
unless an [executable lock](#executable-files-in-use) applies. The modes below
are the image's initial permissions; runtime changes follow the authority
rules described below.

W^X applies when constructing an image: a shipped executable ELF grants no
role write access. Directory `x` is traversal authority and does
not make directory bytes executable. Scripts are source text interpreted by an
executable and may intentionally be writable and executable in
Interactive-owned locations.

The initial image policy follows these principles:

- System owns boot services and immutable OS configuration. Image-built
  executable ELFs are read/execute-only. `/system/bin` temporarily holds
  read/execute-only copies of rush and sh for the 1.99.1-2 toolchain.
- Interactive may read and run installed programs, but cannot replace content
  in `/system`.
- `/user` and `/devtools` are Interactive-owned. Interactive may install
  programs, edit configuration, and create work there; in `/devtools` it may
  replace the installed toolchain with a newer one.
- Scripts are writable by Interactive in its trees. Compiled programs there
  remain non-writable, but Interactive may replace them.
- None may read and execute public installed content, and write its own
  `/none/cfg`, `/none/dev`, and `/none/tmp`. It can traverse `/user/cfg` and
  read explicitly shared configuration. Private files and subdirectories,
  `/user/tmp`, `/system/tmp`, and `/system/logs` remain closed to None.
- Host owner/group/other read and write bits do not map to Motor OS roles. Host
  execute bits select which files require script or ELF classification; the
  image policy supplies all three complete Motor OS permission triplets.

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
| `/system/bin` | `rwxr-xr-x` | `rw-r--r--` | `r-xr-xr-x` | `r-xr-xr-x` | Temporary rush and sh compatibility copies |
| `/system/logs` | `rwxr-x---` | `rw-r-----` | `r-xr-----` | `r-xr-----` | System strobe writes and rotates logs; Interactive may read them and None has no access |
| `/system/tmp` | `rwx------` | `rw-------` | `rwx------` | `r-x------` | System scratch |
| `/user` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | Interactive-owned programs and work, readable by None by default |
| `/user/bin` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | Editable user scripts and W^X compiled programs |
| `/user/cfg` descendants | `rwxrwx---` | `rw-rw----` | `rwxrwx---` | `r-xr-x---` | Private configuration by default; shared entries override this |
| `/user/cfg/helix` | `rwxrwxr-x` | `rwxrw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | Editor configuration shared with None |
| `/user/tmp` | `rwxrwx---` | `rw-rw----` | `rwxrwx---` | `r-xr-x---` | Interactive scratch, closed to None |
| `/none` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | The None role's home; None cannot add entries here |
| `/none/cfg` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` | None-role configuration, which None may write |
| `/none/tmp` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` | None-role scratch |
| `/devtools` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | Transitional compiler trees, compiler launchers, and test fixtures |
| `/user/dev/lorry` | `rwxrwxr-x` | `rw-rw-r--` | `rwxrwxr-x` | `r-xr-xr-x` | Interactive Lorry repository and cache, readable by None |
| `/none/dev` | `rwxrwxrwx` | `rw-rw-rw-` | `rwxrwxrwx` | `r-xr-xr-x` | Source trees and the None-role Lorry repository and cache |

An exact-entry rule gives the `/system/tmp` directory `rwxr-x---`, permitting
Interactive traversal without making its scratch files readable. sys-io creates
`/system/tmp/sys-io` with `rwxr-x---` and its atomic `dhcp.toml` snapshot with
`rw-r-----`. None cannot traverse either directory.

Before any other runtime permission changes, the directory modes have these effects:

- Interactive cannot create a new root-level tree or replace `/system`.
- Interactive can create and replace entries throughout `/user` and
  `/devtools`, except where a longer tree rule restricts access. A native
  toolchain archive's `install.sh` relies on this to replace `/devtools/llvm`
  and `/devtools/rust` ([toolchain.md](toolchain.md)).
- Each role can create and replace entries in its own temporary directory
  and in those of lower roles. None can use only `/none/tmp`. Interactive can
  traverse `/system/tmp` and read the DHCP snapshot, but cannot modify either.
- Only System can create, delete, or rename entries in `/system/logs`.
  Interactive can traverse and read regular logs but cannot alter them; None
  cannot traverse the directory. An image containing a script or ELF under
  this tree is rejected even though its fail-closed profiles are schema-valid.
  In particular, Interactive sys-tty submits raw kernel records to System
  strobe over IPC; strobe alone owns `kernel.log` and `kernel.log.prev`.

Several installed trees deliberately use the default rule:

- `/system/services` remains public read/execute. Interactive tests execute
  `/system/services/dns-resolver --self-test` and spawn None-role test children;
  the spawning role must be able to read the program file.
- Most of `/system/cfg`, including the implicit `/system/cfg/ssl` directory,
  is System-writable and publicly readable. None-role services have not yet
  been audited for configuration reads.
- Development commands live in `/user/bin/dev`, and their supporting data in
  `/user/lib`. The 1.99.1-2 compiler trees and tests temporarily stay under
  `/devtools`; Clang reads `/devtools/llvm/cfg`. `/user/dev/lorry` and `/none/dev/lorry`
  hold the Interactive and None repositories and caches of the installed
  Lorry tool; Lorry refuses to run as System. Other guest build and test
  writes belong under `/none/dev` or the role's temporary directory.
- Development source trees staged in `/none/dev` are consumed in place;
  project build output belongs under `/none/dev` and scratch output in
  the role's temporary directory. Git dependencies are fetched by the build
  tool rather than staged as separate source trees.

### Exact entries

Four credential files override their matching tree mode:

| Entry | Mode | Reason |
|---|---|---|
| `/user/cfg/sshd.toml` | `rwxrw----` | Interactive may edit the SSH PATH and host key; None cannot read the key |
| `/system/cfg/ssl/ssl-key.pem` | `rw-r-----` | The Interactive development web-server command needs the key; None does not |
| `/user/cfg/russhd/users.toml` | `rwxrw----` | SSH login names and password verifiers, which russhd refuses if None can read them |
| `/user/cfg/ssh/authorized_keys.motor` | `rwxrw----` | SSH public keys of the shipped login name |

The last two carry the mode SFTP gives a new file, so shipped and installed
credentials match. All four are supplied by `img_files/motor-os-base`, which is
included in every image. `/system/cfg/ssl` and `/user/cfg/russhd` are implicit
directories created while walking static content, so exact rules and directory
rules apply equally to implicit and explicitly listed paths.

`/user/cfg` itself is `rwxrwxr-x`, permitting None to traverse it. `rush.cfg`
and `rush.toml` are `rwxrw-r--`; optional `lorry.toml` and `rmux.toml` use
file-specific tree profiles with the same mode. Private sibling entries keep
the default configuration profile. Changing `sshd.toml`'s PATH requires a
reboot; a new console shell reads `rush.cfg` when it starts.

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
  - path: "/user/cfg/sshd.toml"
    mode: "rwxrw----"
```

Policy paths are normalized absolute image paths. Tree matching uses complete
path components, so `/user` does not match `/username`; the longest matching
tree wins, and an exact entry wins over a tree. A content overlay may replace a
source file but cannot replace the destination's permission.

The imager rejects:

- unknown policy fields, invalid or non-monotonic modes, non-normalized paths,
  and duplicate tree or exact paths;
- regular-file modes that grant execute to any role but System;
- directory profiles that do not grant System `rwx`, because the builder must
  create children in every directory it constructs;
- script profiles that do not grant System execute;
- ELF profiles that do not grant System execute or that grant write to any
  role;
- any script or ELF directly under `/system/bin` whose resolved mode is not
  exactly `r-xr-xr-x`;
- any entry under `/system` or `/user` that grants None write access, including
  explicit `imager mkdir`, `put`, and `chmod` modes;
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
Motor OS mode.

The Motor OS filesystem root and every explicit or implicit directory are created with
their resolved policy modes. Files whose final mode lets System write are
created with that final mode. Files whose final mode denies System write are
created temporarily as `rw-------`, populated, and atomically changed through
the image-administration API to their final mode before the image is flushed.
Consequently, a shipped ELF is never writable and executable at the same time
during image construction. The transition happens only in the offline,
unpublished scratch filesystem; runtime changes follow the rules below.

The builder retains the host checks for named required executables. These catch
missing or non-executable generated inputs independently of policy
classification.

## Verification and test artifact locations

Imager tests cover policy parsing and validation, rule precedence, source
classification, content overlays, the root mode, and file finalization by
building and reopening a small Motor OS filesystem image.

Guest acceptance tests check command modes in `/system/bin`, `/user/bin`,
`/user/bin/dev`, and the transitional `/devtools/bin`:

- every `/system/bin/*` compatibility entry is exactly `r-xr-xr-x`;
- every command in `/user/bin`, `/user/bin/dev`, and `/devtools/bin` is either an ELF at
  `r-xr-xr-x` or a script at `rwxrwxr-x`; and
- any regular data file or unexpected mode in those directories fails the
  suite.

With the initial image permissions, the development-image suite proves that
Interactive can edit `/user/bin/dev/www` in place and rename it, and installs
a native toolchain into `/devtools`. Functional checks prove that Interactive
cannot create a root-level directory and can write the appropriate scratch and
source trees. Tests do not walk and assert the modes of
every other image file. `test-image-layout.sh` also checks shared configuration,
private credentials, and replacement through a temporary name. Runtime-installed
executables use `rwxrwxr-x`, data uses `rwxrw-r--`, and directories use
`rwxrwxr-x`; None can read or execute them but cannot write them.

The VM harnesses share their guest directories (`src/tests/test-roots.sh`).
Test binaries are the development image's shipped `/devtools/tests`, or, on
the standard image, uploads to `/none/tmp/motor-tests/tests`, which None-role
test children can run. Interactive scratch is `/user/tmp/motor-tests` on both
images, and fixtures that a None-role child must open go in
`/none/tmp/motor-tests/tmp`. The harness creates these directories itself and
fails if one already exists, because a directory that None created would be
writable by None. Standard tests continue to assert that `/devtools` is
absent.

## Runtime behavior and remaining limits

- Each role has its own temporary directory: `/system/tmp`, `/user/tmp`, and
  `/none/tmp`. When rt.vdso starts a process, a child without `TMPDIR` gets
  its role's directory. A `TMPDIR` the parent set is kept, even for a
  lower-role child. Because std hands rt.vdso the merged environment, a value
  equal to the parent's own counts as inherited, and a lower-role child gets
  its own directory instead.
- Runtime-created regular files start `rw-` for their creator, `rwx` for
  higher roles, and `r--` for lower roles. Directories start `rwx` for the
  creator and higher roles and `r-x` for lower roles. Producers finalize
  executables with `rw-` → `r-x` after all writes succeed. A process may also
  change its own role from `r-x` → `rwx`, restoring write access. These two
  transitions and ordinary narrowing are allowed for every role, on files
  and directories whose current parent grants that role `w`. Direct
  `rw-` → `rwx` remains denied; editable executables
  can use `rw-` → `r-x` → `rwx`.
- Every runtime permission change requires `CAP_FS_WRITE` and the calling
  role's `w` on the entry's immediate parent, including narrowing, changes to
  lower roles, and unchanged-mode requests. Entry-ID operations need parent
  `w` but not `x`; pathname lookup still needs `x`. Only System may change
  `/`. A file's own `w` still permits editing its contents when its parent
  denies permission changes: a file that Interactive may write in a
  directory whose `w` it has dropped can be edited but not chmodded.
- An SFTP upload onto an existing file replaces its contents in place and
  keeps its installed mode: OPEN's mode is a creation hint. The exception is
  an upload whose mode excludes a lower role that can currently read the
  file: those roles lose access before the contents change, and under a
  protected parent such an upload is refused. `put -p` and `scp -p` install
  their mode at close and are refused before writing when the parent denies
  it. A mode request on an open upload (SETSTAT or FSETSTAT) is authorized
  immediately and removes lower-role access before further writes;
  finalization at close may remove the uploader's write access or grant access
  to lower roles. New uploads start private until close; if
  another process seals the parent before close, the final chmod fails and
  the file stays private until an authorized role can restore the parent's
  write access.
- `std::fs::copy` means contents plus mode: the destination takes the
  source's permissions, so copying needs the caller's `w` on the
  destination's parent even when the destination file itself is writable and
  already has that mode. Where the parent denies it, or the finished mode
  exceeds a higher role's byte (an executable copied onto a file that System
  holds at `rw-`), the copy is refused before truncation. Replacing such a
  file's contents in place takes an ordinary write, not a copy.
- Every change must stay within the immediately higher role's permissions;
  System has no higher role. Narrowing cascades to lower roles, while
  widening does not automatically restore their removed permissions. Thus
  `r-x` is not a permanent seal: System can make a shipped ELF writable, and a
  lower role can make an `r-x` directory writable if its ceiling is `rwx`
  and its parent grants that role `w`. Thus None cannot chmod `/user` or
  `/user/tmp`, but can chmod entries inside `/user/tmp` when their own modes
  allow the change.
- A role at `r--` or `---` still cannot widen its own permissions. The
  `std::fs::Permissions::set_readonly(true)` transition to `r--` remains
  irreversible for that role; replacing the file still requires a writable
  parent. Exact-permissions creation is available for entries that must be
  linked with their final mode.
- Runtime logs are created atomically as `rw-r-----` by System-role strobe via
  the exact-permissions API. Rotation renames the current file to `.prev`,
  preserving its mode. Authorized lower-role processes use `moto_sdk::log`;
  `CAP_LOG` admits a peer to strobe but does not grant direct filesystem
  access.
- The remaining `/system/cfg` content, including `sys-init.cfg` and
  `sys-net.toml`, remains readable by None. Narrowing those reads requires an
  audit of None-role services.
- The model has no users, ownership, groups, ACLs, sticky directories,
  symlinks, numeric Unix modes, or recursive chmod.
- Non-writable files can be replaced where their parent directory is
  writable, unless an executable lock applies. A permanent System seal
  requires `r--` or `---`, which also removes execute or directory traversal
  permission.
- Copying onto an existing writable file whose parent denies permission
  changes is refused, because the copy could not give it the source's
  permissions. Its contents can still be replaced by writing to it.

### Executable files in use

Motor OS locks an executable while loading it and while any process uses it
for demand paging. Writes, truncation, deletion, renaming, replacement by
renaming another file onto it, permission changes (`chmod`), and
`copy_file_range` into it fail with `E_NOT_ALLOWED`. This applies even when
file and directory permissions would otherwise allow the operation.

The lock lasts until the last process using those mappings exits or is
killed. It no longer blocks file operations once that exit is visible.
A daemon can therefore keep its executable locked for its whole lifetime.

Files smaller than 1 MiB are loaded completely during spawn. They keep no
executable lock after the child is created. The same is true of any larger
image that the loader loads completely.

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
6. **Git dependency source trees are not staged separately.** Development
   projects fetch their reviewed Git dependencies through the build tool.
   Cargo writes project targets below `/none/dev` and uses the role's
   temporary directory for scratch.
7. **Standard test binaries live under `/none/tmp`, not a newly created
   `/devtools`.** Making `/` Interactive-writable solely to preserve the old
   upload path would also permit replacement of `/system`. The binaries must
   be reachable by None-role children, and `/user/tmp` is closed to None.
8. **Guest mode enumeration is restricted to `/*/bin/*`.** Policy unit tests
   validate all configured modes and image construction validates every
   resolved entry. Guest tests concentrate on executable installation
   boundaries and functional access checks, avoiding a brittle duplicate of
   the complete image manifest.
9. **`rmux` creates `$TMPDIR` only when it is absent.** On Motor OS, rmux's
   client and server meet over the SDK's IPC (`moto_sdk::ipc`) and need no port file. The client
   still creates a caller-selected, absent `TMPDIR` before it starts a server,
   because panes inherit it and Rush stages pipelines there. Blindly calling
   `create_dir_all` on an existing directory first asks the Motor OS filesystem
   to create it, and the filesystem checks write access to the parent before
   detecting the existing child, so a role that may not write the parent is refused.
   Testing whether the directory exists first avoids that request.
10. **Denial acceptance tests assert filesystem postconditions.** During
    implementation, the sysbox `mkdir` and `mv` applets printed a permission
    diagnostic but returned success; `rm` already returned failure correctly.
    `mkdir`, `mv`, and the applet with the same defect, `rmdir`, now return
    failure when their filesystem operation fails. The tests assert both the
    command status and the resulting filesystem state: a forbidden root entry
    or renamed script remains absent, while a forbidden directory or script
    deletion leaves its target present. The postcondition checks remain as
    direct verification of the filesystem authority boundary.
11. **The PID-kill systest identifies its child by PID.** Process debug names
    are limited to 32 bytes, and the standard-image test path
    `/none/tmp/motor-tests/tests/systest` is longer than that limit. The old
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
13. **Systest creates its temporary directory only when it is absent.** A
    role's temporary directory can be writable while its parent is not, as
    with `/none/tmp` for None. Unconditionally calling
    `create_dir_all` for that existing directory asks the Motor OS filesystem
    for create permission on the non-writable parent before it observes the child, so
    the systest receives `PermissionDenied`. Making the parent writable
    would broaden the image policy, and changing
    `create_dir_all` semantics is outside image-policy scope. A shared systest
    helper therefore skips creation when `TMPDIR` is already a directory and
    retains creation for standalone runs that select an absent path.
14. **Lorry likewise preserves a non-writable parent of an existing staging
    directory.** Lorry's atomic-output helper used `create_dir_all` on every
    staging parent, including an existing temporary directory used for
    admission, review, and vendoring scratch. The Motor OS filesystem consequently
    required create permission on that directory's parent before Lorry could create a
    private child inside it. The helper now creates the parent only when it is
    not already a directory. This preserves absent custom staging paths,
    Lorry's private-child and atomic-publication behavior, and the image's
    parent-directory permissions.
