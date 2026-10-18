# Multiple filesystems in sys-io

Status: **design under review, fifth pass** (2026-10-18). The answers to
Q1 to Q13 are folded in as decisions 1 to 16 below and into the
requirements and design; requirements are settled except where marked
**(proposed)**. Design items still marked (proposed) await review. No
code has changed in this effort; motor-fs commit `4527c75b` (generation
advances only on a new directory entry) landed independently and is
reflected below.

Changes in this revision, for a reviewer who read the previous one:
decision 1 rewritten and decision 16 added: the mount id is a 24-bit
per-boot counter carried in two fragments of the entry id and looked up
by a linear search of the mount vector, replacing the index-plus-epoch
scheme; Motor FS gains a 2^48 generation limit beside the 2^56 block
limit and reports either as `StorageFull`; D1, D2, D14, R1.7, R2.3, R3.4,
R6.2 and plan step 4 follow; Q13 is closed.

Decisions so far:

1. **Entry-id scheme.** Motor FS entry ids are used as-is today, with
   two bytes-worth of headroom reserved: Motor FS is limited to 2^56
   blocks and 2^48 generations, so the top byte of the block-number word
   and the top two bytes of the generation word are always zero on disk.
   sys-io carries a 24-bit **mount id** in those 24 bits. The mount id is
   a per-boot counter that never repeats: it fills the 16 generation-word
   bits first and spills into the block-number byte only past 65,535
   mounts. The mount table is a vector of mounts searched by id; the root
   filesystem has id 0 and is first. See D1 and D2.
2. **First use case is `/none/tmp`**, the None role's temporary directory,
   which every image already creates. memfs is mounted over it and the root
   filesystem's `/none/tmp` is shadowed. `/user/tmp` stays on the root
   filesystem; the tests, scripts and tools that use it are out of scope.
3. **Configuration is the file only.** Iteration 1 has no runtime `mount`
   command. Mounts come from `/system/cfg/sys-fs.toml` in the
   one-TOML-table-per-mount notation of D8 (Q1).
4. **The config and the shadow marker ship in `img_files/motor-os-base`**,
   which every image layers (Q2).
5. **No capacity cap by default.** `max_size` stays an optional per-mount
   setting with its own memfs tests; an uncapped memfs is bounded by guest
   memory, and sys-io declines memfs operations that allocate while the
   kernel reports memory pressure (Q3, D13).
6. **Cross-mount rename gets a new error code**, a `moto_rt::Error`
   variant mapped to `std::io::ErrorKind::CrossesDevices`, and `sysbox mv`
   falls back to copy-plus-delete on it (Q4). This touches `moto-rt`, the
   std port and the mlibc port in the toolchain tree (D11).
7. **Executables in memfs** are locked while they back a running process
   exactly as root-filesystem executables are, and the demand pager copies
   their bytes on each fault as it does today. Sharing memfs pages with the
   process is a later consideration, not designed here (Q5, D4).
8. **Boot failures fail closed**: a malformed config or a mount that cannot
   be applied panics sys-io with a clear log line (Q6, D9).
9. **`CMD_GET_MOUNTS` and `sysbox mount` are in iteration 1** (Q7, D10).
10. **Roadmap kept open**: a second block device, multiple Motor FS
    partitions per block device, and virtio-fs mounts are later iterations
    and must not be precluded (Q8, D14).
11. **Test gate** as R9.3 (Q9).
12. **A 16 MiB reserve.** Allocating memfs operations are refused with
    `StorageFull` when the guest's free-for-admission memory is below
    16 MiB, checked once per such request (Q10, D13).
13. **The error code lands first.** `moto-rt` gets `CrossesDevices`, the
    crate is published, the Rust and mlibc forks map it, and the rebuilt
    toolchain is selected before any sys-io patch, so the implementation
    uses the final code from the start (Q11; plan steps 1 and 2).
14. **`sysbox mv` falls back for files and directories** (Q12, D11).
15. **Runtime mount and unmount commands are planned** for a later
    iteration. Iteration 1 stays boot-only (decision 3) but its structures
    must take mount and unmount without redesign (R1.7, D14).
16. **Limits are reported as "filesystem full".** Motor FS returns
    `StorageFull` when a block number or a generation would reach its
    limit (2^56 blocks, 2^48 generations); the same code is what a later
    mount command returns when the 24-bit mount counter would run out
    (Q13, D1, D14).

Workflow for this document: iterate on requirements first, then on the
design, then on the implementation plan. Each phase is reviewed before the
next one starts.

## Background: what exists today

Facts the requirements and design build on. File references are anchors,
not line numbers.

### sys-io and the filesystem stack

- sys-io serves exactly one filesystem, mounted at `/`. `runtime::fs::FS`
  (`src/sys/sys-io/src/runtime/fs.rs`) is an enum with one variant,
  `MotorFs` over a `VirtioPartition`. `fs::init` reads the MBR of the single
  virtio-blk device, skips FlatFs and SrFs partitions with a warning, panics
  on a second MotorFs partition, and panics when none is found.
  `runtime/mod.rs` asserts that there is at most one block device.
- The client protocol (`src/sys/lib/moto-sys-io/src/api_fs.rs`) is
  entry-id based. `EntryId` is an opaque `u128`; `ROOT_ID` is 0 at the
  protocol level and motor-fs maps it to its on-disk root. `CMD_STAT_PATH`
  walks a whole absolute path server-side in one round trip; every other
  command takes entry ids (`CMD_CREATE_*` take a parent id, `CMD_MOVE_*` take
  an entry id and a new parent id, `CMD_COPY_FILE_RANGE` takes two file ids,
  `CMD_SPAWN` takes the executable's entry id). `CMD_FLUSH` has no target: it
  flushes "the" filesystem. Commands are numbered 1 to 21;
  `is_read_command` lists the ones served without `CAP_FS_WRITE`. The
  request decoders for `CMD_RESIZE` and `CMD_DELETE_ENTRY` are infallible
  and allocation-free.
- motor-fs builds an entry id from `EntryIdInternal { block_no: u64,
  generation: u64 }` (`layout.rs`, `repr(C)`), transmuted to the `u128`. The
  block number is the first eight bytes, which on x86-64 are bits 0..63 of
  the `u128`; the never-reused generation is bits 64..127. motor-fs
  validates a client-supplied id against the on-disk entry (in use, and the
  generation matches), so a stale or forged id is refused.
- Clients (`rt.vdso/src/rt_fs.rs` over `moto-io`) canonicalize paths
  lexically, including `..`, keep the cwd as a string, and never call
  `get_parent`. A rename resolves the source entry and the destination
  parent, then issues one move. `std::fs::copy` resolves both files and
  loops over `copy_file_range` in 64 KiB chunks; there is no read/write
  fallback. `FileAttr.entry_id` is exposed to programs as the file's unique
  identity.
- Permission enforcement (`r`/`w`/directory `x` per role) lives inside
  motor-fs: `require_access` loads the entry and calls the pure
  `check_access(metadata, role, need)`; the authority rules for changing a
  mode (`may_set`, `perms_monotonic`) already live in `async-fs` and are
  called from motor-fs's transactions. sys-io derives the role from the
  connection peer's capabilities and passes it down; `CAP_FS_WRITE` gates
  every mutating command in sys-io itself. Default modes for new entries
  are computed in sys-io, so they are the same for every filesystem it
  serves.
- State keyed by entry id inside sys-io: the file lock manager, the
  executable locks (`spawn::ExecLocks`, consulted by `refuse_if_executing`
  before write, resize, delete, move, replace and permission changes), and
  the demand pager's mappings. All of it assumes entry ids are unique.
- The demand pager (`runtime/fs/spawn/pager.rs`) serves a fault by
  allocating a page-aligned buffer, reading the executable's bytes into it
  block by block through the `FS` object (`read_range` / `read_exact_at`),
  applying relocations to the buffer, and handing the buffer to the kernel
  with `SysMem::pager_fill`. The process therefore gets its own copy of
  every page; nothing is shared with the filesystem's memory.
- One `LocalRwLock<FS>` serializes every writer, including block I/O waits.
- sys-io's own filesystem users bypass the client protocol and call the `FS`
  object directly: the net config loader (`/system/cfg/sys-net.toml`), the
  `resolv.conf` writer, the spawn path and the pager, and the stats
  responder, which publishes `FS_CAPACITY_BYTES` / `FS_AVAILABLE_BYTES` from
  `num_blocks` / `empty_blocks`.
- Config loading pattern: `sys-net.toml` is read at boot with direct `FS`
  calls (never `std::fs`), block by block, with a 64 KiB size cap; a missing
  or malformed file makes `net::init` fail and sys-io panic.
- Memory pressure: the kernel raises the `memory_pressure` flag on its
  shared static page when free-for-admission memory is at or below
  `PRESSURE_LOW_PAGES` (512 pages, 2 MiB) and clears it at
  `PRESSURE_HIGH_PAGES` (768 pages, 3 MiB) (`kernel/src/mm/admission.rs`).
  `moto_sys::memory_pressure()` reads the flag without a syscall;
  `moto_sys::stats::AdmissionStats::get()` is one syscall and its
  `free_for_admission()` is the number the kernel compares against its
  floors. While the flag is up, sys-io refuses new clients and every known
  FS command except `CMD_FILE_LOCK`/`UNLOCK` with
  `moto_rt::Error::OutOfMemory` (`served_under_pressure`); the stated
  reason is that any other command can grow sys-io, and sys-io dies if the
  kernel refuses that growth. sys-io's block cache is sized from guest RAM,
  1 MiB per 32 MiB. sys-io has a debug-build self-test facility
  (`crate::self_test`).
- Process memory: every Motor OS process, sys-io included, allocates
  through rt.vdso's `frusa::Frusa4K` (`rt.vdso/src/rt_alloc.rs`,
  `src/sys/lib/frusa`). Allocations up to 4 KiB come from size-class slabs
  whose batches are requested from the kernel with `SysMem::alloc` and grow
  from one page to 8 and then 64 pages as a class grows; larger allocations
  go to `SysMem::alloc` directly and `SysMem::free` returns them at once.
  Slab memory goes back to the kernel only when a whole batch is free and
  `reclaim()` runs, which a housekeeping task does every 5 seconds when the
  slack exceeds 1 MiB, or for any slack under memory pressure. A 4 KiB
  block freed through the global allocator therefore stays resident until
  its batch (up to 256 KiB) is entirely free. `SysMem::alloc(PAGE_4K, 1)`
  maps one readable, writable page the kernel admits immediately, and
  `SysMem::free` unmaps it.
- Error codes: `moto_rt::Error` is a `repr(u16)` enum whose last code is
  `PageAbsent = 23` (`moto-rt/src/error.rs`). Three places map the codes:
  the Rust std port, `library/std/src/sys/io/error/motor.rs` in
  `../toolchain-src/rust` (unknown codes become `ErrorKind::Uncategorized`);
  the mlibc port, `sysdeps/motor/include/mlibc/motor-util.hpp` in
  `../toolchain-src/mlibc` (`StorageFull` is `ENOSPC` there); and
  `moto-rt` itself. The toolchain is built from upstream Rust 1.99, so
  `ErrorKind::CrossesDevices` exists.
- How a moto-rt change reaches std (`docs/toolchain.md` §5,
  `docs/build-rustc.md`): Rust std depends on the published crates.io
  `moto-rt` (`version = "0.17"`), pinned by the Rust fork's
  `library/Cargo.lock`, never on a path into this checkout. The tuple that
  identifies a toolchain is `src/toolchain-versions.sh` (fork commits,
  lockfile hashes, lineage id); `src/build-motor-os.sh` builds it, derives
  the toolchain key from what it compiled, and prints the rustup name
  `motor-<lineage>-<key>`, which is what `rust-toolchain.toml`'s `channel`
  holds. Only the commits, the id and the rustup base change the key. The
  procedure for a new `moto-rt`: publish the crate; select it in the
  fork's `library/Cargo.lock` and commit that on the fork branch (together
  with any std change); push, since nothing is built from an unpushed
  commit; edit `MOTOR_RUST_REV` and `MOTOR_RUST_LIBRARY_LOCK_SHA256`
  (and `MOTOR_MLIBC_REV` for an mlibc change); run `src/build-motor-os.sh`;
  put the printed name into `rust-toolchain.toml`; run the core gate; commit
  the declaration, the selector and the docs together. Commits `57b5e6ea`,
  `0d731dca` and `d7917225` are the last instance of this: the moto-rt bump
  with `src/sys/Cargo.lock`, a refresh of about eighteen `Cargo.lock` files
  under `src/bin`, `src/imager` and `src/tests`, then the toolchain
  declaration, selector and docs. The local `moto-rt` may run ahead of
  std's within one major version, so a new variant compiles in this
  repository before the toolchain is rebuilt; std just reports it as
  `Uncategorized` until then.
- sysbox (`src/sys/tools/sysbox`) hosts the coreutils-style commands.
  `cp` has `-r` with `copy_directory` / `copy_file` helpers over
  `std::fs::copy`; `mv` is a thin wrapper around `std::fs::rename` and
  reports any error. There is no `mount` command; rush's only filesystem
  builtins are `cd` and `pwd`.

### `/none/tmp` today

- It is the None role's temporary directory (`docs/fs-permissions.md`):
  rt.vdso's `role_temp_dir` (`rt_process.rs`) gives a None-role child
  `TMPDIR=/none/tmp`, and Lorry's `Role::None.temp_directory()` is the same
  path. `/system/tmp` and `/user/tmp` play the same role for System and
  Interactive; `/user/tmp` is `rwxrwx---`, closed to None, and stays on the
  root filesystem (decision 2).
- Every image creates it. All six image YAMLs (`motor-os-base`, `motor-os`,
  `motor-os-dev`, `motor-os-wasm`, `motor-os-system-tty`,
  `motor-os-vsock-test`) list `/none`, `/none/cfg` and `/none/tmp` under
  `directories`, and the imager's unit test asserts that the developer image
  lists it. All six layer `img_files/motor-os-base` as their first
  `static_dirs` entry. No image ships a file inside `/none/tmp`.
- Policy (`src/imager/motor-os-permissions.yaml`): `/none` is `rwxrwxr-x`,
  so None cannot add entries to it; `/none/tmp` is `rwxrwxrwx` for
  directories, `rw-rw-rw-` for files, `rwxrwxrwx` for scripts and
  `r-xr-xr-x` for ELF executables. Runtime-created entries get sys-io's
  default modes (an Interactive-created directory is `rwxrwxr-x`, a file
  `rwxrw-r--`), which the harness relies on: a directory None created first
  would be writable by None.
- Runtime users:
  - `src/tests/test-roots.sh`, sourced by `full-test.sh`. On the standard
    image `MOTOR_TEST_ROOT=/none/tmp/motor-tests`; the harness creates
    `/none/tmp/motor-tests`, `.../tests` and `.../tmp` over sftp (failing
    if one exists), uploads `systest`, `mio-test`, `tokio-tests`,
    `crossterm-smoke` and `rmux-probe` into `.../tests`, and runs them from
    there for the rest of the test. `.../tmp` holds fixtures that a
    None-role child must open. The developer-image run uses `/devtools`
    instead. `remove_test_roots` deletes an earlier run's leftovers.
  - `src/tests/test-system-tty.sh`, run by `full-test.sh` in its own VM:
    copies `systest` to `/none/tmp/admission-systest` and
    `/none/tmp/mmio-systest`, runs `chmod r-xr-xr-x` on one, and executes
    both from the System console with reserve capabilities.
  - `systest`: `none_temp_path` creates a per-run directory in `/none/tmp`
    for the role permission tests, which check the default modes of created
    directories and files, `set_readonly` and `set_permissions`.
    `temp_dir.rs` asserts the `TMPDIR` string only.
  - `src/tests/test-wasm.sh`, run by `full-test-dev.sh` in 224 and 256 MiB
    guests: the wasm and javy smoke suites use `/none/tmp/<name>-<pid>` as
    scratch and `/none/tmp/javy-tests` for inputs, all small files.
  - Lorry uses it as the None-role temporary directory. Its production
    code never renames out of it: the atomic writer stages beside the
    destination, and every `temp_dir()` use is a test fixture. russhd's
    sftp `put` writes the destination in place.
  - Nothing at boot touches `/none/tmp`, and no test or tool relies on its
    contents surviving a reboot.
- `docs/fs-permissions.md` items 7, 11 and 13 record why the test binaries
  live there (None-role children must be able to run them) and that
  `create_dir_all` on the existing `/none/tmp` by None is refused at the
  parent's `w` check, so systest and rmux skip creation when the directory
  exists.
- Data written into `/none/tmp` by the gate, per VM:

  | Build | Standard image, five test binaries | System-tty image, two `systest` copies |
  |---|---|---|
  | release | 9.2 MB | 9.4 MB |
  | debug | 29.9 MB | 16.9 MB |

  The default test guest has 1024 MiB; `--memory 256` is the small shape
  the harness supports.

## Requirements

Items marked **(stated)** come from the task as given, **(decided)** from
the review so far, **(proposed)** are inferred from the code and the
project guidelines and need confirmation. The open questions at the bottom
collect the uncertainties.

### R1. Scope

- R1.1 **(stated)** sys-io serves more than one filesystem at a time. The
  filesystem on the data partition stays mounted at `/`; additional
  filesystems are mounted at directories below it.
- R1.2 **(stated)** The mount table is driven by `/system/cfg/sys-fs.toml`,
  a new file. Without it, behavior is exactly today's: the root filesystem
  only.
- R1.3 **(decided)** First use case: mount an in-memory filesystem
  (`memfs`, to be created) at `/none/tmp`, completely hiding the
  `/none/tmp` directory of the root filesystem. In mount-command terms:
  `mount -t memfs /none/tmp`.
- R1.4 **(decided)** Iteration 1 applies mounts at boot from the config
  only. No runtime mount or unmount, and no client command can change the
  mount table.
- R1.5 **(decided)** The mount mechanism is not memfs-specific. Later
  iterations will add a second block device, multiple Motor FS partitions
  per block device, virtio-fs mounts, and runtime mount and unmount
  commands; iteration 1 implements only boot-time memfs mounts but must
  not preclude those (D14).
- R1.6 **(decided)** No kernel changes. The work lives in sys-io, a new
  memfs library crate under `src/sys/lib`, small additions to `async-fs`,
  `motor-fs`, `moto-sys-io`, `moto-io` and sysbox, plus the error-code
  change of decision 6 in `moto-rt`, the std port and the mlibc port. The
  changes outside this repository are called out explicitly in D11 and in
  the implementation plan (AGENTS.md notes 3 and 4).
- R1.7 **(proposed)** Unmount-readiness. Because unmount is planned
  (decision 15), iteration 1 must already satisfy: a mount can disappear
  while clients hold its entry ids, and every such id then fails closed
  with `InvalidArgument`, never reaching another filesystem; the mount
  table can change after boot without touching the request handlers;
  everything sys-io keeps per entry (file locks, executable locks, pager
  mappings) can be found by mount id, so "is this mount busy" is
  answerable; the config validator and the mount step are callable for a
  single new entry against the live table, not only for a whole file at
  boot; and a mount id is never reused within a boot (D1). D14 states
  what each of these costs now, which is close to nothing.

### R2. Configuration

- R2.1 **(decided)** TOML, one `[[mount]]` table per mount (D8), parsed
  with the `toml` and `serde` crates sys-io already uses for
  `sys-net.toml`, read at boot with direct `FS` calls, size-capped.
- R2.2 **(decided)** Each mount entry names the mount point (an absolute,
  canonical path) and the filesystem type. memfs entries may set a capacity
  cap and a root mode. The schema is D8.
- R2.3 **(decided)** The file is validated as a whole before any mount is
  applied: unknown types or keys, duplicate mount points, non-absolute or
  non-canonical paths, a mount point at `/` or inside another mount, and
  more than 255 entries (a policy cap, not an id-space limit) are errors.
  A malformed file, or a mount that
  fails to apply, panics sys-io with a log line naming the entry (decision
  8, D9).
- R2.4 A missing `/system/cfg/sys-fs.toml` is not an error and costs one
  failed lookup in `/system/cfg` at boot.
- R2.5 **(decided)** `img_files/motor-os-base/system/cfg/sys-fs.toml`
  mounts memfs at `/none/tmp` in every image. The directory exists in every
  image already, so no image YAML or policy entry changes.

### R3. Namespace semantics

- R3.1 **(stated)** A mount completely shadows the mount point directory
  of the parent filesystem: its contents are unreachable by any path and
  any entry id while the mount is active. The shadowed directory's entries
  stay on disk, unchanged.
- R3.2 **(proposed)** The mount point must exist on the parent filesystem
  and be a directory. sys-io does not synthesize mount points. For
  `/none/tmp` this holds in every image.
- R3.3 Every way of reaching the mount point resolves to the mounted
  filesystem's root: a path walk (`CMD_STAT_PATH`), a single-component
  lookup in the parent (`CMD_STAT`), and enumeration of the parent
  directory (`CMD_GET_FIRST_ENTRY` / `CMD_GET_NEXT_ENTRY` followed by
  `CMD_METADATA` / `CMD_GET_NAME`). A program must not be able to observe
  two identities or two metadata records for `/none/tmp` depending on how
  it got there. Design: D3.
- R3.4 **(decided)** Entry ids are unique across all mounted filesystems:
  the mount id lives in the id (D1). `FileAttr.entry_id` keeps meaning
  "this file", and the lock manager, executable locks and pager stay
  correct without per-mount special cases. An id whose mount id names
  no mounted filesystem is rejected; an id cannot address one filesystem's
  entry through another's id space. Root-filesystem ids are bit-identical
  to today's.
- R3.5 Operations that span two filesystems:
  - **(decided)** Rename or move across mounts is refused with
    `moto_rt::Error::CrossesDevices`, which std reports as
    `ErrorKind::CrossesDevices` and libc as `EXDEV`. It is never emulated
    inside sys-io as copy-plus-delete; `sysbox mv` performs the fallback
    for files and directories (D11).
  - Copy across mounts works: `cp /user/tmp/x /none/tmp/x` and
    `std::fs::copy` into or out of `/none/tmp` are everyday operations.
    The data path lives in sys-io (D5).
  - Deleting, renaming or moving the mount point directory itself, or
    replacing it via a rename onto it, is refused while the mount is
    active.
  - `CMD_FLUSH` flushes every mounted filesystem that has anything to
    flush; memfs has nothing.
- R3.6 Lexical `..` handling in clients is unchanged: no server-side parent
  traversal crosses a mount boundary, because none exists today.
- R3.7 sys-io's internal users that take client-supplied ids (spawn, the
  pager, the lock manager, stats) go through the mount table. The net
  config loader and the `resolv.conf` writer keep addressing the root
  filesystem directly: `/system/cfg` is image content and must not be
  redirectable by a mount.
- R3.8 Operations on the parent directory that name the mount point behave
  as they do today, because the shadowed directory is still on disk and
  the parent's checks are the parent filesystem's: creating `tmp` in
  `/none` is refused for None at the parent's `w` check and returns
  "already exists" for a role that may write `/none`. `create_dir_all` on
  `/none/tmp` therefore keeps the behavior `docs/fs-permissions.md` item
  13 describes.

### R4. memfs

- R4.1 A new library crate implementing `async_fs::FileSystem`, in the
  spirit of motor-fs: files, directories, rename, resize,
  `copy_file_range`, timestamps, per-role permissions and permission
  changes, the same filename validation rules.
- R4.2 Contents live in sys-io's memory only and are lost at shutdown or
  reboot. `flush` and `fsync` are no-ops that succeed.
- R4.3 Permission semantics are identical to motor-fs's, as specified in
  `src/sys/lib/motor-fs/PERMISSIONS_DESIGN.md`: the same five access
  values, the same role authority rules, the same enforcement points,
  including directory `x` for traversal and listing and `w` on the parent
  for creation, deletion, rename and permission changes. The enforcement
  code is shared, not re-implemented (D7); divergence between the two
  filesystems is a security bug. systest's role permission tests run
  against `/none/tmp` and so become memfs acceptance tests the day the
  mount ships.
- R4.4 The root of a memfs mount carries explicit permissions. By default
  they are those of the shadowed directory at mount time, `rwxrwxrwx` for
  `/none/tmp`; the config may override them. A mount never widens access
  relative to the shadowed directory unless the config says so explicitly.
- R4.5 **(decided)** Capacity. A memfs mount may carry a cap, `max_size`,
  enforced by memfs itself: a request that would take the mount past the
  cap fails with `StorageFull` before anything is allocated or changed, and
  metadata and names count. There is no cap by default: an uncapped memfs
  is bounded by guest memory, and the controls are the 16 MiB reserve and
  the memory-pressure handling of D13, under which sys-io refuses every
  memfs operation that can allocate with `StorageFull`. memfs allocation
  is fallible, so a page the kernel refuses is an error to the client,
  never an abort of sys-io. Memory freed by deleting or shrinking memfs
  entries returns to the kernel at once (D7). The cap is covered by memfs
  host tests (R9.1); the shipped config sets none.
- R4.6 **(decided)** Executables stored in memfs can be spawned and
  demand-paged like executables on the root filesystem. sys-io locks a
  memfs file that backs a construction or a running process exactly as it
  locks a Motor FS file (the same `ExecLocks`, keyed by the exported id),
  and the pager copies bytes out of memfs on every fault as it copies them
  out of the block cache today. A memfs file can be made executable with
  `chmod`. The standard-image gate uploads its test binaries into
  `/none/tmp` and runs them from there, so this is a day-one requirement.
  Sharing memfs blocks with the process instead of copying is a later
  consideration (D4).
- R4.7 File locking (`CMD_FILE_LOCK`) works on memfs files without
  changes: the lock manager is in sys-io and keyed by entry id.
- R4.8 With a cap, `num_blocks` / `empty_blocks` report the cap and the
  remaining capacity in 4 KiB blocks. Without one they report zero, the
  convention tmpfs uses for an unlimited mount, and the mount listing
  (D10) prints the bytes in use and `unlimited`.
- R4.9 memfs honors the `FileSystem` trait's block-bounded read and write
  contract that clients already chunk for; it may also serve cross-block
  requests, but nothing may depend on it.
- R4.10 Rust-first, std only plus `src/sys/lib` crates; no new external
  dependencies beyond what sys-io already pulls.

### R5. Security

- R5.1 Mounting is a System-level, image-controlled operation. `/system/cfg`
  is System-writable only, so Interactive and None cannot alter the mount
  table.
- R5.2 All inputs that cross the client boundary (entry ids, paths, names,
  offsets, lengths) are validated per mount exactly as they are today for
  motor-fs. A crafted entry id fails closed (R3.4, D1).
- R5.3 The role model is preserved end to end: the role comes from the
  connection's kernel-reported capabilities, `CAP_FS_WRITE` still gates
  mutations in sys-io before dispatch, and every mounted filesystem
  enforces per-role permissions (R4.3).
- R5.4 Resource bounds on everything a client can grow: name and path
  lengths (existing `MAX_PATH_LEN`, `MAX_FILENAME_LEN`), the cross-mount
  copy bounce buffer (D5), the config file size, and, for memfs, the
  optional cap or else the reserve and the memory-pressure handling of
  D13.
- R5.5 `/none/tmp` keeps its `rwxrwxrwx` policy mode as the memfs root
  mode (R4.4), and None still cannot add entries to `/none` (R3.8). The
  permission tests in `full-test.sh` keep passing unchanged; in particular
  the harness's rule that it creates the test directories first, so that
  None cannot write them, relies on sys-io's default modes being the same
  on memfs.
- R5.6 **(decided)** Memory as the shared resource. With no cap, any
  process that may write `/none/tmp`, including a None-role one, can grow
  memfs until the guest's free-for-admission memory falls to the 16 MiB
  reserve; from then on every allocating memfs request fails with
  `StorageFull` while the rest of the system, with 16 MiB to work with,
  keeps running, and the kernel's own pressure flag at 2 MiB stays a
  backstop for memory consumed by others. Today the same process can only
  fill the 256 MB data partition. memfs memory is reclaimed by deleting or
  shrinking its entries, which work under pressure (D13) and return pages
  to the kernel immediately (D7), or by rebooting; a process exiting frees
  its own pages but nothing in memfs. sys-io never aborts because of memfs
  (R4.5).

### R6. Performance and boot time

- R6.1 Boot-time cost of the feature with no `sys-fs.toml` present is one
  directory lookup. With the shipped config it is reading one small file
  plus creating an empty memfs: no device I/O beyond the config read, no
  new threads, nothing proportional to RAM size.
- R6.2 Dispatch adds no measurable per-request cost on the root filesystem
  path: extracting the mount id, a `RefCell` borrow of the mount table (a
  non-atomic counter, D2), a linear search of the mount vector (the root
  is first, so one comparison), and a comparison against each mount's
  shadowed id (one per mount); no allocation.
- R6.3 memfs requests do not wait behind root-filesystem block I/O: the
  lock is per mount (D6).
- R6.4 memfs data path cost is a memcpy per 4 KiB chunk plus bookkeeping;
  no block cache, no transaction log. An allocating memfs request
  additionally costs one `AdmissionStats` syscall for the reserve check
  (D13) and one page-mapping syscall per newly allocated 4 KiB block (D7),
  so a 32 KiB sequential write costs at most nine syscalls on top of the
  IPC it already costs. Rewrites of allocated blocks cost none.
- R6.5 Memory shift: data the gate writes into `/none/tmp` now lives in
  RAM instead of on disk, about 30 MB for a debug run (Background table).
  Negligible in the default 1024 MiB guest; about 12% of a 256 MiB guest.
  A running memfs executable costs its size twice, once in memfs and once
  in the process's pages (D4).

### R7. Observability

- R7.1 **(decided)** The active mount table is visible from a shell:
  `sysbox mount` with no arguments prints the read-only listing of D10.
- R7.2 `FS_CAPACITY_BYTES` / `FS_AVAILABLE_BYTES` keep describing the data
  partition and are documented as such; the listing shows each mount's
  bytes in use and its cap or `unlimited`, so a disk budget and a RAM
  budget are never mixed.
- R7.3 Boot logs name each applied mount and each rejected config entry.

### R8. Compatibility and non-goals

- R8.1 No compatibility machinery: as with process roles, new code ships
  with a complete new image. Protocol changes need no versioning.
- R8.2 Non-goals for iteration 1: nested mounts (a mount point inside
  another mount), bind mounts, read-only mounts, persistence of memfs
  contents, quotas per role within a memfs, mounting over `/user/tmp` or
  `/system/tmp`. Runtime mount and unmount, a second block device,
  multiple Motor FS partitions per device and virtio-fs are later
  iterations, not non-goals (R1.5, D14).
- R8.3 **(decided)** Existing tests, scripts and tools that use
  `/user/tmp` are untouched.
- R8.4 Existing users of `/none/tmp` (the test harness, systest, the wasm
  and javy suites, Lorry, None-role `TMPDIR` consumers) keep working
  without changes. The observable differences are that `/none/tmp` is
  empty after every boot, that it is bounded by memory rather than by the
  data partition, and that a rename between it and the rest of the tree
  now fails with `CrossesDevices`; `docs/fs-permissions.md` gets a
  sentence saying so.

### R9. Testing

- R9.1 memfs gets host-run unit tests in its own crate, like motor-fs's
  `tests.rs`: it is library code, not kernel code, so host tests are
  appropriate. They cover `max_size` (enforcement, atomicity of a refused
  request, the `resize` charge, accounting of metadata and names) even
  though the shipped config sets no cap, and the block store's accounting
  of allocated and freed pages (D7).
- R9.2 In-VM integration tests in `src/tests/full-test.sh` (directly or via
  `systest`): after boot `/none/tmp` is served by mount 1 (its
  `FileAttr.entry_id` carries mount id 1 while `/none`'s carries 0, and
  `sysbox mount` lists it as memfs, unlimited) and is empty; shadowing (the
  marker file shipped in the image's `/none/tmp` is invisible by path and
  by enumeration); None can create and list entries in `/none/tmp` and
  still cannot create in `/none`; cross-mount copy between `/user/tmp` and
  `/none/tmp` works in both directions; `std::fs::rename` across the
  boundary fails with `ErrorKind::CrossesDevices` and `sysbox mv` across
  it succeeds, for a file and for a directory; file locks work on memfs;
  `rmdir /none/tmp` and `mv /none/tmp /none/x` are refused and leave the
  contents intact; `remove_dir_all` on a subtree of `/none/tmp` works; and
  a memfs file that is written, then deleted, leaves the guest's
  free-for-admission memory where it was before the write, within the
  noise of the test process itself (D7's "returned at once"). Spawning
  from memfs, `chmod` on memfs files and the role permission matrix are
  already exercised by the existing gate the moment the mount ships
  (Background). The config validator's error cases and the missing-file
  path are covered by sys-io's debug self-test, since no shipped image
  lacks the file. The reserve and pressure logic of D13 is covered by the
  self-test as a pure decision over (free pages, command, mount kind); no
  in-VM test drives the guest to the reserve.
- R9.3 **(decided)** This is core OS work (`src/sys`): `src/tests/full-test.sh`
  must pass consistently in debug and release, at least three times each,
  before each patch is committed. The patch that ships the config also runs
  `src/tests/full-test-dev.sh --release` once, because the developer and
  wasm images layer the same base tree. The toolchain step (plan step 2)
  is gated as `docs/toolchain.md` §5 prescribes: the same three debug and
  three release runs plus one release developer-image run, on the new
  toolchain, before its declaration and selector are committed. Patches
  are kept to 100-300 lines including tests.
- R9.4 No new compiler or clippy warnings; `cargo fmt` from the repository
  toolchain.

## Design

D1, the shape of D2, the notation of D8, and the decisions listed at the
top are settled; items marked (proposed) await review.

### D1. Entry ids across mounts (decided)

An `EntryId` leaving sys-io is the fs-local id the filesystem produced,
with a 24-bit **mount id** packed into bits the filesystem keeps clear.
For Motor FS the fs-local id is `block_no | (generation << 64)`; the
reserved bits are the top byte of the block-number word (bits 56..63 of
the `u128`) and the top two bytes of the generation word (bits 112..127).
The mount id's low 16 bits go to bits 112..127 and its high 8 bits to
bits 56..63, so a counter fills the generation-word fragment first and
touches the block-number byte only past 65,535 mounts. The two fragments
are a packing detail: `split` and `join` are the only code that knows the
layout.

Invariants:

- Every `FileSystem` implementation produces ids with bits 56..63 and
  112..127 clear. Motor FS guarantees it by limiting a filesystem to 2^56
  blocks (256 EiB at 4 KiB blocks) and 2^48 generations:
  `MotorFs::open_with_cache_size` refuses a superblock whose `num_blocks`
  or `generation` is at or past its limit, `MotorFs::format` and the
  image-admin growth path refuse to create one past the block limit, and
  `allocate_block` and the directory-entry allocation that advances the
  generation return `StorageFull` when the next value would reach a limit
  (decision 16). Since commit `4527c75b` a generation is consumed only
  for a new directory entry, so at a sustained 1000 entries per second
  the generation limit is 8,900 years away. memfs guarantees both by
  construction (D7). A future adapter whose backend hands out arbitrary
  64-bit ids (virtio-fs, D14) keeps its own id table. sys-io
  debug-asserts the invariant on every id an FS returns.
- The constants live in `async-fs` (`MAX_FS_BLOCKS = 1 << 56`,
  `MAX_FS_GENERATIONS = 1 << 48`, with the mount-id layout documented
  beside them), so motor-fs, memfs and sys-io share one definition.
- The mount id is a per-boot counter. The root filesystem is mount 0, so
  root-filesystem ids are bit-identical to today's and the protocol's
  `ROOT_ID` (0) still names the root of the root filesystem. Every later
  mount, at boot or at runtime, takes the next value; a value is never
  reused within a boot, so an id of an unmounted filesystem can never
  name another one (D14). Mount N's root is `join(N, ROOT_ID)`. When the
  counter would exceed 2^24 - 1 the mount is refused with `StorageFull`
  (decision 16): 16.7 million mount operations per boot, 194 days at one
  per second.
- On input, sys-io splits the id, finds the mount by id, and rejects an
  id with no mount (`InvalidArgument`, the same code motor-fs uses for a
  stale id). The fs-local id then goes through the filesystem's own
  validation, unchanged from today.

Helpers in `runtime::fs` (names illustrative):

```rust
type MountId = u32;                       // 24 bits used
fn split(id: EntryId) -> (MountId, EntryId);   // (mount id, fs-local id)
fn join(mount: MountId, local: EntryId) -> EntryId;
```

### D2. Mount table (shape decided, details proposed)

```rust
struct Mount {
    id: MountId,                      // the per-boot counter value (D1)
    fs: Rc<LocalRwLock<FS>>,          // FS::MotorFs(..) | FS::MemFs(..)
    kind: MountKind,                  // for the listing and the logs
    parent: Option<MountPoint>,       // None for the root filesystem
}

struct MountPoint {
    mount: MountId,       // the parent filesystem's id
    shadowed: EntryId,    // fs-local id of the shadowed directory there
    name: String,         // the mount point's leaf name
    path: String,         // the configured path, for the listing
}

struct MountTable {
    mounts: Vec<Mount>,   // searched by id; the root (id 0) is first
    next_id: MountId,     // the counter; never decremented
}
```

A lookup is a linear search of the vector: with one or a few mounts that
is faster than any map and has nothing to tune, and the root is matched
on the first comparison. Unmount removes the element; the ids of the
remaining mounts do not change because they are values, not positions.

In iteration 1 the table is built in `fs::init` before the listeners
start and never changes afterwards (R1.4). It is nevertheless held as
`Rc<RefCell<MountTable>>` in `FsRuntime` (which is a struct of `Rc`s
cloned into every task, so a shared cell is the only way a later mount
command can change the table for all of them): `resolve` and `export`
take a borrow, copy out what the handler needs (the mount id, the
fs-local id and a clone of the mount's `Rc<LocalRwLock<FS>>`), and
release it. The rule is that **a table borrow is never held across an
await**, which keeps unmount's future table mutation from ever
conflicting with a handler. The cost is a non-atomic counter per request
(R6.2). `FsRuntime.fs` becomes `FsRuntime.mounts`, and every
`runtime.fs.read()` / `.write()` call site becomes "resolve the id, then
lock that mount". `resolve` is the only place that maps an id to a
mount. `MountKind` is an enum (`MotorFs`, `MemFs`) that D14's later
kinds extend.

### D3. Resolving mount points (proposed)

Two normalizations make R3.3 hold:

- **Input.** `resolve(id) -> (mount, local)`: split the id, then, if
  `(mount, local)` equals some mount's `(parent.mount, parent.shadowed)`,
  replace it with `(that mount, ROOT_ID)`. A client that somehow holds the
  shadowed directory's id (a forged one that passes motor-fs validation)
  gets the mount, never the shadowed content.
- **Output.** `export(mount, local) -> EntryId`: the inverse check, so a
  `CMD_STAT`, `CMD_STAT_PATH`, `CMD_GET_FIRST_ENTRY` or
  `CMD_GET_NEXT_ENTRY` result that names a shadowed directory comes back
  as the mount's root id.

The shadowed-id comparisons are one per mount (R6.2).

Per-command consequences for a mount root `(N, ROOT_ID)` with `N != 0`:

- `CMD_STAT_PATH` walks component by component as today; after every hop
  it applies the output check and continues inside the new mount. For
  `/none/tmp/motor-tests/tests/systest` the walk does `none` and `tmp` on
  mount 0, exports `tmp` as mount 1's root, and finishes on mount 1. It
  holds only the current mount's read lock, dropped before switching (D6).
- `CMD_GET_NEXT_ENTRY` asks for the *next sibling* of an entry, which for a
  mount root is a question about the parent directory: sys-io forwards it
  to the parent mount with the shadowed id, then exports the answer (the
  next sibling may itself be a mount point).
- `CMD_GET_NAME` forwards to the parent mount with the shadowed id (the
  mount point's leaf name); `CMD_METADATA` goes to the mounted filesystem's
  root. `ls -l /none` therefore shows the mount's own metadata under the
  name `tmp`.
- `CMD_DELETE_ENTRY` and `CMD_MOVE_*` with a mount root as the subject are
  refused with `NotAllowed`; `CMD_MOVE_ENTRY` with replace whose
  destination resolves to a mount point is refused too (the existing
  destination `stat` for `refuse_if_executing` is where the check goes).
  `std::fs::remove_dir_all("/none/tmp")` thus empties the memfs and then
  fails on the root, like a busy mount point elsewhere.
- `CMD_CREATE_*` and a non-replacing `CMD_MOVE_ENTRY` into the parent
  directory with the mount point's name are plain requests on the parent
  mount: motor-fs checks `w` on `/none` and then finds the shadowed `tmp`,
  so the outcome is today's (R3.8). Nothing is synthesized.
- `CMD_SET_PERMISSIONS` / `CMD_SET_ALL_PERMISSIONS` on a mount root go to
  the mounted filesystem, whose rules already say only System may change a
  root's mode.
- Everything else (read, write, resize, create, locks, spawn) resolves the
  id and dispatches to one mount.

Permissions along the path are unchanged: traversing `/none` is checked by
the root filesystem, listing `/none/tmp` by memfs's root mode (R4.4).

### D4. Request dispatch, executable locks and the pager (proposed; the lock and pager semantics are decision 7)

`on_msg` keeps its capability and pressure gates (D13 refines the latter).
Each handler begins with `let (mount, local) =
runtime.mounts.resolve(id)?;` and locks `runtime.mounts[mount].fs`. The
`FS` enum gains `MemFs(memfs::MemFs)`; the enum dispatch stays (no `dyn`).
`prefetch` and `cache_stats` become no-ops for memfs.

The lock manager, the executable locks and the pager key their state by
the *exported* id, so a shadowed id and the mount root it aliases can never
hold two locks, and a memfs executable is locked against write, resize,
delete, move, replacement and permission change for as long as a
construction or a mapping references it, by the code that does it today.

The pager's fault path is unchanged: `PageBuf` → `read_range` →
`read_exact_at` → `FS::read`, now through the executable's resolved mount;
memfs serves those block reads from its own blocks, so the process gets a
private copy of each page, as it does from the block cache. Sharing memfs
blocks with the process instead would need kernel support for mapping
sys-io memory into another process and could never cover relocated pages;
it is recorded here as a later optimization and not designed.

### D5. Cross-mount operations (proposed; the error code is decision 6)

- `CMD_MOVE_ENTRY` and `CMD_MOVE_NOREPLACE` with the entry's mount
  different from the new parent's mount return
  `moto_rt::Error::CrossesDevices`. Nothing is moved. The check comes after
  `resolve` of both ids and before any lock.
- `CMD_COPY_FILE_RANGE` with different mounts copies through a bounce
  buffer inside sys-io: read block-aligned chunks from the source under its
  read lock, drop it, write them to the destination under its write lock.
  `size` is capped per request at `WRITE_MAX_BYTES` (32 KiB); the client
  already loops. Executable locks apply to the destination as today. The
  same-mount path is unchanged.
- `CMD_FLUSH` flushes mounts in table order, each under its own write lock.

### D6. Locking (proposed)

One `LocalRwLock<FS>` per mount. The single rule: **a task never holds two
mount locks at once**. `CMD_STAT_PATH` drops the lock before crossing a
mount boundary; the cross-mount copy alternates; everything else touches
one mount. No lock ordering, no deadlock analysis. The lock is fair (a
queue of waiters), which is what a future unmount needs: it takes the
mount's write lock, waits behind the requests in flight, and no new
request gets in ahead of it (D14).

### D7. memfs (proposed; the capacity rules are decision 5)

A new crate `src/sys/lib/memfs`, std, depending on `async-fs` and
`async-trait`, and on `moto-sys` for the block store on Motor OS only
(the `cfg(target_os = "motor")` dependency pattern `async-fs` and
`motor-fs` already use).

- **Ids.** A slab of entries; the fs-local id is
  `slot | (generation << 64)` with `slot < 2^56` by construction and a
  per-filesystem generation counter that never repeats, mirroring Motor FS
  so a stale id fails validation the same way. Bits 56..63 are clear (D1).
- **Entries.** `Metadata` (the shared 128-byte record, so permissions and
  timestamps are the same type motor-fs stores), the leaf name, the parent
  slot, and either file data or a directory. A directory's children are a
  `BTreeMap<String, slot>`: lookup by name is `O(log n)`, and
  `get_first_entry` / `get_next_entry` enumerate in name order.
- **File data.** Lazily allocated 4 KiB blocks, one `Option<Block>` per
  block index, so sparse files and `resize` cost only what is touched.
  Reads and writes are served per block; cross-block requests are split
  internally.
- **Block store.** Data blocks do not come from the global allocator. On
  Motor OS the global allocator is frusa, which serves 4 KiB allocations
  from slab batches of up to 256 KiB and returns a batch to the kernel only
  when it is entirely free and the 5-second reclaim pass runs (Background);
  a memfs that deleted most of its files could keep most of its memory
  resident, and the reserve check of D13 would be fooled by it. Instead a
  `Block` is one page obtained with `SysMem::alloc(PAGE_SIZE_SMALL, 1)` and
  released with `SysMem::free` when the block is dropped: the kernel admits
  it at once, sees it freed at once, and the allocation is fallible by
  construction (a refused page is `StorageFull` to the client). On the
  host, for the unit tests, a `Block` is a boxed page. The cost is one
  syscall per newly allocated or freed block (R6.4); allocating blocks in
  larger runs is a later optimization if that ever shows.
- **Capacity.** `MemFs::new(max_size: Option<u64>, root_permissions)`.
  memfs always accounts its usage: every allocated data block, a fixed
  per-entry charge and the name length. With a cap, a request that would
  exceed it fails with `StorageFull` before any allocation or state
  change, and `resize` charges the blocks a later write would allocate, so
  a huge `set_len` fails up front. Without a cap nothing is refused by
  memfs itself; D13 is the control. `used_bytes()` and `max_size()` feed
  the listing; the trait's `num_blocks` / `empty_blocks` report the cap
  and the remainder, or zero and zero when uncapped (R4.8).
- **Permissions.** Shared code, not a copy: `Need` and the pure
  `check_access(metadata, role, need)` move from `motor-fs/src/fs.rs` to
  `async-fs` (motor-fs keeps calling them), `validate_filename` moves
  alongside, and `may_set` / `perms_monotonic` are already there. memfs
  applies them at the insertion points PERMISSIONS_DESIGN.md §5 lists:
  `x` on the parent for `stat` and enumeration, `w` on the parent for
  create, delete, move (both parents) and mode changes, `r`/`w` on the file
  for read/write/resize, System-only for the root's mode.
- **Root mode.** sys-io passes the shadowed directory's mode read at mount
  time (`rwxrwxrwx` for `/none/tmp`), or the configured one.
- **Timestamps.** `Timestamp::now()` on create, write, resize, rename.
- **Tests.** Host unit tests covering every trait method, the capacity
  accounting with and without a cap (R9.1), the block store's page counts
  across write, truncate and delete, stale-id rejection, and the
  permission matrix for all three roles.

### D8. Configuration file (notation decided; defaults as decided in Q3)

```toml
# /system/cfg/sys-fs.toml. Mounts are applied in file order at boot.
[[mount]]
path = "/none/tmp"
type = "memfs"
# max_size = "64M"      # optional; absent means no cap (decision 5)
# mode = "rwxrwxrwx"    # optional; the default is the shadowed directory's
```

Rules: `path` is absolute and canonical (no `.`, `..`, empty or trailing
components), not `/`, unique, and not below another entry's path (nesting
is a non-goal); `type` is `memfs`; unknown keys are rejected
(`deny_unknown_fields`); at most 255 entries; the file is at most 64 KiB.
`max_size` accepts an integer byte count or a `K`/`M`/`G` suffix; `mode`
uses the nine-character triplet notation of `docs/fs-permissions.md`. The
loader mirrors `net::config::load`: direct `FS` calls on mount 0, block by
block. Parsing is one pure function over the file's bytes, and validation
is one pure function over (the mounts already in the table, one new
entry), which the boot loader folds over the file's entries in order and
which a future mount command calls for its single entry against the live
table (R1.7). The debug self-test covers both (R9.2).

The entry is deserialized as an enum tagged by `type`, so later kinds add
their own keys without touching memfs's: `type = "motor-fs"` with `device`
and `partition`, `type = "virtio-fs"` with `tag` (D14). An unknown `type`
is an error today.

### D9. Boot sequence (decided policy; proposed mechanics)

In `fs::init`, after the root MotorFs opens and before the pager and the
listeners start:

1. Build the table with mount 0.
2. Look up `/system/cfg/sys-fs.toml` on mount 0. Absent: done (R2.4).
3. Parse and validate the whole file (R2.3). Any error: log the entry and
   the reason, then panic, as `net::init` does for `sys-net.toml`.
4. For each entry, `mount_one(table, entry)`: walk the path on the parent
   mount as System, require a directory, read its mode, create the
   filesystem (memfs with the cap and the root mode), append the `Mount`.
   A failure here panics the same way. Log one line per mount, including
   whether the shadowed directory is empty (information, not a warning:
   the shipped marker file of D12 makes it non-empty by design).
   `mount_one` is the step a future mount command repeats at runtime
   (R1.7); at boot nothing else runs, so it needs no locking yet.
5. Hand the table to `FsRuntime` as `Rc<RefCell<MountTable>>` (D2); the
   pager, the listeners and the stats responder start as today.
   `net::init` keeps receiving mount 0's `Rc<LocalRwLock<FS>>` (R3.7).

Nothing can observe a partially built table.

### D10. Stats and the mount listing (decided scope; proposed format)

`FS_CAPACITY_BYTES` / `FS_AVAILABLE_BYTES` keep reporting mount 0 and are
documented as the data partition. The listing is a new read-only command,
`CMD_GET_MOUNTS` (22), added to `is_read_command`, answering with one text
line per mount, `id type path used cap`, with `cap` the configured
`max_size` or `unlimited`, in an io page. `moto-io` gains a `mounts()`
call on `FsClient` and `sysbox mount` prints the lines. It is served to
every role: mount paths are visible through `ls` anyway. Per-mount metrics
in the stats responder can follow.

### D11. Changes outside `sys-io` (the complete list)

| Crate / tree | Change | Size |
|---|---|---|
| `moto-rt` | `Error::CrossesDevices = 24`, `E_CROSSES_DEVICES`; version 0.17.9; `src/sys/Cargo.lock` and the lockfile refresh of about eighteen `Cargo.lock` files (Background); published to crates.io | small, but touches every lockfile; publishing needs crates.io access |
| `../toolchain-src/rust` (the `moturus/rust` fork branch) | `library/std/src/sys/io/error/motor.rs`: map `CrossesDevices` to `ErrorKind::CrossesDevices`; `library/Cargo.lock`: select moto-rt 0.17.9; one commit, pushed | one line plus the lock |
| `../toolchain-src/mlibc` (the `moturus/mlibc` fork branch) | `sysdeps/motor/include/mlibc/motor-util.hpp`: `case 24: return EXDEV;`; one commit, pushed | one line |
| this repository, toolchain declaration | `src/toolchain-versions.sh` (`MOTOR_RUST_REV`, `MOTOR_RUST_LIBRARY_LOCK_SHA256`, `MOTOR_MLIBC_REV`), the rebuilt toolchain's name in `rust-toolchain.toml`, `docs/build-rustc.md` and `docs/toolchain.md` moto-rt version mentions | config and docs; one `src/build-motor-os.sh` run |
| `async-fs` | `MAX_FS_BLOCKS`, `MAX_FS_GENERATIONS` and the mount-id layout note; `Need` + `check_access` + `validate_filename` moved here | small |
| `motor-fs` | enforce the block limit in `open_with_cache_size`, `format`, image-admin growth and `allocate_block`, and the generation limit at open and where a directory entry takes a generation, both as `StorageFull`; call the moved helpers | small |
| `memfs` (new) | the filesystem, its block store and its host tests | the bulk of the library work |
| `moto-sys-io` | `CMD_GET_MOUNTS` and its codec (D10) | small |
| `moto-io` | `FsClient::mounts()` for sysbox | small |
| `sysbox` | `mount` listing; `mv` falls back to copy-plus-delete on `ErrorKind::CrossesDevices` for files and directories, reusing `cp`'s `copy_file` / `copy_directory` and then `remove_file` / `remove_dir_all` on the source; an existing destination directory is an error, an existing destination file is replaced as `rename` would replace it, a failure mid-way leaves the partial copy in place as coreutils does | small |
| `img_files/motor-os-base` | `system/cfg/sys-fs.toml`; `none/tmp/.shadowed-by-memfs` for the test | two files; no YAML or policy change |
| `docs/fs-permissions.md` | one sentence: `/none/tmp` is in memory, empty after every boot, bounded by memory | docs |
| kernel, `rt.vdso`, Rust std behavior beyond the mapping, imager code | none | — |

### D12. Test plan (proposed)

- Host: memfs unit tests (D7); motor-fs tests gain the block-limit
  rejection; a sys-io self-test (`crate::self_test`, debug builds) for
  `split`/`join`/`resolve`/`export` round trips, the shadowed-id alias,
  the config validator's accept and reject cases including a missing file,
  and the D13 decision as a pure function over free pages, command and
  mount kind.
- In-VM, added to `full-test.sh` and `systest` as listed in R9.2. The
  shadowing test ships `.shadowed-by-memfs` in the image's `/none/tmp`
  through `img_files/motor-os-base/none/tmp/` and asserts that `/none/tmp`
  is empty after boot and that the marker's path does not resolve.
- The existing gate is the acceptance test for spawn, `chmod`, uploads and
  the permission matrix on memfs: from the patch that ships the config on,
  every standard-image `full-test.sh` run executes its test binaries from
  memfs.
- Gate: R9.3.

### D13. memfs under memory pressure (proposed mechanics; decisions 5 and 12 set the policy)

Two signals, two outcomes:

- **The reserve (decision 12).** Before serving a memfs request that can
  allocate (`CMD_WRITE`, `CMD_CREATE_*`, `CMD_RESIZE` to a larger size,
  `CMD_MOVE_*` within memfs, `CMD_COPY_FILE_RANGE` with a memfs
  destination), sys-io reads `AdmissionStats::get().free_for_admission()`
  (one syscall, R6.4) and refuses the request with `StorageFull` when it
  is below 16 MiB (4096 pages). The check runs once per request, which is
  enough because one request allocates a bounded amount: at most
  `WRITE_MAX_BYTES` of data blocks plus one entry. Programs see the
  temporary filesystem as full, which is the condition a tmp-filling
  program handles. Requests on other mounts are not affected.
- **The kernel's flag, as today.** When the flag is up, the existing gate
  refuses every known command but `UNLOCK` with `OutOfMemory`, for every
  mount; nothing new is needed for memfs to be included. The flag rises at
  2 MiB, well below the reserve, so with memfs as the only consumer it is
  not reached; it remains the backstop when other processes consume the
  memory.
- **Freeing memfs operations stay served under the flag.**
  `served_under_pressure` is extended to `CMD_DELETE_ENTRY`, and to
  `CMD_RESIZE` when the new size is not larger than the current one, when
  the target id resolves to a memfs mount. Both request decoders are
  infallible and allocation-free, the mount lookup is a linear search of
  a short vector, and
  the operations only release memory, which is the property that exempts
  `UNLOCK` today. With D7's block store the released pages reach the
  kernel inside the same request.
- **Backstop.** A page the kernel refuses between the check and the
  allocation is `StorageFull` to the client (D7); sys-io never aborts.
- **Stats.** `pressure_refused` keeps counting the flag's refusals; a new
  `reserve_refused` counts the reserve's. The self-test checks the
  classification (D12).

### D14. What the roadmap needs kept open (decision 10)

Iteration 1 implements memfs only, but these later kinds must fit without
redesign. What the current design already does and what it must avoid:

- **A second virtio-blk device.** `runtime/mod.rs`'s single-device
  assertion is lifted then. A `Mount` with `FS::MotorFs` over any
  `VirtioPartition` is exactly what mount 0 is; the only addition is that
  `block_cache_blocks()` becomes a per-MotorFs budget rather than a
  single global one. Iteration 1 does not assume that mount 0 is the only
  Motor FS, nor that mounts beyond 0 are memfs.
- **Multiple Motor FS partitions per device.** `fs::init` panics on a
  second MotorFs partition today; later the root is the first MotorFs
  partition and the others are mountable by config (`type = "motor-fs"`,
  `device`, `partition`). D1's block limit applies per filesystem; two
  Motor FS instances produce overlapping fs-local ids and are told apart by
  the mount id, which is the whole point of it. The image tooling for
  creating such images is that iteration's work.
- **virtio-fs.** A `FileSystem` adapter speaking FUSE to a virtio-fs
  device. FUSE node ids are arbitrary 64-bit values, so the adapter keeps
  an id table that issues fs-local ids with the mount-id bits clear and a
  generation (D1). How the host's ownership maps onto the three roles is
  that iteration's design question; the mount table, locks, pager,
  cross-mount copy and the listing need no change. `CMD_FLUSH` already
  flushes every mount.
- **Read-only mounts** are a per-mount flag checked next to the
  `CAP_FS_WRITE` gate; the `Mount` struct has room for it.
- **Runtime mount and unmount (decision 15).** A privileged command pair
  (System role; the exact capability is that iteration's decision) that
  calls `mount_one` with a validated entry (D8, D9), or unmounts by mount
  id or path. What unmount needs, and what iteration 1 does about it now:
  - *In-flight requests.* Unmount takes the mount's write lock; the lock
    is fair, so it waits for the requests in flight and admits no new one
    (D6). Then it flushes a Motor FS, swaps `FS::Unmounted` into the
    `Rc<LocalRwLock<FS>>` (a variant added then; every `FS` method on it
    returns `InvalidArgument`), drops the filesystem, which for memfs
    returns its pages to the kernel at once (D7), and removes the element
    from the vector under a short borrow (D2). A handler that cloned the
    `Rc` before the swap and locks after it finds `Unmounted` and fails
    cleanly. Nothing in iteration 1 changes for this beyond D2's shape.
  - *Stale ids held by clients.* sys-io does not know which entry ids
    clients hold (open files are an id in rt.vdso, not a server-side
    object), so after an unmount they exist. They fail closed because a
    mount id is a per-boot counter value that is never reused (D1): no
    later mount can be found under the stale id, so no filesystem, in
    particular no second Motor FS partition with the same (block,
    generation) pair, ever sees it. The counter is also what bounds mount
    operations per boot, 16.7 million, refused with `StorageFull` past
    that (decision 16).
  - *Busy check.* An unmount is refused while the mount backs a running
    or loading executable, a demand-paged mapping, or a held file lock.
    Those live in `ExecLocks` (a map keyed by exported id), the pager's
    mappings (each records its `entry`) and the lock manager; because the
    mount id sits in the middle of the `u128`, ids of one mount are not a
    contiguous key range, so the check is a linear scan of three small
    maps, fine for a rare operation. No re-keying now.
  - *The mount point.* After unmount the shadowed directory is reachable
    again with its original id; D3's aliasing simply stops. A directory
    handle a process kept open across mount and unmount therefore works
    throughout, once on the mount and then on the directory, which is the
    intended behavior.
  - *Mount at runtime.* `mount_one` walks the mount point on the parent
    mount, which can change under it at runtime; that iteration validates
    the mount point under the parent's write lock before inserting. Same
    function, one more guard.
  - *Memory.* Unmounting memfs discards its contents; the pages return to
    the kernel at once (D7) and the reserve of D13 is restored.
- **Avoided in iteration 1:** no code assumes `mounts.len() == 2`, that
  mount 1 is memfs, that mount points lie on mount 0 (only the validator
  rejects nesting), that a non-root mount has nothing to flush, that the
  table is immutable (D2), or that mount ids are small, dense, or
  positions in the vector (D1).

## Implementation plan (draft; to be finalized after the design review)

Small reviewed patches, each with its tests; `src/sys` patches run the
R9.3 gate before commit. Steps 1 and 2 are the decision 6 work and land
first (decision 13), so every later patch uses `CrossesDevices` as the
final code. Step 2 changes trees outside this repository and needs
crates.io and fork-push access; the split of that work is in the Q11
answer. Steps 3 to 13 change no observable behavior in the shipped
images; step 14 switches `/none/tmp` to memfs with every mechanism it
depends on already in place.

1. `moto-rt`: `Error::CrossesDevices = 24`, version 0.17.9, `src/sys/Cargo.lock`
   and the lockfile refresh. std reports the code as `Uncategorized` until
   step 2; nothing produces it yet.
2. Toolchain, per `docs/toolchain.md` §5: publish moto-rt 0.17.9; commit
   the std mapping and the `library/Cargo.lock` selection on the Rust fork
   branch and the `EXDEV` line on the mlibc fork branch; push both; edit
   `src/toolchain-versions.sh`; run `src/build-motor-os.sh`; put the
   printed name into `rust-toolchain.toml`; update the two docs; run the
   §5 gate; commit the declaration, selector and docs together.
3. `async-fs`: `MAX_FS_BLOCKS`, the id-layout note, and the moved
   `Need` / `check_access` / `validate_filename`; motor-fs adjusted to
   call them. No behavior change.
4. `motor-fs`: the block limit at open, format, image-admin growth and
   `allocate_block`, and the generation limit at open and at
   directory-entry allocation, all reported as `StorageFull` (decision
   16), with host tests.
5. `memfs` crate, part 1: entries, directories, lookup and enumeration,
   create/delete/rename, metadata, host tests.
6. `memfs`, part 2: the block store (D7), file data,
   read/write/resize/copy_file_range, accounting, the optional cap with its
   tests.
7. `memfs`, part 3: permission enforcement and the role matrix tests.
8. `sys-io`: `MountTable` with mount 0 only, behind `Rc<RefCell<..>>`
   (D2); `split`/`join`/`resolve`/`export`; every handler and internal
   user (spawn, pager, locks, stats) resolves before locking; per-mount
   lock. No behavior change; full gate.
9. `sys-io`: `sys-fs.toml` parser, the per-entry validator and
   `mount_one` (D8, D9) with self-tests, boot-time mounting with the
   fail-closed policy, `FS::MemFs`. No image ships the file yet.
10. `sys-io`: mount-point semantics of D3 (shadow aliasing, sibling
    forwarding, name forwarding, refusals) with self-tests.
11. `sys-io`: cross-mount copy and the cross-mount move error (D5);
    `sysbox mv` fallback for files and directories; tests for both.
12. `sys-io`: the reserve and the pressure-gate refinement (D13) with
    self-tests and the `reserve_refused` counter.
13. `CMD_GET_MOUNTS`, `FsClient::mounts()` and `sysbox mount`; the listing
    shows mount 0 alone until 14.
14. Ship `sys-fs.toml` and `.shadowed-by-memfs` in `img_files/motor-os-base`,
    add the in-VM tests of R9.2, and the `docs/fs-permissions.md` sentence.
    Gate: `full-test.sh` debug and release three times each, plus
    `full-test-dev.sh --release` once.

## Open questions

All questions so far are answered and kept for numbering stability.

- **Q1. Config notation.** Answered: config file only, D8's format
  (decision 3).
- **Q2. Where the config and the marker ship.** Answered: the base tree
  (decision 4).
- **Q3. memfs capacity default.** Answered: no cap by default; `max_size`
  stays and is tested; allocating memfs operations are declined under
  memory pressure (decision 5, D13).
- **Q4. Cross-mount rename error.** Answered: a new code mapped to
  `CrossesDevices`, with the `sysbox mv` fallback (decision 6, D11).
- **Q5. Executables in memfs.** Answered: same executable locks, the pager
  copies bytes on faults, shared pages later (decision 7, D4).
- **Q6. Failure policy at boot.** Answered: fail closed (decision 8, D9).
- **Q7. Observability scope.** Answered: in iteration 1 (decision 9, D10).
- **Q8. What the design must not preclude.** Answered: a second block
  device, multiple Motor FS partitions per device, virtio-fs (decision 10,
  D14).
- **Q9. Test gate.** Answered (decision 11, R9.3).
- **Q10. A memfs reserve above the kernel's watermark.** Answered: yes, a
  fixed 16 MiB of free-for-admission memory, refusing with `StorageFull`
  (decision 12, D13).
- **Q11. Logistics of the toolchain change.** Your question: what is "a
  new channel string", is it just a new toolchain id, and why not add the
  error code first? Answer: yes, it is the rustup toolchain name in
  `rust-toolchain.toml`, `motor-<lineage>-<key>`, which
  `src/build-motor-os.sh` prints after a build; the key hashes what was
  compiled, so it changes whenever the Rust fork commit or its lockfiles
  change, and it is copied, not invented. The change itself is one enum
  variant in `moto-rt` and one mapping line each in the std port and in
  mlibc. What makes it more than two lines is the path by which std sees
  the variant (Background): std depends on the *published* `moto-rt`, so
  the crate is published to crates.io, the fork's `library/Cargo.lock`
  selects it, the fork commits are pushed, the toolchain is rebuilt, and
  the new name is committed with the declaration. Doing it first is
  right, and the plan now does (decision 13, steps 1 and 2); nothing in
  sys-io is written against an interim code. Confirmed split: you publish
  moto-rt 0.17.9 and push the two fork branches; I prepare the moto-rt
  patch, the two fork diffs and the declaration edit, run
  `src/build-motor-os.sh` once the pushes are in, put the printed name
  into `rust-toolchain.toml`, and run the §5 gate on the result.
- **Q12. Scope of the `sysbox mv` fallback.** Answered: files and
  directories (decision 14, D11).

- **Q13. Mount-id scheme and the Motor FS limits.** Answered, superseding
  the index-plus-epoch proposal: the mount id is a 24-bit per-boot
  counter in the 16 reserved generation-word bits plus the 8 reserved
  block-number bits, filling the generation bits first; the table is a
  vector searched by id; Motor FS limits generations to 2^48 and blocks
  to 2^56 and reports either as `StorageFull`, as does a mount that would
  exhaust the counter (decisions 1 and 16, D1, D2, D14). The numbers:
  with a generation consumed only per new directory entry (commit
  `4527c75b`), 1000 per second is a realistic high bound and 2^48 lasts
  8,900 years at that rate; the counter allows 16.7 million mount
  operations per boot, 194 days at one per second.
