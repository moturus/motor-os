# Multiple filesystems in sys-io

Status: **preparatory work complete; sys-io mount integration pending**
(2026-10-20). The wire-ID codec, incoming Motor FS ID validation,
cross-device error and toolchain mappings, shared filesystem helpers, and
standalone memfs crate are committed. sys-io still serves one Motor FS
filesystem; `/none/tmp` is still on disk. No mount config is shipped.

All sysbox work remains outside iteration 1, including a mount-listing
command and cross-mount `mv` fallbacks (decisions 9 and 14). Existing
clients continue to use sys-io's file-copy requests; sys-io never
implements a move by copying and deleting. D15 retains the agreed
safeguards for a future sysbox design. Mount-table ownership remains as
specified in D2; the proposed simplification is not yet decided.

Completed work:

| Work | Commit(s) | Current result |
|---|---|---|
| Wire entry-ID shuffling | `d3af1b66` | Per-boot AES-128 when AES-NI is available, otherwise the warned XOR fallback; both preserve root ID 0. Client ingress/egress uses the shared codec. |
| Incoming Motor FS ID validation | `d6c0ad2a` | Reject impossible block addresses before cache access; validate entry blocks and generations, including stale/forged-ID tests. This is separate from future mount-bit validation. |
| Cross-device error | `f34023e0`, `5c1e5749` | Published moto-rt 0.17.9, `CrossesDevices = 24`, std/mlibc mappings, sys-io's reverse mapping, refreshed pins/locks and selected rebuilt toolchain (D11). |
| Shared access/name helpers | `c4b688a5` | `Need`, `check_access`, `MAX_FILENAME_LEN` and `validate_filename` live in `async-fs`; motor-fs uses them and preserves its filename-validation API. |
| Standalone memfs | `8dfe872f` | Complete synchronous implementation with thin async adapters, sparse storage, quota accounting, independent free-page cache and shared host/native tests (D7). No production caller yet. |

Standing summary: for iteration 1, sparse files and the 16 MiB reserve
(8 MiB on guests under 32 MiB), with D13's admission and reclamation
rules, are accepted as sufficient OOM protection; a rigorous OOM
treatment is deferred and comes back into scope when iteration 1 is
complete (R8.5, D15). The codec's weaker XOR mode remains explicitly
accepted in D1. Mount-id packing, routing, boot mounting, pressure
admission and mount observability remain to be implemented.

The implementation plan below is reconciled with the current requirements,
design and committed work. Its original step numbers are retained for
cross-references; the wire codec and standalone memfs landed out of the
original sequence. The completed validation is recorded with the plan.

Decisions so far:

1. **Internal entry-id scheme.** Motor FS entry ids retain their layout, with
   three bytes-worth of headroom reserved: Motor FS is limited to 2^56
   blocks and 2^48 generations, so the top byte of the block-number word
   and the top two bytes of the generation word are always zero on disk.
   sys-io carries a 24-bit **mount id** in those 24 bits. The mount id is
   a per-boot counter that never repeats: it fills the 16 generation-word
   bits first and spills into the block-number byte only past 65,535
   mounts. The mount table is a vector of mounts searched by id; the root
   filesystem has id 0 and is first. Client-facing IDs additionally use a
   per-boot reversible permutation fixing 0. sys-io checks CPUID once at
   startup: use AES-128 through AES-NI if available; otherwise log a
   warning and use the adjusted XOR fallback with a random seed (D1).
   The fallback is obfuscation, not cryptographic protection. All IDs pass
   through the chosen codec at the client boundary. The wire codec landed
   in `d3af1b66`; the internal mount-id scheme remains to be implemented.
2. **First use case is `/none/tmp`**, the None role's temporary directory,
   which every image already creates. memfs is mounted over it and the root
   filesystem's `/none/tmp` is shadowed. `/user/tmp` stays on the root
   filesystem; the tests, scripts and tools that use it are out of scope.
3. **Configuration is the file only.** Iteration 1 has no runtime `mount`
   command. Mounts come from `/system/cfg/sys-fs.toml` in the
   one-TOML-table-per-mount notation of D8 (Q1).
4. **The config and the shadow marker ship in `img_files/motor-os-base`**,
   which every image layers (Q2).
5. **Every memfs has a cap; the default comes from RAM.** `max_size` is
   an optional per-mount setting. Without it the cap is guest RAM rounded
   down to a multiple of 16 MiB, minus 16 MiB, and at least 8 MiB (Q14,
   Q21; the RAM figure is `guest_ram_mib()`, D7). A configured cap may
   exceed RAM and is then reported as configured. Independently of the
   cap, sys-io refuses memfs operations that allocate while the guest's
   free memory is below the reserve (decision 12, D13).
6. **Cross-mount rename uses the new error code**, the implemented
   `moto_rt::Error::CrossesDevices` variant mapped to
   `std::io::ErrorKind::CrossesDevices` and libc's `EXDEV` (Q4).
   No copy-plus-delete fallback is implemented in iteration 1 (decision 14).
   The error plumbing is complete (D11); returning it for cross-mount
   rename awaits sys-io mount dispatch.
7. **Executables in memfs** are locked while they back a running process
   exactly as root-filesystem executables are, and the demand pager copies
   their bytes on each fault as it does today. Sharing memfs pages with the
   process is a later consideration, not designed here (Q5, D4).
8. **Boot fails on bad config**: a malformed config or a mount that cannot
   be applied at boot panics sys-io with a clear log line (Q6, D9). Only
   the boot loader panics: the validator and the mount step return
   errors, so a later runtime mount command reports them to its caller
   and never panics sys-io (R2.3).
9. **The mount-listing API is in iteration 1; its sysbox command is
   deferred** (Q7, D10, D15).
10. **Roadmap kept open**: a second block device, multiple Motor FS
    partitions per block device, and virtio-fs mounts are later iterations
    and must not be precluded (Q8, D14).
11. **Test gate per milestone.** Patches are tested lightly; the full
    gate runs at the end of each milestone of the implementation plan,
    with the developer-image run added for the larger ones (Q9, Q18,
    R9.3).
12. **Iteration-1 OOM protection is accepted.** Allocating memfs operations
    are refused with `StorageFull` when free-for-admission memory is below
    16 MiB, checked once per such request. Before refusing, sys-io
    empties the free-block caches of the memfs mounts and checks again.
    Every sys-io admission gate that would refuse for a memory reason,
    the kernel-pressure gates included, drains the caches and re-reads
    its signal first; a gate that admits never touches them (D13). On a guest under 32 MiB the threshold
    is 8 MiB (Q21). This sampled threshold plus true sparse files is
    accepted as sufficient for iteration 1; it is not a proof against
    every OOM scenario. The rigorous treatment of metadata, concurrent
    allocations and headroom becomes in scope again as soon as iteration
    1 is complete (R8.5, D15).
13. **The error code lands first.** This prerequisite is complete:
    `moto-rt` has `CrossesDevices`, the crate is published, the Rust and
    mlibc forks map it, and the rebuilt toolchain is selected. sys-io
    mount support will use the final code from the start (Q11; plan
    steps 1 and 2). The wire codec landed separately.
14. **All sysbox work is deferred.** Iteration 1 adds no `mount` command,
    `mv` fallback, recursive-move flag, or changes to `cp`. Cross-mount
    rename fails without copying or deleting anything. Server support for
    existing file-copy requests remains in scope (D5). Future command
    semantics need a separate design (Q12, D15).
15. **Runtime mount and unmount commands are planned** for a later
    iteration, and Interactive users will be able to run them: Motor OS
    has no privilege escalation (no `su`, no `sudo`), so they are gated
    by the caller's own role, not by a switch to System. Iteration 1
    stays boot-only (decision 3); keep mount-qualified IDs and encapsulated
    dispatch, while deferring lifecycle and permission design (R1.7, D14).
16. **A bad entry id corrupts its mount; nothing asserts.** sys-io checks
    every id a filesystem returns. One with mount-id bits set marks the
    mount corrupted: sys-io logs an error naming the mount and the id,
    fails that request with `InvalidData`, and fails every later request
    that resolves to the mount with `InvalidData` until reboot (D1, D2).
    The Motor FS limits (2^56 blocks, 2^48 generations) cannot be reached
    by normal operation and get no error path and no tests; nothing
    asserts them, in motor-fs or in sys-io, and motor-fs carries no
    checks for those format limits: the planned sys-io check is the single
    guard (Q13, Q22). Motor FS's implemented validation of untrusted input
    IDs against actual device bounds and entry metadata is separate.
    The mount counter is different: once runtime mount
    exists, exhausting it is client-driven, so it is an error
    (`StorageFull`), never a panic (D1, D14).
17. **memfs keeps a free-block cache.** Freed data blocks stay in a
    per-mount cache up to a RAM-derived cap and are reused before new
    pages are requested; past the cap they return to the kernel at once.
    sys-io empties the caches before final memory-admission refusals and
    after freeing requests served under the kernel's pressure flag
    (D7, D13). This is reactive, not an idle pressure observer.
18. **Nested mounts and read-only mounts are later iterations**, not
    non-goals: a memfs may later be mounted at `/user/data/tmp` inside a
    second block device mounted at `/user/data`. Iteration 1 resolves
    every mount point through the live mount table. Parent-before-child
    nesting is accepted by the validator, but a later mount must not hide
    an earlier one: reject a path that is an ancestor of an earlier entry.
    In iteration 1 a nested mount cannot be applied, because a memfs is
    empty at boot and its nested mount point would not exist. The unmount
    side of nesting is that later design's (Q15; R1.5, R2.3, D8, D9, D14).
19. **A mount root cannot be renamed, moved, replaced or deleted** while
    the mount is active; each is `NotAllowed`, checked before
    `CrossesDevices`. The rejected operation changes nothing.
    Ancestors of a mount point are not protected: the mount is
    keyed by the shadowed directory's id, not by its path, so renaming an
    ancestor moves the mount with it and only the listed path, which is
    the configured one, goes stale (Q16; R3.5, D3, D10).
20. **Per-mount statistics**: bytes in use, entry count and cap per
    mount in the mount listing; memfs totals and the reserve counter in
    the stats responder (Q17; R7.4, D10).
21. **memfs ids are a counter.** A per-filesystem `u64` that never
    repeats, kept in a map; the fs-local id carries its top byte in the
    high word so the mount-id bits are clear by construction (Q19, D7).
22. **The memfs memory test runs on guests whose memfs cap is at most
    1 GiB.** It lives in systest, fills memfs to the reserve, and checks
    basic service and accounting recovery; on a larger guest
    it skips itself with a notice (R9.2, D12, D13).
23. **True sparse files and allocated-storage accounting.** Logical size
    and holes consume no data blocks or per-hole index slots. `max_size`
    counts allocated data blocks plus metadata/name/index charges (D7),
    with no charge for holes or future writes. Sparse growth alone must
    not fail because the cap is full. Exact allocator-residency accounting
    and a rigorous OOM bound are deferred under decision 12.
24. **Protected configuration and explicit observability.** No mount may
    shadow any part of `/system/cfg` (R2.3). The mount listing uses bounded
    structured pagination, and corrupted mounts have unknown usage
    statistics (D10). Shell display belongs to the deferred sysbox work.

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
  `CMD_SPAWN` takes the executable's entry id). There is no "get parent"
  command on the wire. `CMD_FLUSH` has no target: it flushes "the"
  filesystem. Commands are numbered 1 to 21; `is_read_command` lists the
  ones served without `CAP_FS_WRITE`. The request decoders for
  `CMD_RESIZE` and `CMD_DELETE_ENTRY` are infallible and allocation-free.
- motor-fs builds an entry id from `EntryIdInternal { block_no: u64,
  generation: u64 }` (`layout.rs`, `repr(C)`), transmuted to the `u128` in
  `From<EntryIdInternal> for EntryId`. The block number is the first eight
  bytes, which on x86-64 are bits 0..63 of the `u128`; the never-reused
  generation is bits 64..127. Since `d6c0ad2a`, all incoming IDs pass
  through `internal_id`: root zero maps to the on-disk root; superblock,
  transaction-log and out-of-device addresses are rejected before block
  cache access. The entry-block type/in-use and generation checks then
  reject malformed or stale identities. The superblock keeps `num_blocks`,
  `free_blocks` and `generation`; it has no entry count.
- Since `d3af1b66`, those raw entry ids stay internal to sys-io.
  `FsRuntime` owns a shared per-boot `EntryIds` codec
  (`runtime/fs/entry_ids.rs`): AES-128 through AES-NI when available,
  otherwise the warned, non-cryptographic XOR fallback of D1. Client IDs
  are decoded at ingress and encoded at egress, including the IDs exposed
  through `FileAttr.entry_id`; the root stays zero. Internal filesystem
  users, locks and pager mappings retain unencoded identities.
- Clients (`rt.vdso/src/rt_fs.rs` over `moto-io`) canonicalize paths
  lexically, including `..`, keep the cwd as a string, and never call
  `get_parent`. A rename resolves the source entry and the destination
  parent, then issues one move. `std::fs::copy` resolves both files and
  loops over `copy_file_range` in 64 KiB chunks; there is no read/write
  fallback. `FileAttr.entry_id` is exposed to programs as the file's unique
  identity.
- Permission enforcement (`r`/`w`/directory `x` per role) lives inside
  each filesystem. Since `c4b688a5`, the pure `check_access(metadata,
  role, need)`, `Need`, filename validation and its length bound live in
  `async-fs`, alongside the mode-authority rules (`may_set`,
  `perms_monotonic`). Motor FS and memfs use those shared helpers.
  sys-io derives the role from the connection peer's capabilities and
  passes it down; `CAP_FS_WRITE` gates
  every mutating command in sys-io itself. Default modes for new entries
  are computed in sys-io, so they are the same for every filesystem it
  serves.
- `src/sys/lib/memfs` is a workspace member with ten tests wired into
  `full-test.sh` in both profiles. Its async trait methods delegate to
  public synchronous counterparts and never yield; the same tests also
  run natively through Lorry. It has no production dependency from sys-io,
  no RAM-derived defaults and no admission policy. Callers supply its
  capacity, cache cap and root mode; D7 describes the implemented library.
- State keyed by entry id inside sys-io: the file lock manager, the
  executable locks (`spawn::ExecLocks`, consulted by `refuse_if_executing`
  before write, resize, delete, move, replace and permission changes), and
  the demand pager's mappings. All of it assumes entry ids are unique.
- The demand pager (`runtime/fs/spawn/pager.rs`) serves a fault by
  allocating a page-aligned buffer, reading the executable's bytes into it
  block by block through the `FS` object (`read_range` / `read_exact_at`),
  applying relocations to the buffer, and handing the buffer to the kernel
  with `SysMem::pager_fill`. The process therefore gets its own copy of
  every page; nothing is shared with the filesystem's memory. A fill that
  fails kills the faulting process.
- One `LocalRwLock<FS>` serializes every writer, including block I/O waits.
- sys-io's own filesystem users bypass the client protocol and call the `FS`
  object directly: the net config loader (`/system/cfg/sys-net.toml`), the
  `resolv.conf` writer, the spawn path and the pager, and the stats
  responder, which publishes `FS_CAPACITY_BYTES` / `FS_AVAILABLE_BYTES` from
  `num_blocks` / `empty_blocks`.
- Stats wire form: a `MetricEntry` is `(metric id, scope, value)`, where
  the scope is a PID or 0 for the provider-wide aggregate; collectors learn
  metric names through `CMD_DESCRIBE`. Every FS metric today is global.
- Config loading pattern: `sys-net.toml` is read at boot with direct `FS`
  calls (never `std::fs`), block by block, with a 64 KiB size cap; a missing
  or malformed file makes `net::init` fail and sys-io panic.
- RAM-derived limits: `runtime::guest_ram_mib()` is the kernel's reported
  physical memory plus 10 MiB, which approximates the guest's configured
  size; `SMALL_GUEST_MIB` (256) separates small guests. The block cache
  (1 MiB per 32 MiB, 16 MiB from 256 MiB up), the TCP buffers and the
  connection limits are all sized from it.
- Memory pressure: the kernel raises the `memory_pressure` flag on its
  shared static page when free-for-admission memory is at or below
  `PRESSURE_LOW_PAGES` (512 pages, 2 MiB) and clears it at
  `PRESSURE_HIGH_PAGES` (768 pages, 3 MiB) (`kernel/src/mm/admission.rs`).
  `moto_sys::memory_pressure()` reads the flag without a syscall;
  `moto_sys::stats::AdmissionStats::get()` is one syscall, needs no
  capability, and its `free_for_admission()` is the number the kernel
  compares against its floors; systest's `pressure.rs` already uses both.
  While the flag is up, sys-io refuses new clients and every known FS
  command except `CMD_FILE_LOCK`/`UNLOCK` with
  `moto_rt::Error::OutOfMemory` (`served_under_pressure`); the stated
  reason is that any other command can grow sys-io, and sys-io dies if the
  kernel refuses that growth. sys-io has a debug-build self-test facility
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
- Error codes: `moto_rt::Error` is a `repr(u16)` enum;
  `CrossesDevices = 24` follows `PageAbsent = 23`
  (`moto-rt/src/error.rs`) and is published in moto-rt 0.17.9
  (commit `f34023e0`). Three places map the codes:
  the Rust std port, `library/std/src/sys/io/error/motor.rs` in
  `../toolchain-src/rust` (unknown codes become `ErrorKind::Uncategorized`);
  the mlibc port, `sysdeps/motor/include/mlibc/motor-util.hpp` in
  `../toolchain-src/mlibc` (`StorageFull` is `ENOSPC` there); and
  `moto-rt` itself. `NotAllowed` is `PermissionDenied` / `EPERM`;
  `AlreadyInUse` is `AlreadyExists` / `EEXIST`; `InvalidData` is
  `ErrorKind::InvalidData` / `EIO`; there is no `EBUSY` equivalent. The
  toolchain is built from upstream Rust 1.99, so
  `ErrorKind::CrossesDevices` exists.
- How a moto-rt change reaches std (`docs/toolchain.md` §5,
  `docs/build-rustc.md`): Rust std depends on the published crates.io
  `moto-rt` (minimum 0.17.9 for the new error mapping), pinned by the Rust fork's
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
  the declaration, the selector and the docs together. The latest instance
  is `f34023e0` plus `5c1e5749`: moto-rt 0.17.9 and `CrossesDevices`,
  the consumer lockfile refresh, fork pins, rebuilt toolchain selector,
  reverse error mapping and docs. The selected std now recognizes this
  variant. For future additions, local `moto-rt` can run ahead of std's
  within one major version, so a new variant may compile here before std
  recognizes it; an old std reports such a code as `Uncategorized`.
- sysbox (`src/sys/tools/sysbox`) hosts the coreutils-style commands.
  `cp` has `-r` with `copy_directory` / `copy_file` helpers over
  `std::fs::copy`; `mv` is a thin wrapper around `std::fs::rename` and
  reports any error. There is no `mount` command; rush's only filesystem
  builtins are `cd` and `pwd`.
- systest (`src/sys/tests/systest`) depends on `moto-io`, `moto-sys` and
  `moto-sys-io`, runs its tests sequentially, and prints
  `<test>: SKIPPED (<reason>)` for a test that does not apply to the
  current guest.

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
- Policy (`src/imager/motor-os-permissions.yaml`): `/none` is `rwxrwxr-x`
  today; `/none/tmp` is `rwxrwxrwx` for directories, `rw-rw-rw-` for
  files, `rwxrwxrwx` for scripts and `r-xr-xr-x` for ELF executables.
  Runtime-created entries get sys-io's default modes (an
  Interactive-created directory is `rwxrwxr-x`, a file `rwxrw-r--`), which
  the harness relies on: a directory None created first would be writable
  by None. `/none`'s own mode is policy outside this work and may change
  in parallel; nothing here depends on it.
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
    `temp_dir.rs` asserts the `TMPDIR` string only. `pressure.rs` drives
    the guest below the kernel's low watermark with a squeeze child.
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

Items marked **(stated)** come from the task and subsequent user guidance;
**(decided)** records an accepted review decision. These requirements
remain authoritative; implementation status does not relax them. The plan
and question record below are reconciled as of 2026-10-20. D15 records
explicitly deferred work.

### R1. Scope

- R1.1 **(stated)** sys-io serves more than one filesystem at a time. The
  filesystem on the data partition stays mounted at `/`; additional
  filesystems are mounted at directories below it.
- R1.2 **(stated)** The mount table is driven by `/system/cfg/sys-fs.toml`,
  a new file. Without it, only the root filesystem is mounted. D1's
  opaque wire-ID scheme still applies.
- R1.3 **(decided)** First use case: mount an in-memory filesystem
  (`memfs`, now implemented as a standalone crate) at `/none/tmp`,
  completely hiding the `/none/tmp` directory of the root filesystem.
  In mount-command terms:
  `mount -t memfs /none/tmp`.
- R1.4 **(decided)** Iteration 1 applies mounts at boot from the config
  only. No runtime mount or unmount, and no client command can change the
  mount table.
- R1.5 **(decided)** The mount mechanism is not memfs-specific. Later
  iterations will add a second block device, multiple Motor FS partitions
  per block device, virtio-fs mounts, read-only mounts, nested mounts (a
  mount point inside another mount, for example a memfs at
  `/user/data/tmp` inside a second block device mounted at `/user/data`),
  and runtime mount and unmount commands that Interactive users can run.
  Iteration 1 implements only boot-time memfs mounts but must not
  preclude those (decisions 15 and 18, D14).
- R1.6 **(decided)** Iteration 1 implements memfs and sys-io mount support,
  including the supporting shared-library and protocol changes in D11.
  The new `CrossesDevices` error in `moto-rt` and its corresponding stdlib
  and mlibc mappings are explicitly in scope, along with the required
  toolchain update. All sysbox changes are out of scope, including
  command-specific tests. No kernel changes. D11 identifies the supporting
  changes to `async-fs`, `motor-fs`, `moto-sys-io` and `moto-io`, and the
  completed changes outside this repository in `../toolchain-src/rust` and
  `../toolchain-src/mlibc` (AGENTS.md notes 3 and 4).
- R1.7 **(decided)** Keep future mounts possible without implementing their
  lifecycle now: mount IDs are never reused within a boot, entry-related
  state uses mount-qualified IDs, table access is encapsulated, and the
  validator and mount step return errors rather than panic. Unknown mount
  IDs fail with `InvalidArgument`. Runtime admission, unmount races, busy
  checks and existing-handle semantics belong to that later design (D14);
  iteration 1 does not promise it will need no handler changes.

### R2. Configuration

- R2.1 **(decided)** TOML, one `[[mount]]` table per mount (D8), parsed
  with the `toml` and `serde` crates sys-io already uses for
  `sys-net.toml`, read at boot with direct `FS` calls, size-capped.
- R2.2 **(decided)** Each mount entry names the mount point (an absolute,
  canonical path) and the filesystem type. memfs entries may set a capacity
  cap and a root mode. The schema is D8.
- R2.3 **(decided)** The file is validated as a whole before any mount is
  applied: unknown types or keys, duplicate mount points, non-absolute or
  non-canonical paths, a mount point at `/`, and more than 255 entries (a
  policy cap, not an id-space limit) are errors. A mount point inside an
  earlier entry's mount is not an error: mounts are applied in file
  order, and each mount point is resolved through the mounts applied
  before it (decision 18, D9). Reject an entry whose path is a proper
  ancestor of an earlier entry's path: applying it would hide an existing
  mount. Compare whole path components and validate the given order;
  do not reorder entries. In iteration 1 a parent-before-child entry cannot
  succeed, because a memfs is empty at boot and the nested mount point
  would not exist (R3.2). A path at or below `/system/cfg`, or an
  ancestor of `/system/cfg`, is rejected, so mounts cannot hide protected
  configuration from pathname readers while internal users address mount
  0; that check compares whole path components, not string prefixes. A
  malformed file, or a mount that fails
  to apply, panics sys-io at boot with a log line naming the entry (decision
  8, D9). The panic is the boot loader's alone: the validator and the
  mount step return errors, so a later runtime mount command reports them
  to its caller and never panics sys-io.
- R2.4 A missing `/system/cfg/sys-fs.toml` is not an error and costs one
  failed lookup in `/system/cfg` at boot.
- R2.5 **(decided)** `img_files/motor-os-base/system/cfg/sys-fs.toml`
  mounts memfs at `/none/tmp` in every image. The directory exists in every
  image already, so no image YAML or policy entry changes.

### R3. Namespace semantics

- R3.1 **(stated)** A mount completely shadows the mount point directory
  of the parent filesystem in pathname lookup and enumeration. At boot,
  mounts are applied before any client receives IDs. In AES mode,
  unissued descendant IDs are computationally impractical to guess (D1).
  The accepted XOR fallback does not provide that protection against a
  deliberate client: known IDs can reveal its seed. Pathname/enumeration
  shadowing and ordinary permissions still apply in both modes, but
  direct-ID access to hidden descendants is not secured by XOR. Neither
  mode revokes an already-issued ID. The treatment of such IDs when
  runtime mounting arrives remains open
  (D14, D15). The shadowed entries stay on disk, unchanged.
- R3.2 **(decided)** The mount point must exist on the parent filesystem
  and be a directory. sys-io does not synthesize mount points. For
  `/none/tmp` this holds in every image.
- R3.3 Every way of reaching the mount point resolves to the mounted
  filesystem's root: a path walk (`CMD_STAT_PATH`), a single-component
  lookup in the parent (`CMD_STAT`), and enumeration of the parent
  directory (`CMD_GET_FIRST_ENTRY` / `CMD_GET_NEXT_ENTRY` followed by
  `CMD_METADATA` / `CMD_GET_NAME`). A program must not be able to observe
  two identities or two metadata records for `/none/tmp` depending on how
  it got there. Design: D3.
- R3.4 Entry ids are unique across all mounted filesystems: the mount id
  lives in the internal id, and the wire permutation is bijective (D1).
  `FileAttr.entry_id` is opaque, stable within a boot, and keeps meaning
  "this file", and the lock manager, executable locks and pager stay
  correct without per-mount special cases. An id whose mount id names
  no mounted filesystem is rejected; an id cannot address one filesystem's
  entry through another's id space. Only the wire `ROOT_ID` stays 0;
  other wire IDs use the boot's chosen codec. Clients must treat them as
  opaque; only AES mode cryptographically conceals the mount-id layout.
  A filesystem that returns a local id with mount-id bits set has
  broken the invariant: sys-io marks that mount corrupted and fails it
  closed with `InvalidData` from then on (decision 16, D1).
- R3.5 Operations that span two filesystems:
  - **(decided)** Rename or move across mounts is refused with
    `moto_rt::Error::CrossesDevices`, which std reports as
    `ErrorKind::CrossesDevices` and libc as `EXDEV`. It is never emulated
    inside sys-io as copy-plus-delete. The sysbox fallback is deferred;
    iteration 1 leaves both source and destination unchanged on rejection.
  - File copy across mounts works through existing clients, including
    `std::fs::copy` into or out of `/none/tmp`. The data path lives in
    sys-io (D5); it copies bytes without deleting the source. Client-side
    traversal and copy semantics are unchanged; no sysbox work is required.
  - **(decided)** Deleting, renaming or moving the mount point directory
    itself, or replacing it via a rename onto it, is refused with
    `NotAllowed` while the mount is active (decision 19, D3). The check
    precedes the cross-mount check. Rejected operations leave the mount
    and its contents intact, whether the other operand is on the same
    mount or a different one.
  - `CMD_FLUSH` attempts every healthy mount, even if another fails;
    memfs has nothing to flush. A corrupted mount is skipped and makes
    the result `InvalidData`, never success (D5).
- R3.6 Lexical `..` handling in clients is unchanged: no server-side parent
  traversal crosses a mount boundary, because none exists today.
- R3.7 sys-io's internal users that take client-supplied ids (spawn, the
  pager, the lock manager, stats) go through the mount table. The net
  config loader and the `resolv.conf` writer keep addressing mount 0
  through the common checked-access helper, including its corruption
  gate. R2.3 protects `/system/cfg` from shadowing, so pathname readers
  see the same configuration that those internal users read and write.
- R3.8 Operations on the parent directory that name the mount point behave
  as they do today, because the shadowed directory is still on disk and
  the checks are the parent filesystem's: creating `tmp` in `/none` is
  refused at the parent's `w` check for a role that may not write
  `/none`, and returns "already exists" for a role that may. Nothing is
  synthesized. Which roles may write `/none` is policy outside this work.

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
- R4.5 Capacity. Every memfs mount has a cap, enforced by memfs itself
  before exceeding the charged allocation. File data is charged only for
  allocated blocks, never holes or logical size; metadata, names and
  sparse-index entries also count toward `max_size` (D7). Namespace
  operations are atomic on returned errors; multi-block writes and copies
  may return a committed prefix (R4.13). A refused allocation is
  `StorageFull`. The cap is `max_size` when configured, else guest RAM
  rounded down to a multiple of 16 MiB, minus 16 MiB, and at least
  8 MiB: 1008 MiB in the 1024 MiB test guest, 240 MiB in a 256 MiB one,
  8 MiB under 32 MiB (decision 5, D7). A configured cap may exceed RAM.
  Independently of the cap, the 16 MiB reserve and the memory-pressure
  handling of D13 apply: sys-io refuses every memfs operation that can
  allocate with `StorageFull` while free memory is below the reserve,
  after emptying the memfs free-block caches. Because the system itself
  uses more memory than the formula subtracts, the reserve is in practice
  reached before the default cap; the cap is what the listing and
  `num_blocks` report. Data-page allocation is fallible. For iteration 1,
  sparse storage, bounded data requests, the reserve and reclamation are
  accepted as sufficient OOM protection. Making every metadata/request
  allocation fallible or proving sufficient headroom is deferred until
  iteration 1 is complete (R8.5, D15). Memory freed by deleting or shrinking
  memfs entries goes into the mount's bounded free-block cache, and past
  the cache's cap back to the kernel at once; sys-io empties the caches under
  pressure (decision 17, D7, D13). The configured cap and the cache are
  covered by memfs host tests (R9.1); the shipped config sets no
  `max_size` and so gets the default.
- R4.6 **(decided)** Executables stored in memfs can be spawned and
  demand-paged like executables on the root filesystem. sys-io locks a
  memfs file that backs a construction or a running process exactly as it
  locks a Motor FS file (the same `ExecLocks`, keyed by canonical internal id),
  and the pager copies bytes out of memfs on every fault as it copies them
  out of the block cache today. A memfs file can be made executable with
  `chmod`. The standard-image gate uploads its test binaries into
  `/none/tmp` and runs them from there, so this is a day-one requirement.
  Sharing memfs blocks with the process instead of copying is a later
  consideration (D4).
- R4.7 File locking (`CMD_FILE_LOCK`) works on memfs files without
  changes: the lock manager is in sys-io and keyed by entry id.
- R4.8 **(decided)** `num_blocks` / `empty_blocks` report the cap and the
  remaining capacity after all charges, in whole 4 KiB blocks rounded down,
  whether the cap is configured or derived (R4.5). A configured cap larger
  than RAM is reported as configured; the reserve of D13 still bites first.
  The mount listing (D10) reports each mount's bytes in use, entry count
  and cap.
- R4.9 **(decided)** memfs's primitive `read` and `write` calls are bounded
  to a single 4 KiB filesystem block, including unaligned slices that fit
  within that block. Reject a slice crossing a block boundary with
  `InvalidArgument`; check offset/length arithmetic before any mutation.
  A block-bounded write writes the complete slice or returns an error
  without modifying the file (R4.13). Reads may return fewer bytes at EOF.
  sys-io chunks multi-block I/O; copy implementations also use these
  block-bounded primitives. No cross-block primitive support is required
  in iteration 1.
- R4.10 Rust-first, std only plus `src/sys/lib` crates; no new external
  dependencies beyond what sys-io already pulls. Dev-dependencies for the
  host tests are fine, motor-fs included: one trait-level test sequence
  can then run against both filesystems and compare their answers.
- R4.11 **(stated)** memfs supports sparse files. Growing a
  file updates its logical size without allocating data or index entries
  for holes. A small write at a large offset allocates only the touched
  blocks and their index entries; all intervening bytes read as zero.
  Logical size can exceed `max_size`. Offsets, sizes and end positions
  use checked arithmetic and the existing API's representable limits.
- R4.12 Reused pages, holes, and bytes exposed after shrink/regrow read as
  zero unless written. Shrink/delete visit allocated entries rather than
  iterating through holes. Their work can scale with allocated blocks,
  but they must not require a growing temporary collection or cache
  allocation to release memory. Returning pages to the kernel is always
  allowed instead of expanding cache bookkeeping.
- R4.13 **(decided)** Create, delete, rename and mode changes leave the
  namespace unchanged on a returned error. Each block-bounded write is
  atomic: on error, file bytes, logical size and quota usage are unchanged,
  with no leaked pages or charges. The classic single-page `CMD_WRITE`
  response carries status only, so it must never report a short success.
  Multi-block write requests and copies may commit a prefix of complete
  chunks: a later failure returns the successful byte count, or the error
  if no bytes completed. There is no whole-IPC-write rollback requirement.
  Copies may materialize holes; preserving sparse extents during copy is
  deferred.

### R5. Security

- R5.1 **(decided)** In iteration 1, mounting is image-controlled: the
  mount table comes from `/system/cfg`, which is System-writable only, so
  Interactive and None cannot alter it. A later iteration gives
  Interactive users runtime mount and unmount commands (decision 15,
  D14). Motor OS has no privilege escalation, so those commands will be
  gated by the caller's own role and capabilities, never by acting as
  System. Iteration 1 keeps that open: the mount step takes the acting
  role as a parameter (System at boot) and returns errors instead of
  panicking (R2.3).
- R5.2 All inputs that cross the client boundary (entry ids, paths, names,
  offsets, lengths) are validated per mount exactly as they are today for
  motor-fs. A wire id is decoded before mount and local-id validation;
  decoding itself does not authenticate it. Unknown or stale decoded
  identities fail validation; a valid identity still needs the caller's
  usual permissions. Only AES mode provides D1's computational protection
  against guessing unissued IDs; the XOR fallback is an explicitly weaker
  compatibility mode, not an authorization boundary. Ids coming back
  from a filesystem are checked too, and a bad one disables its mount
  rather than sys-io (decision 16).
- R5.3 The role model is preserved end to end: the role comes from the
  connection's kernel-reported capabilities, `CAP_FS_WRITE` still gates
  mutations in sys-io before dispatch, and every mounted filesystem
  enforces per-role permissions (R4.3).
- R5.4 Resource bounds on everything a client can grow: name and path
  lengths (existing `MAX_PATH_LEN`, `MAX_FILENAME_LEN`), the cross-mount
  copy bounce buffer (D5), the config file size, and, for memfs, the cap
  (configured or derived), the bounded free-block cache, the reserve and
  the memory-pressure handling of D13.
- R5.5 `/none/tmp` keeps its `rwxrwxrwx` policy mode as the memfs root
  mode (R4.4). The permission tests in `full-test.sh` keep passing; in
  particular the harness's rule that it creates the test directories
  first, so that None cannot write them, relies on sys-io's default modes
  being the same on memfs. What None may do in `/none` itself is policy
  outside this work and is neither required nor tested here.
- R5.6 Memory as the shared resource. Any process that may
  write `/none/tmp`, including a None-role one, can grow memfs up to its
  cap, or until the guest's free-for-admission memory falls to the
  reserve (16 MiB; 8 MiB on a guest under 32 MiB, decision 12), whichever
  comes first; allocating requests then undergo reclamation and admission
  again (D13), returning `StorageFull` if the reserve check still fails.
  The kernel's pressure flag at 2 MiB is a backstop. The intended result
  is continued service. For iteration 1, the protection is accepted under
  decision 12, with the bounded smoke checks of D12. Defining a stronger
  service workload and proving headroom against concurrent consumers are
  deferred until iteration 1 is complete (R8.5, D15). Today the same
  process can only fill the 256 MB data partition. memfs memory is
  reclaimed by deleting or shrinking its entries by already-held IDs
  under pressure (D13), returning pages to the bounded free-block cache and
  past it to the kernel at once (D7), or by rebooting; under pressure
  such freeing requests return their released data pages to the kernel
  (D13). Pathname cleanup can still be refused at lookup while the flag
  remains set; reclaim-on-admission does not by itself change that API.
  A process exiting frees its own pages but nothing in memfs. This
  iteration's acceptance assumption does not assert a universal OOM
  guarantee (R4.5).

### R6. Performance and boot time

- R6.1 Boot work is limited to the small config lookup/read, resolving
  configured mount points and reading their metadata, creating empty
  filesystems, and constant-size wire-codec initialization, including one
  CPUID feature check at sys-io startup (D1). Path
  lookups can cause device reads; do not claim zero extra I/O beyond the
  config read. No filesystem scans, new threads, or work proportional to
  RAM size; cap calculations use the cached `guest_ram_mib()`.
- R6.2 Dispatch overhead is bounded and allocation-free: a wire-id
  permutation on entry/exit, extracting the internal mount id, a `RefCell`
  borrow of the mount table (a non-atomic counter, D2), a lookup by mount id, the
  corrupted flag, and the shadowed-id check (one comparison per mount);
  no allocation. The table is a vector searched linearly, because Motor
  OS deployments are expected to have few mounts; every lookup goes
  through `MountTable` methods and nothing outside the table knows the
  representation, so sys-io can switch to a sorted vector or a map if a
  deployment ever has many mounts (D2). Measure both codecs' dispatch cost;
  CPUID, random-seed generation and AES key setup run only at startup.
- R6.3 memfs requests do not wait behind root-filesystem block I/O: the
  lock is per mount (D6).
- R6.4 memfs data path cost is a memcpy per 4 KiB chunk plus sparse-index
  bookkeeping (and zero initialization where needed);
  no block cache, no transaction log, and no readahead tasks. An allocating
  memfs request additionally costs one `AdmissionStats` syscall for the
  reserve check (D13) and one page-mapping syscall per newly allocated
  4 KiB block that the free-block cache cannot serve (D7). An aligned 32 KiB write needs
  up to eight data-page allocations; sparse-index and other metadata
  allocations are additional costs, so nine is not a total syscall bound.
  Rigorous headroom accounting for those allocations is deferred (R8.5).
- R6.5 Memory shift: data the gate writes into `/none/tmp` now lives in
  RAM instead of on disk, about 30 MB for a debug run (Background table).
  Negligible in the default 1024 MiB guest; about 12% of a 256 MiB guest.
  After deletions memfs keeps up to its free-block cache cap resident
  (51 MiB in a 1024 MiB guest, 16 MiB in a 256 MiB one, D7) until sys-io
  empties the cache under pressure. A running memfs executable costs its
  size twice, once in memfs and once in the process's pages (D4).

### R7. Observability

- R7.1 **(decided)** The active mount table is available through the
  read-only API of D10. A sysbox listing command is deferred. The API is
  intentionally global for every role, including paths the caller cannot
  traverse; this discloses topology and usage, not file access.
- R7.2 `FS_CAPACITY_BYTES` / `FS_AVAILABLE_BYTES` keep describing the data
  partition and are documented as such; the listing shows each mount's
  bytes in use and its cap, so a disk budget and a RAM budget are never
  mixed.
- R7.3 Boot logs name each applied mount and each rejected config entry.
  A mount that sys-io marks corrupted (decision 16) gets one error line
  naming the mount, its path and the offending id, and the listing shows
  it as corrupted from then on.
- R7.4 **(decided)** sys-io exports statistics per mount: bytes in use,
  entry count and cap, in the listing (D10). The stats responder gains
  memfs totals (bytes in use, entries, cached free bytes) and the reserve
  refusal counter (D13); per-mount entries in the responder are not
  added, because a `MetricEntry` scope means a PID today (Q17).

### R8. Compatibility and non-goals

- R8.1 No compatibility machinery: as with process roles, new code ships
  with a complete new image. Protocol changes need no versioning.
- R8.2 Non-goals for iteration 1: bind mounts, persistence of memfs
  contents, quotas per role within a memfs, mounting over `/user/tmp` or
  `/system/tmp`, hole-preserving copies, and all sysbox changes (including
  mount listing, copy/move command behavior and their acceptance tests).
  Nested mounts, read-only mounts, runtime mount and
  unmount, a second block device, multiple Motor FS partitions per device
  and virtio-fs are later iterations, not non-goals (R1.5, D14).
- R8.3 **(decided)** Existing tests, scripts and tools that use
  `/user/tmp` are untouched.
- R8.4 Existing users of `/none/tmp` (the test harness, systest, the wasm
  and javy suites, Lorry, None-role `TMPDIR` consumers) are expected to
  keep working without changes, but that is an expectation, not a
  requirement: a test that needs changing is changed. The observable
  differences are that `/none/tmp` is empty after every boot, that it is
  bounded by its cap and by memory rather than by the data partition, and
  that a rename between it and the rest of the tree now fails with
  `CrossesDevices`; `docs/fs-permissions.md` gets a sentence saying so.
- R8.5 **(stated, tenth pass)** Rigorous OOM protection is deferred for
  iteration 1. Accept the 16 MiB reserve plus sparse files, with 8 MiB on
  guests under 32 MiB and the admission/reclamation rules of D13. This
  deferral ends automatically when iteration 1 is complete: the OOM issue
  becomes active design scope again for subsequent iterations, without
  requiring a new user request. D15 records the follow-up questions;
  iteration-1 completion must carry them forward as open work, not mark
  them resolved by the reserve assumption or by passing smoke tests.

### R9. Testing

- R9.1 memfs gets host-run unit tests in its own crate, like motor-fs's
  `tests.rs`: it is library code, not kernel code, so host tests are
  appropriate. They cover cap enforcement, atomic block-bounded writes
  on returned errors, rejection of cross-block primitive requests,
  partial progress across complete copy chunks, no charge for sparse
  growth/holes, distant-offset writes, overflow rejection, zero-filled
  holes and shrink/regrow, and the metadata/name/index charges of D7.
  They also cover the
  block store's accounting of allocated, cached and freed pages,
  including the cache cap and `release_free_blocks` (D7).
- R9.2 In-VM integration tests in `src/tests/full-test.sh` (directly or via
  `systest`): after boot `/none/tmp` is served by memfs (the listing
  names its mount and the derived cap of R4.5); wire IDs are opaque, so
  tests do not extract mount bits from `FileAttr.entry_id`. Its ID agrees
  across path lookup, component lookup and enumeration, and it is
  empty; shadowing (the marker file shipped in the image's `/none/tmp` is
  invisible by path and by enumeration); None can create and list entries
  in `/none/tmp`; cross-mount copy between `/user/tmp` and `/none/tmp`
  works in both directions; `std::fs::rename` across the boundary fails
  with `ErrorKind::CrossesDevices` for files and directories, without
  copying or deleting anything.
  File locks work on memfs;
  `std::fs::remove_dir("/none/tmp")`, `std::fs::rename("/none/tmp",
  "/none/x")` and `std::fs::rename("/none/tmp", "/user/x")` fail with
  `PermissionDenied` and leave the contents intact; a replacement onto a
  mount root returns `NotAllowed` before `CrossesDevices`.
  `remove_dir_all` on a
  subtree of `/none/tmp` works. The **memfs memory test** (decision 22)
  lives in systest and runs only when the memfs cap is at most 1 GiB,
  which is the default 1024 MiB test guest and the 256 MiB shape; on a
  larger guest it prints a skip notice. It is specified in D12. Spawning
  from memfs, `chmod` on memfs files and the role permission matrix are
  already exercised by the existing gate the moment the mount ships
  (Background). The config validator's error cases and the missing-file
  path are covered by sys-io's debug self-test, since no shipped image
  lacks the file. The corrupted-mount path is covered by the self-test
  only, using injected bad IDs: cover aliases, forwarding, internal users
  and flush as well as direct resolve. Listing tests cover pagination,
  unusual path characters and unknown statistics on corrupted mounts.
- R9.3 **(decided)** This is core OS work (`src/sys`). Individual patches
  are tested lightly: build, clippy, the crate's host tests, and the
  in-VM test the patch adds, if any. The full gate runs per milestone of
  the implementation plan: `src/tests/full-test.sh` in debug and release,
  three times each, for every milestone that changes shipped code, plus
  `src/tests/full-test-dev.sh --release` once for the larger milestones
  (the sys-io dispatch refactor and the patch that ships the config,
  because the developer and wasm images layer the same base tree). The
  toolchain milestone (plan steps 1 and 2) is gated as `docs/toolchain.md`
  §5 prescribes: three debug and three release runs plus one release
  developer-image run, on the new toolchain, before its declaration and
  selector are committed. Patches are kept to 100-300 lines including
  tests.
- R9.4 No new compiler or clippy warnings; `cargo fmt` from the repository
  toolchain.

## Design

The mechanisms below incorporate the accepted review recommendations.
D1 settles CPU-dependent codec selection. D15 records deferred work,
including the OOM review that reopens on iteration-1 completion.

### D1. Entry ids across mounts and opaque wire IDs (decided)

**Implementation status:** the wire codec, its shared `FsRuntime`
ownership, client-boundary conversions and debug codec self-tests landed
in `d3af1b66`. Motor FS input-ID validation landed separately in
`d6c0ad2a`; memfs's local counter-ID packing is implemented in `8dfe872f`.
The shared mount-layout constants, mount-id packing, mount-point
normalization and corruption quarantine remain planned (steps 7 and 10).

There are three identity forms: fs-local IDs, internal mount-qualified
IDs, and opaque wire IDs. Keep them distinct at call sites. An internal
ID is the fs-local id with a 24-bit **mount id** packed into clear bits.
For Motor FS the fs-local id is `block_no | (generation << 64)`; the
reserved bits are the top byte of the block-number word (bits 56..63 of
the `u128`) and the top two bytes of the generation word (bits 112..127).
The mount id's low 16 bits go to bits 112..127 and its high 8 bits to
bits 56..63, so a counter fills the generation-word fragment first and
touches the block-number byte only past 65,535 mounts. The two fragments
are a packing detail: `split` and `join` are the only code that knows the
layout. Locks, executable locks and pager mappings use canonical internal
IDs. Clients receive only wire IDs, including in `FileAttr.entry_id`.

**Startup selection.** Before serving clients, sys-io checks the guest's
CPUID leaf 1, ECX bit 25 ([Intel AES-NI reference](https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf)).
If set, select AES-128 using standard Rust `core::arch::x86_64` AES
intrinsics. Keep AES-specific instructions, including key expansion, in
functions enabled for the `aes` target feature and call them only after
this check; do not require AES globally for the binary. Rust documents
this runtime-dispatch pattern in [`core::arch`](https://doc.rust-lang.org/core/arch/).
If clear, log one warning that entry IDs use weak XOR obfuscation and
select the fallback below. No software AES or new external dependency is
required (R4.10). The selected codec and its random key/seed stay fixed for
the boot; requests do not repeat CPUID or choose their own codec.

**AES mode.** AES is a reversible cipher
on 128-bit blocks ([FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)).
Generate a secret 128-bit key `K` once per boot with the existing
`moto_rt::fill_random_bytes`; never use the public `boot_random_id` as a
key. Precompute the key schedules and `mask = AES_K(0)`. Convert `u128`
values to/from AES blocks in little-endian byte order:

```text
encode_wire(internal) = AES_K(internal) XOR mask
decode_wire(wire)     = AES_inverse_K(wire XOR mask)
```

The formulas are inverses; `encode_wire(0) = 0`, and injectivity ensures
no other ID maps to 0.

This construction relies on AES's pseudorandom-permutation assumption.
In the ideal-permutation model, guessing any of `H` unissued hidden IDs
in `q` attempts has probability approximately `q * H / 2^128` when the
observed/query counts are small relative to the domain. This bound applies
only to AES mode.

**XOR fallback (accepted compatibility tradeoff).** Generate a random
nonzero `u128` seed `S` per boot using `moto_rt::fill_random_bytes`. Use
the same function for encoding and decoding:

```text
xor_codec(x) = x          if x == 0 or x == S
               x XOR S   otherwise
```

Plain XOR swaps `0` and `S`; this adjustment leaves those two values fixed
and keeps every other XOR pair. It is a bijection and its own inverse:
`0` remains `0`, no nonzero ID becomes `0`, and no collision or retry is
needed per ID. Special-casing only input zero would be incorrect, because
input `S` would still map to zero.

This fallback does not make unissued IDs computationally unguessable. For
an ordinary known internal/wire pair, `S = internal XOR wire`; XOR also
preserves differences between ordinary pairs. The listing reveals mount
IDs, from which clients can construct non-root mounts' internal root IDs;
lookup returns the corresponding wire IDs. Thus seed recovery is practical.
The zero adjustment does not repair it. The startup warning must make the
weaker protection clear without logging the seed. Clients retain the
same permission checks, but direct-ID hiding of shadowed descendants is
not a security guarantee on guests without AES-NI (R3.1, R5.2).

**Common codec rules.** Both modes are allocation-free per ID, without a
per-entry table. Encode after mount-point normalization; decode exactly
once at client ingress, before internal routing. Internal walks and pager
calls do not encode/decode each intermediate ID. Keep key schedules,
masks and seeds private to sys-io, with no logging or client-visible
state. Neither codec authenticates an ID: every wire value decodes, known
IDs remain usable, and all existing permission and identity checks still
apply. Neither revokes IDs issued before a future runtime mount or
guarantees deterministic rejection of IDs from another boot.

Invariants:

- Every `FileSystem` implementation produces ids with bits 56..63 and
  112..127 clear. Motor FS does so by the construction of its on-disk
  format, a filesystem of up to 2^56 blocks (256 EiB at 4 KiB blocks) and
  2^48 generations: since commit `4527c75b` a generation is consumed only
  for a new directory entry, so at a sustained 1000 entries per second
  the generation limit is 8,900 years away, and no guest has a 256 EiB
  partition. memfs guarantees both by construction (D7). A future adapter
  whose backend hands out arbitrary 64-bit ids (virtio-fs, D14) keeps its
  own id table.
- **sys-io checks, it does not assert** (decision 16). `check_local(mount,
  local)` tests the 24 reserved bits of every id a filesystem returns. It
  covers `export`, path walks and internal filesystem users; client IDs
  instead go through `resolve` and ordinary identity validation. An
  invalid client ID does not mark a mount corrupted. A set reserved bit
  in a filesystem-produced ID means the filesystem has broken the
  invariant and nothing it says can be trusted
  any more: sys-io logs an error naming the mount id, its kind, its path
  and the id, sets the mount's `corrupted` flag under a short table
  borrow (D2), and fails the request with `InvalidData`. From then on
  the common mount-access gate fails subsequent calls on that mount with
  `InvalidData`, including aliases, forwarded operations, pager requests
  and internal mount-0 users. Recheck state after awaiting the mount lock,
  before calling the filesystem; an earlier `resolve` is insufficient.
  The listing shows it as corrupted with unknown usage (D10), `CMD_FLUSH`
  skips it and reports `InvalidData`, and a process demand-paged from it
  dies at its next fault, as any process
  whose fill fails does today. Mount 0 is not special: a corrupted root
  filesystem prevents access through mount 0; already-known IDs on healthy
  mounts remain usable. sys-io keeps running, and the log line says why;
  a reboot is the remedy. There is no error path, no assert and no test
  for the Motor FS limits themselves,
  in motor-fs or anywhere else: this check is the single guard (Q22). The
  self-test covers `check_local` and the flag (D12).
- The planned constants belong in `async-fs` (`MAX_FS_BLOCKS = 1 << 56`,
  `MAX_FS_GENERATIONS = 1 << 48`, with the mount-id layout documented
  beside them). They were not part of the shared-helper extraction;
  add them with mount routing in step 7 so memfs and sys-io share the
  definition. They do not add Motor FS format-limit checks (decision 16).
- The mount id is a per-boot counter. The root filesystem is mount 0, so
  its internal ids retain today's layout and the wire `ROOT_ID` (0)
  still names the root of the root filesystem. Every later
  mount, at boot or at runtime, takes the next value; a value is never
  reused within a boot, so an id of an unmounted filesystem can never
  name another one in that boot (D14). Mount N's internal root is
  `join(N, ROOT_ID)` and its wire root is the encoding of that value.
  When the counter would exceed 2^24 - 1 the mount is refused with `StorageFull`
  (decision 16): 16.7 million mount operations per boot, 194 days at one
  per second. This is an error and not a panic because a runtime mount
  command makes it client-driven.
- After wire decoding, sys-io splits the internal id, finds the mount by
  id, and rejects an id with no mount (`InvalidArgument`, the same code motor-fs uses for a
  stale id) or a corrupted mount (`InvalidData`). The fs-local id then
  goes through the filesystem's own validation, unchanged from today.

Helpers in `runtime::fs` (names illustrative):

```rust
type MountId = u32;                       // 24 bits used
fn split(id: EntryId) -> (MountId, EntryId);   // (mount id, fs-local id)
fn join(mount: MountId, local: EntryId) -> EntryId;
fn check_local(mount: MountId, local: EntryId) -> Result<EntryId>; // decision 16
```

`split`/`join` operate only on internal IDs; the wire codec wraps the
protocol boundary. `FsRuntime` owns the shared codec, initialized before
listeners, without adding a static. Its mode and key/seed stay fixed for
the boot.

### D2. Mount table (decided)

```rust
struct Mount {
    id: MountId,                      // the per-boot counter value (D1)
    fs: Rc<LocalRwLock<FS>>,          // FS::MotorFs(..) | FS::MemFs(..)
    kind: MountKind,                  // for the listing and the logs
    parent: Option<MountPoint>,       // None for the root filesystem
    corrupted: bool,                  // set once, never cleared (decision 16)
}

struct MountPoint {
    mount: MountId,       // the parent filesystem's id (any mount, D14)
    shadowed: EntryId,    // fs-local id of the shadowed directory there
    path: String,         // the configured path, for the listing
}

struct MountTable {
    mounts: Vec<Mount>,   // private; the root (id 0) is first
    next_id: MountId,     // the counter; never decremented
}

impl MountTable {
    fn find(&self, id: MountId) -> Option<&Mount>;
    /// The mount whose mount point is `(parent, shadowed)`, if any (D3).
    fn find_by_mount_point(&self, parent: MountId, shadowed: EntryId) -> Option<&Mount>;
    fn iter(&self) -> impl Iterator<Item = &Mount>;     // table order
    fn insert(&mut self, ..) -> Result<MountId>;        // takes the next id
    fn mark_corrupted(&mut self, id: MountId);          // decision 16
}
```

**All mount lookups go through these methods**; nothing else touches
`mounts`, which a review of each patch checks. Today a lookup is a linear
search of the vector: with one or a few mounts that is faster than any map
and has nothing to tune, and the root is matched on the first comparison.
Because the representation is private, sys-io can later switch to a
sorted vector or a map, or switch at a threshold, without touching a
handler. Unmount removes the element; the ids of the remaining mounts do
not change because they are values, not positions.

In iteration 1 the table is built in `fs::init` before the listeners
start and changes afterwards only by `mark_corrupted` (R1.4). It is held
as `Rc<RefCell<MountTable>>` in `FsRuntime` (which is a struct of `Rc`s
cloned into every task): `resolve` and `export`
take a borrow, copy out what the handler needs (the mount id, the
fs-local id and a clone of the mount's `Rc<LocalRwLock<FS>>`), and
release it; `mark_corrupted` takes a mutable borrow for the one store.
The rule is that **a table borrow is never held across an await**, which
avoids borrow conflicts while another task runs. The cost is a
non-atomic counter per request (R6.2).
`FsRuntime.fs` becomes `FsRuntime.mounts`, and every `runtime.fs.read()`
/ `.write()` call site becomes "resolve the id, then lock that mount".
`resolve` maps an entry ID to a mount; explicit internal mount-0 access
and forwarding use the same corruption gate. No internal user retains an
unguarded filesystem access path. `MountKind` is an enum (`MotorFs`,
`MemFs`) that D14's later kinds extend.

### D3. Resolving mount points (decided)

Two internal normalizations make R3.3 hold; D1's codec surrounds them:

- **Input.** `resolve(internal_id) -> (mount, local)`: split the id, find the
  mount (`InvalidArgument` if none, `InvalidData` if corrupted), then, if
  `find_by_mount_point(mount, local)` names a mount, replace the pair
  with `(that mount, ROOT_ID)`, checking that mount's state too. A client
  holding the shadowed directory's wire ID reaches the mounted root.
  This aliases that directory alone, not its descendants (R3.1).
- **Output.** `export(mount, local) -> internal_id`: `check_local` (D1), then
  the inverse check, so a `CMD_STAT`, `CMD_STAT_PATH`,
  `CMD_GET_FIRST_ENTRY` or `CMD_GET_NEXT_ENTRY` result that names a
  shadowed directory comes back as the mount's internal root id. Encode
  that result only when sending it to a client. Check both the originating
  and aliased mount's corruption state before returning an ID.

The shadowed-id comparisons are one per mount (R6.2).

Per-command consequences for a mount root `(N, ROOT_ID)` with `N != 0`:

- `CMD_STAT_PATH` walks component by component as today; after every hop
  it applies the output check and continues inside the new mount. For
  `/none/tmp/motor-tests/tests/systest` the walk does `none` and `tmp` on
  mount 0, exports `tmp` as mount 1's root, and finishes on mount 1. It
  holds only the current mount's read lock, dropped before switching (D6).
  The same walk resolves mount points at boot (D9), which is what makes
  a nested mount point land on its parent mount (decision 18).
- `CMD_GET_NEXT_ENTRY` asks for the *next sibling* of an entry, which for a
  mount root is a question about the parent directory: sys-io forwards it
  to the parent mount with the shadowed id, then exports the answer (the
  next sibling may itself be a mount point). Forwarding checks the parent
  mount's corruption state through the common access gate.
- `CMD_GET_NAME` forwards to the parent mount with the shadowed id (the
  mount point's leaf name); `CMD_METADATA` goes to the mounted filesystem's
  root. `ls -l /none` therefore shows the mount's own metadata under the
  name `tmp`.
- `CMD_DELETE_ENTRY`, `CMD_MOVE_ENTRY` and `CMD_MOVE_NOREPLACE` with a
  mount root as the subject, and a replacing `CMD_MOVE_ENTRY` whose
  existing destination is a mount root, are refused with `NotAllowed`
  (decision 19). A mount root is a resolved pair `(N, ROOT_ID)` with
  `N != 0`, which is also what the shadowed directory's id resolves to.
  After resolving the input IDs, check the subject; for a replacing move,
  look up and check the existing destination under its parent's lock
  before considering `CrossesDevices`. Release that lock before any
  cross-mount dispatch. Same-mount moves keep or revalidate the destination
  under the mutation lock. Thus destination protection has the same error
  precedence as source protection, without holding two mount locks.
  Ancestors of a mount point are not protected: the mount point is keyed
  by the shadowed id, so renaming `/none` moves the mount with it and the
  listing keeps showing the configured path (D10).
  `std::fs::remove_dir_all("/none/tmp")` still
  empties the memfs and then fails on the root with `PermissionDenied`,
  like a busy mount point elsewhere.
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

### D4. Request dispatch, executable locks and the pager (decided; the lock and pager semantics are decision 7)

`on_msg` keeps its capability and pressure gates (D13 refines the latter).
Handlers decode client IDs, then resolve and canonicalize the internal
identity before taking the mount lock. Reserve reclamation happens before
holding a filesystem lock (D13). Internal callers skip wire decoding. The
`FS` enum gains `MemFs(memfs::MemFs)`; the enum dispatch stays (no `dyn`).
Both single-page and multi-page read paths skip readahead scheduling for
memfs before creating a task or taking a lock for prefetch. A no-op
`prefetch` inside an already-created task is insufficient. Motor FS keeps
its existing readahead behavior; memfs has no block-cache statistics.

The lock manager, the executable locks and the pager key their state by
the *canonical internal* id, so a shadowed id and the mount root it aliases
can never hold two locks, and a memfs executable is locked against write, resize,
delete, move, replacement and permission change for as long as a
construction or a mapping references it, by the code that does it today.

The pager's fault path is unchanged: `PageBuf` → `read_range` →
`read_exact_at` → `FS::read`, now through the executable's resolved mount;
memfs serves those block reads from its own blocks, so the process gets a
private copy of each page, as it does from the block cache. Sharing memfs
blocks with the process instead would need kernel support for mapping
sys-io memory into another process and could never cover relocated pages;
it is recorded here as a later optimization and not designed.

### D5. Cross-mount operations (decided; the error code is decision 6)

- `CMD_MOVE_ENTRY` and `CMD_MOVE_NOREPLACE` with the entry's mount
  different from the new parent's mount return
  `moto_rt::Error::CrossesDevices`. Nothing is moved. The check comes after
  `resolve` of both IDs and the source/destination protection checks of
  D3, including the destination lookup when replacing. It precedes any
  mutation, not necessarily every lock acquisition.
- `CMD_COPY_FILE_RANGE` with different mounts copies through a bounce
  buffer inside sys-io: read block-aligned chunks from the source under its
  read lock, drop it, write them to the destination under its write lock.
  `size` is capped per request at `WRITE_MAX_BYTES` (32 KiB), for both
  same-mount and cross-mount copies; the client already loops over short
  successful counts. This bounds allocations even if a sparse source has
  an enormous logical length. Chunks respect both block boundaries;
  account for unaligned endpoints when bounding touched pages. Executable
  locks apply to the destination as today. A copy need not preserve holes:
  zero-filled source ranges may become allocated destination blocks, so
  an otherwise sparse source may exhaust the destination cap. The request
  never removes the source. No sysbox changes are needed for this data path.
- `CMD_FLUSH` flushes mounts in table order, each under its own write
  lock, skipping corrupted ones (D1). Attempt all healthy mounts even if
  one fails. Return `InvalidData` if any mount was skipped as corrupted;
  otherwise return the first flush error, or success if all succeeded.

### D6. Locking (decided)

One `LocalRwLock<FS>` per mount. The single rule: **a task never holds two
mount locks at once**. `CMD_STAT_PATH` drops the lock before crossing a
mount boundary; cross-mount copy and move validation acquire their mount
locks sequentially. A table borrow never spans an await. The lock is fair,
but fairness alone does not define safe runtime unmount: admission, busy
checks and in-flight requests need a later lifecycle design (D14).

### D7. memfs (sparse files and allocated-storage accounting)

**Implementation status:** the standalone library and its ten tests landed
in `8dfe872f`. It implements all `async_fs::FileSystem` methods, with a
public `<method>_sync` counterpart for each async method; `num_blocks`
remains synchronous. The async adapters delegate directly without awaiting,
spawning tasks or taking async locks. Mounting, RAM-derived defaults,
pressure admission, paging integration and published metrics remain sys-io
work.

The crate `src/sys/lib/memfs` uses std, depending on `async-fs` and
`async-trait`, and on `moto-sys` for the block store on Motor OS only
(the `cfg(target_os = "motor")` dependency pattern `async-fs` and
`motor-fs` already use). memfs knows nothing about RAM or memory
pressure: sys-io computes its cap and its cache cap and passes them in.

- **Ids.** A per-filesystem `u64` counter that never repeats: each new
  entry takes the next value, and the entries live in a
  `BTreeMap<u64, Entry>`. A stale or forged id is simply absent from the
  map and fails with `InvalidArgument`, as a stale Motor FS id does. No
  slab, no free list, no per-slot generation. The fs-local `EntryId` is
  the counter with its low 56 bits in the low word and its top byte at
  bits 64..71, so bits 56..63 and 112..127 are clear by construction (D1);
  the conversion and its inverse are the only code that knows this, and
  the inverse rejects an id with any other bit set. The root is entry 0,
  so the protocol's `ROOT_ID` needs no mapping. At 1000 creations per
  second the counter reaches 2^56 after 2.3 million years, so the split
  is a formality that keeps the invariant exact.
- **Entries.** `Metadata` (the shared 128-byte record, so permissions and
  timestamps are the same type motor-fs stores), the leaf name, the parent
  id, and either file data or a directory. A directory's children are a
  `BTreeMap<Rc<str>, u64>`, sharing each name with its entry: lookup by
  name is `O(log n)`, and `get_first_entry` / `get_next_entry` enumerate in
  name order. These maps and name strings are charged as metadata under
  the capacity rule below. Ordinary collection allocations are permitted under iteration
  1's accepted reserve assumption; rigorous fallibility/residency treatment
  returns to scope on completion of that iteration (R8.5, D15).
- **Sparse file data.** Store logical size separately from an ordered
  map of allocated 4 KiB blocks keyed by block index, conceptually
  `BTreeMap<u64, Block>`. There is no vector sized by logical length and
  no index node for a hole. `set_len(1 TiB)` on an empty file allocates
  no file-data/index blocks, even with a 64 MiB data cap. Writing one
  byte near that end allocates one data block plus bounded index growth.
  Reads synthesize zeroes for absent blocks, stopping at logical EOF.
  A grow-only resize changes metadata, without allocation or precharging
  a later write. Shrink removes only present blocks beyond the new EOF,
  and zeroes the discarded tail of a retained last block. Cached blocks
  are cleared before reuse, so unwritten bytes cannot disclose another
  file's contents. Reads/writes still obey the block contract (R4.9).
  Check offset/length arithmetic before mutation. The rigorous headroom
  bound for tree splits and name/entry creation is deferred (D15).
- **Block store.** Data blocks do not come from the global allocator. On
  Motor OS the global allocator is frusa, which serves 4 KiB allocations
  from slab batches of up to 256 KiB and returns a batch to the kernel only
  when it is entirely free and the 5-second reclaim pass runs (Background);
  a memfs that deleted most of its files could keep most of its memory
  resident until allocator reclamation despite its file usage falling.
  Instead a `Block` is one page obtained with
  `SysMem::alloc(PAGE_SIZE_SMALL, 1)` and
  released with `SysMem::free`: the kernel admits it at once, sees it freed
  at once, and the allocation is fallible by construction (a refused page
  is `StorageFull` to the client). The store keeps a **free-block cache**
  (decision 17): a freed block goes into the cache while the cache is
  below its cap and back to the kernel otherwise, and an allocation takes
  a cached block before asking the kernel. `release_free_blocks()`
  returns every cached block to the kernel without allocating temporary
  storage; admitting a freed block into the cache must not require a new
  allocation. The implemented cache stores its links in the free pages
  themselves. `MemFs::free_block_cache()` returns an independently owned,
  cloneable `FreeBlockCache` handle backed by `Rc<RefCell<..>>`; sys-io
  will retain it so admission can drain free pages without locking the
  filesystem (D13). Entries and live file data are not reference-counted.
  sys-io will compute the cache cap from `guest_ram_mib()`, the same figure
  the block cache and the TCP buffers use, with no further adjustment
  (Background): the larger of 16 MiB and
  5% of RAM on guests of 256 MiB and up (`SMALL_GUEST_MIB`), 8 MiB on
  [128, 256) MiB, 4 MiB on [64, 128) MiB, 2 MiB below 64 MiB. On the
  host, a `Block` uses fallible `alloc_zeroed` with 4 KiB alignment and
  matching `dealloc`; tests set their own cache cap. The cost on Motor OS
  is one syscall per block the cache cannot serve (R6.4); allocating blocks
  in larger runs is a later optimization if that ever shows.
- **Capacity.** `MemFs::new(MemFsConfig { max_size, free_cache_cap,
  root_mode })`. The file-data charge is exactly
  `4096 * allocated_data_blocks`; logical size and holes contribute zero.
  Grow-only resize does not change that charge; writes charge newly
  allocated blocks once, and shrink/delete remove their charge when the
  blocks leave the file. Cached free blocks are not file usage: they
  count against memory and the cache cap, not the file-data charge.
  `max_size` includes metadata charges as well: an entry/root charge,
  stored-name byte length (charged once for the shared name), and a charge
  for each allocated sparse-index/directory-map entry, allowing for tree
  node overhead. Charge before publishing the corresponding storage;
  release its charge on removal. The implemented conservative charges are
  512 bytes per entry (including the root and name's `Rc` header), 128
  per directory link and 64 per sparse-index slot, plus data and name
  bytes. These constants are documented and tested.
  An empty-file workload must eventually reach the cap. Exact allocator
  slab residency and transient growth are part of D15's deferred OOM
  review, not a claim made by `used_bytes()`. The constructor rejects a
  cap too small for its root metadata.
  Namespace changes and block-bounded writes are atomic on returned errors.
  For a write, reserve the entire chunk's quota and obtain any new data
  page before modifying file bytes or logical size; unwind provisional
  pages and charges on error. The primitive returns the full slice length
  on success, never a short write. Multi-block write requests and copies
  may commit a prefix of complete chunks (R4.13); whole-message rollback
  is not required.
  `used_bytes()`, `entry_count()`, `cached_free_bytes()` and `max_size()`
  feed the listing and the stats (D10); the trait's `num_blocks` /
  `empty_blocks` report the cap and the remainder (R4.8). sys-io derives
  `max_size` when the config sets none (decision 5): with `ram` the
  `guest_ram_mib()` figure in bytes, `max(8 MiB, (ram & !(2^24 - 1)) -
  2^24)`, that is RAM rounded down to a multiple of 16 MiB, minus 16 MiB,
  and at least 8 MiB; the subtraction saturates, so a guest under 32 MiB
  gets the 8 MiB floor and, with it, the 8 MiB reserve of D13 (Q21).
- **Permissions.** Shared code, not a copy: `Need` and the pure
  `check_access(metadata, role, need)` moved from `motor-fs/src/fs.rs` to
  `async-fs` in `c4b688a5`; `MAX_FILENAME_LEN` and `validate_filename`
  moved alongside, and `may_set` / `perms_monotonic` were already there.
  memfs applies them at the insertion points PERMISSIONS_DESIGN.md §5 lists:
  `x` on the parent for `stat` and enumeration, `w` on the parent for
  create, delete, move (both parents) and mode changes, `r`/`w` on the file
  for read/write/resize, System-only for the root's mode.
- **Root mode.** sys-io passes the shadowed directory's mode read at mount
  time (`rwxrwxrwx` for `/none/tmp`), or the configured one.
- **Timestamps.** `Timestamp::now()` on create, write, resize, rename.
- **Tests.** Ten shared host/native tests cover every trait method, the
  capacity accounting (R9.1), the block store's page counts across write,
  truncate, delete and `release_free_blocks`, huge sparse growth with no index
  growth, distant writes, zeroing on cache reuse and shrink/regrow,
  stale/malformed-ID rejection, and the permission matrix for all three
  roles. A no-op waker polls each test future once and asserts readiness,
  also checking that memfs never yields. Host tests run transitively from
  `full-test.sh`; native Lorry validation exercises the Motor page
  allocator with the same suite. The optional motor-fs differential suite
  of R4.10 was not added.

### D8. Configuration file (decided)

```toml
# /system/cfg/sys-fs.toml. Mounts are applied in file order at boot.
[[mount]]
path = "/none/tmp"
type = "memfs"
# max_size = "64M"      # optional; absent means the RAM-derived default (decision 5)
# mode = "rwxrwxrwx"    # optional; the default is the shadowed directory's
```

Rules: `path` is absolute and canonical (no `.`, `..`, empty or trailing
components), within `MAX_PATH_LEN`, not `/`, and unique. Reject a path
that is a proper ancestor of an earlier entry's path, comparing whole
components: `/none/tmp` followed by `/none` would hide the first mount.
Entries are not reordered. A path may lie below an earlier entry's path:
each mount point is resolved through the mounts applied before it
(decision 18, D9), so nested mounts require parent-before-child order.
In iteration 1 a nested entry fails at mount time because a memfs is
empty at boot (R2.3). Reject paths at/below `/system/cfg` or above it,
comparing whole components:
`/system/cfg2` is not protected configuration. These checks run over the
whole file before applying any mount (R2.3). `type` is `memfs`;
unknown keys are rejected (`deny_unknown_fields`); at most 255 entries;
the file is at most 64 KiB. `max_size` accepts an integer byte count or a
`K`/`M`/`G` suffix for 2^10, 2^20 and 2^30 bytes; `mode` uses the
nine-character triplet notation of `docs/fs-permissions.md`. The loader
mirrors `net::config::load`: checked access to mount 0, block by block.
Parsing and static validation are pure functions returning errors;
neither panics. The debug self-test covers both (R9.2). Runtime validation
against a changing namespace is deferred with runtime mounts (D14).

The entry is deserialized as an enum tagged by `type`, so later filesystem
kinds can define their own configuration (D14). Unknown types are errors
today; their future device/partition selectors are not designed here.

### D9. Boot sequence (decided)

In `fs::init`, after the root MotorFs opens and before the pager and the
listeners start:

1. Build the table with mount 0.
2. Look up `/system/cfg/sys-fs.toml` on mount 0. Absent: done (R2.4).
3. Parse and validate the whole file (R2.3). Any error: log the entry and
   the reason, then panic, as `net::init` does for `sys-net.toml`.
   In particular, reject any later ancestor path before applying any mount,
   so boot cannot install a mount that hides an earlier one.
4. For each entry, `mount_one(table, entry, Role::System) -> Result<..>`:
   resolve the mount point path through the live table with the walk of
   D3, so a path inside an earlier mount lands on that mount (decision
   18). Require a directory, read its mode, create the filesystem (memfs
   with the cap, the cache cap and the root mode), append the `Mount`.
   The boot loader panics on `Err` with the same log line. Log one line
   per mount, including whether the shadowed directory is empty
   (information, not a warning: the shipped marker file of D12 makes it
   non-empty by design). At boot nothing else runs, so the table needs no
   concurrent-mutation protocol. Runtime mounting needs its own
   validation and lifecycle design (R1.7, D14).
5. Hand the table to `FsRuntime` as `Rc<RefCell<MountTable>>` (D2); the
   pager, the listeners and the stats responder start as today.
   `net::init` receives checked access to mount 0, including the common
   corruption gate, rather than an unguarded filesystem handle (R3.7).

Nothing can observe a partially built table.

### D10. Stats and the mount listing (decided)

`FS_CAPACITY_BYTES` / `FS_AVAILABLE_BYTES` keep reporting mount 0 and are
documented as the data partition. The listing is a new read-only command,
`CMD_GET_MOUNTS` (22), added to `is_read_command`. Requests carry a cursor;
each response carries at most one structured mount record and an explicit
next cursor or end marker. The path is length-prefixed and bounded by
`MAX_PATH_LEN`, so a record fits in one io page even when the full table
does not. Validate cursor and record lengths. `FsClient::mounts()` follows
the cursor until end; the boot-only topology makes iteration stable.
Dynamic-table enumeration semantics belong to the runtime-mount design.
The path in a record is the configured one: if a System-role process
renames an ancestor of a mount point, the mount follows the directory and
the listed path is stale until reboot (decision 19).

A record contains `id`, `type`, `path`, corruption status, and optional
`used`, `entries`, `cap` values. `used` is memfs's data-plus-metadata charge
or a Motor FS's allocated blocks times 4 KiB. `entries` is memfs's count;
Motor FS has no such superblock counter and reports unknown. `cap` is
memfs's configured/derived `max_size` or the partition size. For a
corrupted mount, numbers requiring filesystem access are unknown; do not
invent a last-known snapshot or call the quarantined filesystem. Read
healthy mounts under their individual read locks, rechecking corruption
after lock acquisition. Statistics are sampled, not a table-wide snapshot.

The API intentionally discloses all mount paths and usage to every
role, even when a path cannot be traversed (R7.1); this is an explicit
policy, not something justified by `ls` permissions. The sysbox command
and its output formatting are deferred (D15).

The stats responder gains four global metrics: `fs.memfs.used_bytes`,
`fs.memfs.entries` and `fs.memfs.cached_free_bytes`, summed over the
memfs mounts, and `fs.reserve_refused` (D13). Per-mount entries in the
responder are not added (Q17). If any memfs is corrupted, omit the memfs
totals rather than report partial or stale totals as complete. Likewise,
omit root-FS metrics requiring filesystem access if mount 0 is corrupted.

### D11. Changes outside `sys-io`

These are the supporting changes for memfs and sys-io (R1.6). The new
`moto-rt` error, its stdlib/mlibc mappings and the required toolchain update
are complete. sys-io's reverse mapping in `util::map_err_into_native`
also preserves `ErrorKind::CrossesDevices` as
`moto_rt::Error::CrossesDevices`, committed in `5c1e5749`. The remaining
server work is to produce that error for cross-mount moves (D5).
All sysbox work remains excluded.

Preparatory status (2026-10-20): moto-rt 0.17.9 is published (`f34023e0`).
Commit `5c1e5749` records the consumer pins/locks and toolchain selection.
Local consumer lockfiles and the Rust fork's root and library lockfiles now
select it; std's minimum dependency is also 0.17.9. The Rust mapping is
pushed in `c037341a5a5`, and the mlibc mapping in `52bed56c`. The toolchain
declaration now pins those commits and the Rust lockfile hashes. The host
toolchain with key `bea8b730277cb02938c947d5ed91c2e32f800e5b98f480c1e68d2f3de5b4ee12`
is built, registered and selected in `rust-toolchain.toml`. The matching
native assembly and all four release images are rebuilt. Six moto-rt
path-dependency lockfile updates are committed and pushed outside this
repository: `../javy` (`c496a4f`, two lockfiles) and `../wasmtime`
(`fda311d08c`, four).

| Crate / tree | Status | Change |
|---|---|---|
| `moto-rt` | Done | `Error::CrossesDevices = 24`, `E_CROSSES_DEVICES`, published version 0.17.9; all 17 tracked consumer lockfiles refreshed. |
| `../toolchain-src/rust` | Done, `c037341a5a5` | std maps `CrossesDevices`; its dependency and the root/library lockfiles select moto-rt 0.17.9. Committed and pushed on the fork. |
| `../toolchain-src/mlibc` | Done, `52bed56c` | `motor-util.hpp` maps code 24 to `EXDEV`. Committed and pushed on the fork. |
| this repository, toolchain declaration | Done, `5c1e5749` | Updated fork pins, lock hashes, selector and docs; rebuilt host toolchain and native assembly selected. |
| `async-fs`, shared checks | Done, `c4b688a5` | `Need`, `check_access`, `MAX_FILENAME_LEN` and `validate_filename` moved here. |
| `async-fs`, ID layout | Pending, step 7 | `MAX_FS_BLOCKS`, `MAX_FS_GENERATIONS` and the mount-id layout note. |
| `motor-fs` | Done, `d6c0ad2a`, `c4b688a5` | Validate incoming IDs and use the shared helpers; no checks/asserts for the theoretical format limits (decision 16, Q22). |
| `memfs` | Done, `8dfe872f` | Standalone filesystem, synchronous/async interfaces, sparse block store, free-block cache, quota accounting and shared host/native tests; host suite wired into `full-test.sh`. |
| `moto-sys-io` | Pending, step 13 | `CMD_GET_MOUNTS` and its bounded structured codec (D10). |
| `moto-io` | Pending, step 13 | `FsClient::mounts()` for native clients and integration tests. |
| `systest` | Pending, step 14 | The memfs memory test of D12 and other in-VM mount checks of R9.2. |
| `img_files/motor-os-base` | Pending, step 14 | `system/cfg/sys-fs.toml` and `none/tmp/.shadowed-by-memfs`; no YAML or policy change. |
| `docs/fs-permissions.md` | Pending, step 14 | Document `/none/tmp`'s volatility, cap/reserve and cross-mount rename error (R8.4). |
| sysbox, kernel, `rt.vdso`, Rust std behavior beyond the mapping, imager code | Outside scope | No changes for this iteration. |

All sysbox work is outside this iteration. D15 records the constraints
already agreed for a future cross-mount move design; no copy-plus-delete
algorithm or command implementation is required here.

### D12. Design validation (iteration-1 acceptance)

- Library: the implemented memfs tests run on the host and natively on
  Motor OS (D7). Planned sys-io self-tests (`crate::self_test`, inside
  Motor OS debug builds) cover `split`/`join`/`resolve`/`export` round trips, the
  shadowed-id alias, `check_local` and the corrupted flag (including
  forwarded/internal access and flush, while healthy mounts still work),
  the config validator's accept and reject cases including a missing file,
  a parent-before-child nested entry (accepted by the validator, refused
  by `mount_one` on an empty memfs), a child-before-parent order (rejected
  before any mount is applied), protected configuration paths and
  component-boundary lookalikes for both path checks, the cap, reserve and
  cache-cap derivations as pure functions of a RAM size (including the 8 MiB floor
  and the 8 MiB reserve under 32 MiB), and the D13 decision as a pure
  function over free pages, command and mount kind.
- Wire codec: AES known-answer tests on an AES-capable guest; fixed-key
  round trips and root-zero/nonzero behavior. For XOR, cover `0`, `S`,
  ordinary values and `u128::MAX`, verifying round trips, unique outputs
  and no nonzero-to-zero mapping. Exercise CPUID selection in both modes,
  including startup with AES masked off, the one-time warning and no AES
  instructions executed on that path. In both modes check normalization
  before wire export and lock lookup, consistent use of the selected
  codec, and permissions for a known wire ID. Use internal tests for
  mount-bit packing; clients treat `FileAttr.entry_id` as opaque regardless
  of codec. Sampling guessed IDs is not evidence of cryptographic security,
  and XOR has no such claim. A future runtime-mount test must explicitly
  cover retained descendant IDs.
- Namespace/listing: protect mount roots as source and as replacement
  destination, including error precedence across mounts. Cross-mount
  rename fails before mutation, and file-copy requests preserve the source.
  No sysbox command changes or fallback tests gate iteration 1. Enumerate
  enough long mount paths to require multiple responses, and cover spaces,
  newlines, cursor/end handling and unknown statistics without touching a
  corrupted filesystem.
- Write contract: verify a refused classic single-page write leaves file
  bytes, logical size and quota unchanged; a multi-page write or copy
  failing after a completed chunk reports that prefix. Cover unaligned
  slices within one block and rejection of cross-block primitive calls.
- Readahead: sequential memfs reads, through both single-page and
  multi-page handlers, schedule no readahead tasks. Motor FS retains its
  existing readahead behavior.
- In-VM, added to `full-test.sh` and `systest` as listed in R9.2. The
  shadowing test ships `.shadowed-by-memfs` in the image's `/none/tmp`
  through `img_files/motor-os-base/none/tmp/`. Check emptiness before
  uploading the test binaries there; later checks assert that the
  marker's path does not resolve and it is absent from enumeration.
- **The memfs memory test** (decision 22), a systest test, name
  illustrative `test_memfs_memory`:
  1. Read the listing through `FsClient::mounts()`; find `/none/tmp`,
     type memfs. If its cap exceeds 1 GiB, print
     `test_memfs_memory: SKIPPED (memfs cap <n> MiB > 1 GiB)` and return.
     The default 1024 MiB test guest (cap 1008 MiB) and the 256 MiB
     shape (240 MiB) run it; anything larger skips.
  2. Compute the expected cache cap and reserve from `MemoryStats` with
     D7's tiers and D13's rule (the test's oracle; a `+10 MiB` like
     `guest_ram_mib()`). Record initial charged usage, entry count, cache
     usage and free-for-admission memory.
  3. Cache steady state: write a file in `/none/tmp` larger than the
     cache cap (64 MiB on the default guest; reduce it to fit on smaller
     guests), delete it and repeat twice more. Charged usage and entry
     count return to baseline each time, and cached free pages stay within
     their cap. Record free-for-admission readings as diagnostics; exact
     global allocator recovery is part of the deferred review.
  4. Fill: create a small file `s`, then write a file `big` in 32 KiB
     chunks until a write fails. The failure is `StorageFull`
     (`ErrorKind::StorageFull`, or the raw `E_STORAGE_FULL`).
     Confirm a reserve refusal via its counter rather than assuming every
     `StorageFull` means the same limit. Check that the kernel pressure
     flag stays down in this memfs-driven smoke test. Do not assert that
     post-refusal free memory is at least the sampled threshold, or require
     the deferred in-flight allocation proof to implement this test.
     Creating another memfs file fails with
     `StorageFull`; deleting `s` succeeds (freeing works at the reserve);
     a small file on the root filesystem is written and removed (one
     service check, not proof that all other workloads are unaffected).
  5. Recovery: delete `big`. Charged usage and entry count return to
     baseline, the cache stays within its cap, and creating, writing and
     removing a small memfs file works again. Record memory readings;
     block-store tests verify page ownership and explicit release counts.
  6. Every path, including a failed assertion, deletes what the test
     created, so a failure does not leave memfs full for the rest of the
     suite.
  On the 1024 MiB guest step 4 writes about 900 MiB through 32 KiB
  requests, roughly 30,000 round trips: seconds in release, tens of
  seconds in debug, acceptable in the gate. These are concrete
  iteration-1 smoke and accounting checks, not a proof for every workload.
  A failure still requires diagnosis under AGENTS.md; the OOM deferral is
  not permission to ignore a failure or relax an assertion to get a pass.
- Pressure reclamation: populate a cache, then use the existing controlled
  pressure setup to exercise both FS and network admission. Reclamation
  must precede the final refusal, and an emptied cache must not trigger
  repeated page-free work. Check reopened admission when enough pages
  return and the original refusal when they do not. Exercise freeing by
  already-held IDs while pressure remains, and document that pathname
  lookup can still fail. Quota tests include metadata-only entries now;
  exhaustive allocator-failure injection, adversarial metadata/concurrency
  stress and a stronger service-availability workload belong to the OOM
  review reopened by iteration-1 completion (R8.5, D15).
- The existing gate is the acceptance test for spawn, `chmod`, uploads and
  the permission matrix on memfs: from the patch that ships the config on,
  every standard-image `full-test.sh` run executes its test binaries from
  memfs.
- Gate: R9.3, per milestone.

### D13. memfs under memory pressure (accepted for iteration 1)

For iteration 1, assume the 16 MiB reserve plus sparse files is sufficient
OOM protection (8 MiB on guests under 32 MiB), together with bounded data
requests and the reclamation rules below. Rigorous OOM treatment is
deferred, not an outstanding prerequisite to implementing this iteration.
That deferral expires when iteration 1 is complete (R8.5, D15).

Reclaim before final memory-admission refusal, including at the kernel's
pressure gate; do not rely on a request reaching the memfs data handler.

- **Reserve admission.** Before an allocating memfs request (`CMD_WRITE`,
  `CMD_CREATE_*`, `CMD_MOVE_*`, or `CMD_COPY_FILE_RANGE` with a memfs
  destination), read `AdmissionStats::get().free_for_admission()`.
  The threshold remains 16 MiB, or 8 MiB below 32 MiB of guest RAM.
  Sparse resize growth allocates no data/index storage and is excluded
  from this allocating class; metadata-only growth must remain possible
  when the data cap is full. Rewrites may conservatively use the write
  gate even when their particular blocks are already allocated.
- **Reclaim only before a memory refusal, at any gate.** When an
  admission gate would otherwise refuse for a memory reason, release all
  memfs free-block caches, then resample the relevant signal before
  deciding. This covers FS and network request and client admission
  under the kernel pressure flag as well as the memfs reserve; a gate
  that admits never touches the caches, so the common path costs nothing.
  Keep capability checks and donated-page cleanup correct on all exits.
  Permission errors and independent count/quota limits are not memory
  failures; flushing caches cannot cure them. No failed operation is
  replayed: this is one reclaim-and-recheck during admission, not a
  retry loop. If still refused, preserve the gate's existing error:
  `StorageFull` for the memfs reserve, `OutOfMemory` for kernel pressure.
- **Reclaimer constraints.** Drop request-held filesystem locks before
  reclaiming; never hold two mount locks or a table borrow across await.
  Drain only already-free pages, with no new task, allocation, or growing
  temporary list. Keep free-page cache ownership behind a shared handle,
  separate from the asynchronous filesystem lock. memfs uses that handle
  to return/reuse pages; FS and network admission gates synchronously
  drain it without waiting for a filesystem lock. Cache access never
  spans an await, and insertion uses the free pages themselves or existing
  bookkeeping rather than allocating. Empty caches make subsequent passes
  cheap. Draining takes time proportional to cached pages, not logical
  file length; rigorous service-latency treatment is deferred with the OOM
  review (D15).
- **Kernel pressure.** After reclamation, re-read the kernel's flag; its
  existing 2 MiB/3 MiB hysteresis still governs ordinary admission. If it
  remains set, retain the existing refusals except for `UNLOCK` and the
  memfs freeing operations below. Cache reclamation triggered here can
  reopen ordinary lookups, but does not promise it always will.
- **Freeing operations.** Serve memfs `CMD_DELETE_ENTRY` and shrinking or
  unchanged `CMD_RESIZE` by already-held IDs under the flag, subject to
  normal permissions and executable locks. Decode the opaque ID without
  allocation and inspect size under the mount lock; recheck any
  size-dependent decision under that same guard. No allocating path may
  be admitted based on a stale size check. Free released pages directly
  under pressure and drain the affected cache before replying. Ordinary
  path-based removal still needs lookup; if pressure persists after
  reclamation, that lookup can be refused. Allowing nonallocating sparse
  growth under the flag is not needed for reclamation and is not added
  to this exception merely because the reserve gate excludes it.
- **Allocation bounds.** Sparse storage eliminates growth proportional
  to logical length, and D5 bounds both kinds of copy requests. A write
  or copy can allocate only the touched data pages (including partial
  endpoint pages) plus index/metadata growth. D7 also charges metadata-only
  workloads. Bounding all tree splits, names, request futures and lock
  waiters, or making those allocations fallible, is deferred under R8.5;
  ordinary `BTreeMap`/`String` growth is allowed in iteration 1.
- **Limits of the assumption.** The reserve is a sampled threshold, not a
  kernel reservation. One admitted operation and other in-flight work
  can take free memory below it. A refused data-page allocation becomes
  `StorageFull`; the accepted assumption covers the remaining ordinary
  allocations for this iteration, without claiming a quantitative proof.
  Reclamation is reactive: if no admission reaches sys-io, or the kernel
  rejects a channel/process allocation first, this hook does not run.
  Idle-pressure observation and stronger cleanup admission are deferred
  to the same follow-up, not added to iteration 1.
- **Stats.** Count final refusals, after reclamation: `pressure_refused`
  for the flag and `reserve_refused` for the memfs threshold (D10).
  Validate classification and reclamation ordering in D12.

### D14. What the roadmap needs kept open (decision 10)

Iteration 1 needs a few invariants, not a speculative unmount algorithm:

- Mount IDs are values, never vector positions, and are not reused within
  a boot. Unknown mount IDs fail closed. Locks, executable references and
  pager state retain the mount-qualified internal identity.
- Mount lookup, access checks and mutation are encapsulated. Do not bake
  in exactly two mounts, mount 1 being memfs, or mount 0 being the only
  filesystem that can need flushing.
- Filesystem-local IDs obey D1 regardless of backend; a later adapter may
  need its own translation. Later filesystems must preserve the role model.
- Mount/config helpers return errors; only the boot loader turns an error
  into a panic. A later Interactive mount command needs explicit role and
  capability policy, without privilege escalation (R5.1).

Additional block devices/partitions, virtio-fs, read-only mounts and
runtime mount/unmount each need a later design. Nested mounts need none
on the mount side: `MountPoint.mount` names any mount and `mount_one`
resolves through the live table (D9), with parents mounted before children
and no new mount allowed to hide an existing mount. What remains for later
is the unmount busy check for a mount that is another mount's parent. That
later design must cover
namespace validation, busy checks, in-flight admission, stale handles,
already-issued IDs into shadowed subtrees, permissions and resource
budgets. Lock fairness and an `Rc` alone do not solve that lifecycle.
Do not implement speculative variants, unmount steps or device selectors
now, or promise that later handlers will need no changes.

### D15. Deferred design work

**OOM follow-up: deferred only until iteration 1 is complete.** The user
accepts the 16 MiB reserve plus sparse files (8 MiB on guests under
32 MiB), with bounded data requests and D13's cache reclamation, as
sufficient protection for iteration 1. No exhaustive allocator-failure
analysis or quantitative reserve proof gates that iteration.

**Reactivation trigger:** completing iteration 1 automatically brings this
issue back into active design scope for subsequent iterations. Carry this
item forward at the completion review; do not wait for another request,
leave it permanently out of scope, or mark it resolved because D12 passes.
The reopened review must address:

- Metadata/index/name allocation, allocator slab retention and transient
  tree growth: assess the conservative quota charges against actual
  resident memory and decide where fallible allocation is needed.
- Simultaneous requests, lock waiters and other consumers: bound in-flight
  demand and validate or revise the 16/8 MiB thresholds, including the
  supported minimum guest RAM and service workload that must remain usable.
- Reclamation when no request reaches sys-io, including idle pressure and
  earlier kernel refusals; whether path-based cleanup needs safe lookup
  admission in addition to freeing by already-held IDs.
- Latency and performance of large sparse deletes and cache drains, and
  whether the cache's measured benefit justifies keeping it.
- Adversarial metadata/concurrency workloads, allocator-failure injection
  and meaningful service/recovery tests for any stronger guarantee adopted.

**Sysbox: a separate later design.** All sysbox commands and their tests
are outside iteration 1, including mount listing and cross-mount `mv`
fallbacks. Carry forward these accepted constraints for that later work:

- A cross-mount move must preserve the complete per-role permissions of
  every file and directory, or fail if the caller cannot preserve them.
  Copied data must not be exposed with broader permissions while staging.
- Recursive moves must reject destinations inside the source and must
  check mount boundaries before traversing children, during both copying
  and source cleanup. Configured paths can be stale after ancestor renames;
  boundary checks need reliable entry identity, not path-list comparisons.

Define copying and source-removal failure behavior separately when that
design is opened. A copy never removes its source; a move's later removal
phase needs its own failure contract. The earlier file/directory fallback
algorithms and `-r` interface are not iteration-1 requirements. A future
mount-listing command also needs safe escaping of paths for terminal output.

**Other later scope.** Runtime mounts must decide whether known descendant
IDs survive shadowing or require revocation (D1, D14).
Hole-preserving copies are optional later work; sparse storage does not
imply them. None of these are iteration-1 requirements.

The accepted recommendations are incorporated into R1–R9 and D1–D14.
The plan below records completed work and the remaining implementation;
D15 remains follow-up scope, not an additional iteration-1 prerequisite.

## Implementation plan (updated 2026-10-20)

Keep remaining work in small reviewed patches with focused tests, grouped
into the milestones below; R9.3 specifies the full milestone gates.
Original step numbers are retained, but completed work need not be repeated.
The wire codec (step 8) landed first, and steps 4–6 landed together as the
standalone memfs crate. The remaining mount-layout constants move from the
old step 3 into step 7, where routing needs them. No further external
toolchain changes are planned, and no remaining step touches sysbox.

Until step 14, shipped images still use only mount 0. Intermediate changes
add dispatch/admission machinery and the listing API, but do not switch
`/none/tmp` to RAM. Step 14 enables it only after all supporting mechanisms
and their tests are in place.

**Completed validation (through 2026-10-20).** The combined preparatory
state, including the selected toolchain and the shared-helper/memfs
changes, passed:

- All ten memfs tests on Linux in debug and release, and the same ten
  tests through native Lorry in a release developer VM.
- Motor FS host tests with `image-admin` in both profiles: 45 passed,
  with the three existing benchmark tests ignored.
- Memfs Clippy on Linux and Motor targets, Motor FS host Clippy,
  `cargo check` for sys-io on the Motor target, formatting and diff checks.
- Three debug and three release `src/tests/full-test.sh` runs, plus one
  complete `src/tests/full-test-dev.sh --release` run. The first developer
  run exposed stale WASM memory-limit tests (96 MiB versus the pinned
  runtimes' 4 GiB). The separate test-only fix `c7f9ec66` passed focused
  WASM checks on `wasm:224` and `dev:256`, then the full developer rerun.

This validates the library and existing shipped system, not mounted memfs.
The mount-specific acceptance tests of R9.2/D12 remain pending.

**Milestone A, the error code — complete.**

1. **Done, `f34023e0` and `5c1e5749`.** `moto-rt` exposes
   `CrossesDevices = 24` / `E_CROSSES_DEVICES` in published version 0.17.9;
   consumer lockfiles are refreshed.
2. **Done, D11.** The Rust and mlibc fork mappings are committed and
   pushed; the rebuilt toolchain and native assembly are selected by
   `5c1e5749`, which also adds sys-io's reverse error mapping. The
   completed 3+3+1 gate above used that toolchain.

**Milestone B, shared access/name helpers — complete.**

3. **Done, `c4b688a5`.** Move `Need`, `check_access`, `MAX_FILENAME_LEN`
   and `validate_filename` to `async-fs`; motor-fs calls/re-exports them.
   Motor FS incoming-ID hardening and its tests landed separately in
   `d6c0ad2a`. Neither change introduces checks for the theoretical
   Motor FS format limits (decision 16); shared mount-layout constants
   remain in step 7.

**Milestone C, standalone memfs — complete in `8dfe872f`.**

4. **Done.** Entries, directories, lookup/enumeration,
   create/delete/rename, metadata and never-reused counter IDs, with
   public synchronous operations and thin async trait adapters.
5. **Done.** Native page ownership, the bounded free-page cache and its
   independently drainable handle, sparse data, block-bounded atomic
   writes, resize/copy, data-plus-metadata quota charges and statistics.
   Tests cover holes, distant writes, reuse/zeroing, failed-write
   atomicity, copy prefixes, cache caps and page release.
6. **Done.** Shared permission enforcement, all roles and mode-authority
   transitions, plus the host/native test harness. `full-test.sh` runs
   the host suite in both profiles. No production dependency on memfs
   exists yet; RAM sizing and pressure admission belong to sys-io.

**Milestone D, mount-table dispatch — step 7 remains; step 8 is complete.**

Gate: three debug and three release core runs plus one release
developer-image run, because every handler changes.

7. **Next.** Add the shared ID-layout constants/note and implement the
   mount-0-only `MountTable` behind the D2 methods and
   `Rc<RefCell<..>>`. Add `split`/`join`/`resolve`/`export`, `check_local`
   and corruption quarantine. Route every handler and internal user
   (spawn, pager, locks, stats, net config and `resolv.conf`) through
   checked mount access, including the post-lock corruption recheck;
   use one lock per mount and table-wide flush (D5/D6).
   Preserve the existing wire codec around this internal routing:
   ingress decodes once, egress encodes after normalization, and locks
   and pager state use canonical internal IDs. Add in-VM self-tests for
   packing, unknown mounts, aliases, corruption and checked internal
   access. This dispatch conversion may exceed the usual patch size
   because the callers must change together.
8. **Done, `d3af1b66`.** CPUID-selected AES-128/XOR codec, shared
   `FsRuntime` ownership and all client-boundary conversions. Debug
   self-tests cover XOR/root/round trips and AES known answers when
   available. Retain D12's AES-disabled startup and mount-normalization
   coverage in integration validation; the codec itself needs no rewrite.

**Milestone E, memfs integration and boot mounting — pending.**

Gate: three debug and three release core runs. No image ships the config
during this milestone.

9. Add sys-io's memfs dependency and `FS::MemFs` dispatch. Skip readahead
   task creation on both memfs read paths (D4). Add the `sys-fs.toml`
   parser and whole-file validator, including protected config paths and
   rejection of later ancestors that would hide earlier mounts. Implement
   and test RAM-derived capacity/cache limits and root-mode selection
   (D7–D9); the library continues to receive explicit values.
10. Implement `mount_one` and boot loading with the missing-file and
    fail-closed policies. Complete D3's path normalization, shadow aliasing,
    sibling/name forwarding and protection of mount roots as both source
    and replacement destination. Mount through the live table in file
    order; retain D2 ownership and D6's lock rules. Test nested ordering,
    protected paths, aliases and `NotAllowed` precedence.
11. Add bounded cross-mount copy with chunks respecting both block
    boundaries and committed-prefix reporting; cap same-mount requests
    too. Return the implemented `CrossesDevices` error for cross-mount
    moves after mount-root checks and before mutation (D5). Test both
    directions and executable-lock enforcement; no sysbox fallback.
12. Integrate the memfs reserve and shared cache handles into every
    memory-refusing admission gate, including network/client gates.
    Reclaim and resample before a final refusal; allow the specified
    freeing operations under kernel pressure, rechecking size under the
    same lock and returning released pages before replying. Add
    `reserve_refused` and D12/D13 classification/reclamation tests.
13. Add `CMD_GET_MOUNTS`, its bounded structured pagination codec,
    `FsClient::mounts()` and memfs aggregate metrics (D10). Test malformed
    cursors, path encoding, multi-response listings and unknown/omitted
    statistics for corrupted mounts. The shipped listing shows mount 0
    alone until step 14; no sysbox command.

**Milestone F, enable `/none/tmp` — pending.**

Gate: three debug and three release core runs plus one release
developer-image run.

14. Ship `sys-fs.toml` and `.shadowed-by-memfs` in `img_files/motor-os-base`,
    add R9.2/D12's mounted-filesystem tests, including memory/reserve
    recovery and pressure reclamation, and update `docs/fs-permissions.md`.
    Verify the existing spawn, permissions, copy and developer/WASM users
    on the mounted filesystem. At iteration-1 completion, reopen the
    rigorous OOM review of D15; passing the smoke gate does not close it.

## Open questions

All questions are answered; they are kept for numbering stability and
as the record of how each point was settled.

- **Q1. Config notation.** Answered: config file only, D8's format
  (decision 3).
- **Q2. Where the config and the marker ship.** Answered: the base tree
  (decision 4).
- **Q3. memfs capacity default.** Answered in the fifth pass as "no cap";
  revised in the sixth and settled in the seventh: every memfs has a cap,
  RAM rounded down to 16 MiB minus 16 MiB when `max_size` is absent
  (decision 5, Q14); allocating memfs operations are also declined under
  memory pressure (D13).
- **Q4. Cross-mount rename error.** Answered: a new code mapped to
  `CrossesDevices` and `EXDEV` (decision 6, D11). The `sysbox mv`
  fallback that earlier passes attached to it is deferred with all
  sysbox work (decision 14, D15).
- **Q5. Executables in memfs.** Answered: same executable locks, the pager
  copies bytes on faults, shared pages later (decision 7, D4).
- **Q6. Failure policy at boot.** Answered: fail closed at boot only
  (decision 8, D9).
- **Q7. Observability scope.** Answered: the listing API is in
  iteration 1; its sysbox command is deferred (decision 9, D10, D15).
- **Q8. What the design must not preclude.** Answered: a second block
  device, multiple Motor FS partitions per device, virtio-fs (decision 10,
  D14); nested and read-only mounts joined the list in the sixth pass
  (decision 18).
- **Q9. Test gate.** Answered: per milestone (decision 11, R9.3, Q18).
- **Q10. A memfs reserve above the kernel's watermark.** Answered: yes, a
  fixed 16 MiB of free-for-admission memory, refusing with `StorageFull`
  after emptying the free-block caches (decision 12, D13).
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
  right (decision 13, steps 1 and 2); nothing in sys-io is written against
  an interim code. This sequence is now complete: moto-rt 0.17.9 was
  published, the two fork mappings were pushed, and the rebuilt
  toolchain is selected. D11 records the commits and key; the implementation
  plan records the completed 3+3+1 validation.
- **Q12. Scope of the `sysbox mv` fallback.** Answered: deferred. The
  eleventh pass limited the fallback to files and the twelfth restored
  directories behind `-r`; after the twelfth pass all sysbox work left
  iteration 1, so no fallback ships and a cross-mount rename reports
  `CrossesDevices` without copying or deleting anything (decision 14,
  R3.5, D11). D15 carries the agreed constraints into the later sysbox
  design.
- **Q13. Mount-id scheme and the Motor FS limits.** Answered, superseding
  the index-plus-epoch proposal: the mount id is a 24-bit per-boot
  counter in the 16 reserved generation-word bits plus the 8 reserved
  block-number bits, filling the generation bits first; the table is a
  vector searched by id behind `MountTable` methods. The Motor FS limits
  (2^48 generations, 2^56 blocks) have no error path and no tests,
  because they are unreachable: with a generation consumed only per new
  directory entry (commit `4527c75b`), 1000 per second is a realistic
  high bound and 2^48 lasts 8,900 years at that rate. sys-io checks the
  reserved bits of every id a filesystem returns and marks the mount
  corrupted on a violation instead of asserting (decision 16, seventh
  pass). The mount counter is the one reachable limit, 16.7 million
  mount operations per boot (194 days at one per second), and is an
  error (`StorageFull`) because a runtime mount command makes it
  client-driven (decisions 1 and 16, D1, D2, D14).
- **Q14. The default memfs cap.** Answered: `(RAM & !(2^24 - 1)) - 2^24`,
  RAM rounded down to a multiple of 16 MiB, minus 16 MiB, with RAM the
  `guest_ram_mib()` figure, and at least 8 MiB (decision 5, R4.5, D7,
  Q21).
- **Q15. Nested mount points in iteration 1.** Answered: yes, nesting
  works by construction; the validator does not reject a mount point
  below an earlier entry, `mount_one` resolves it through the live table,
  and in iteration 1 a nested entry fails at mount time because a memfs
  is empty at boot (decision 18, R2.3, D8, D9). The eleventh pass had
  the validator reject overlapping paths; the twelfth pass restored this
  answer.
- **Q16. Renaming a mount root.** Answered: no fallback. Renaming,
  moving, replacing or deleting a mount root is `NotAllowed`, checked
  before the cross-mount check, so renaming `/none/tmp` to `/none/x` is
  an error that changes nothing (decision 19, R3.5, D3, D5). The eleventh
  pass extended the protection to every ancestor of a mount point; the
  twelfth pass removed that again, since the mount is keyed by the
  shadowed id and only the listed path can go stale (D10).
- **Q17. Per-mount statistics.** Answered: agreed. The listing carries
  `used`, `entries` and `cap` per mount, a Motor FS reports its entry
  count as unknown, and the stats responder carries memfs totals plus
  the reserve counter, with no per-mount scoped entries (decision 20,
  R7.4, D10).
- **Q18. Milestone gates.** Answered: agreed; milestones A to F as in the
  implementation plan (decision 11, R9.3).
- **Q19. memfs ids as a plain counter.** Answered: confirmed (decision
  21, D7).
- **Q20. The free-block cache.** Answered: yes to all three: the caches
  are emptied on the reserve path and after freeing requests served under
  the kernel's flag; the 256 MiB tier is "256 MiB and up", matching
  `SMALL_GUEST_MIB`; the RAM figure is `guest_ram_mib()` with no further
  adjustment (decision 17, D7, D13). Revised in the eleventh pass and
  kept in the twelfth: the caches are also drained at any sys-io
  admission gate, FS or network, that would otherwise refuse for a
  memory reason, before that final refusal, through a cache handle
  shared with sys-io so the drain needs no filesystem lock; a gate that
  admits never touches them (decisions 12 and 17, D7, D13).
- **Q21. The default cap on tiny guests.** The Q14 formula gives 0 for a
  guest under 32 MiB (16 MiB rounds to 16, minus 16), and a zero cap
  would make memfs refuse everything while `num_blocks` reported 0,
  tmpfs's "unlimited" convention. Answered: the derived cap is at least
  8 MiB, and on a guest where the floor applies, that is under 32 MiB,
  the reserve is 8 MiB instead of 16 MiB, so memfs can actually hold
  something there (decisions 5 and 12, R4.5, D7, D13; the memory test's
  oracle follows the same rule, D12).
- **Q22. Motor FS asserts, or none.** The fifth pass asked for
  release-build asserts of the Motor FS limits in motor-fs; the sixth
  pass had those plus a sys-io assert; the seventh replaced the sys-io
  assert with the check-and-corrupt rule and proposed dropping the
  motor-fs asserts, since a Motor FS that ever produced an out-of-range
  id is caught by sys-io and disables only its own mount, which is
  strictly better than a panic once a second Motor FS partition exists
  (D14). Answered: no asserts; the checks that return `InvalidData` and
  mark the mount corrupted remain the planned single guard for those
  format limits (decision 16, D1, D11, plan step 7). The separate
  `d6c0ad2a` hardening validates untrusted incoming IDs against the
  actual device and entry metadata; it does not enforce the theoretical
  2^56/2^48 format limits. The shared-helper move is complete (step 3).
