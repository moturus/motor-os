# Multiple filesystems in sys-io

Status: iteration 1 (memfs over the three tmp directories, configured in
`/system/cfg/sys-fs.toml`) is committed; [fs-permissions.md](../fs-permissions.md)
describes it and `git show b686d5e6:docs/plans/multi-fs.md` records it
(requirements and design: `c1890b6a`). Iteration 2 was reviewed against
`4fcde583` on 2026-11-06; D1–D5 are accepted. Implementation is in progress,
starting with step 0; test each patch and commit it with a one-line message.

## Iteration 2: findmnt, Motor FS mounts, read-only mounts

Mount existing Motor FS filesystems at boot from `sys-fs.toml`, writable or
read-only, from MBR primary partitions on the root or additional virtio-block
devices or from a whole device, and allow a read-only root; root stays mount 0
and memfs is unchanged. Still deferred: formatting at mount time, GPT, hotplug,
runtime mount/unmount, virtio-fs, a permission-preserving cross-mount `mv`. All
changes stay in this repository (no kernel, moto-rt, stdlib, toolchain or
`src/sys` static change) in 100–300-line patches whose tests reach `full-test.sh`.

### Configuration

```toml
[root]                # optional; root is mounted before this file is read
read_only = true      # needs a writable [[mount]] at exactly /system/logs
[[mount]]
path = "/user/data"   # existing directory, resolved through earlier mounts
type = "motor-fs"
device = 1            # ordinal among discovered virtio-block functions
partition = 1         # optional MBR slot 1-4; absent: Motor FS fills the device
# cache_mb = 32       # optional LRU cache size in MiB
# read_only = true    # optional; every modifying request fails with NotAllowed
```

- `device` follows the PCI scan order and is never renumbered: a function that
  fails to parse keeps its slot, so `discover_virtio_devices` in virtio-async
  must report failed functions with the kind the PCI device ID gives (today it
  drops them). Log the index-to-PCI mapping. `partition` counts unused and
  non-Motor slots; zero is invalid. No format guessing: a bad MBR or slot never
  falls back to the whole device, an omitted `partition` never searches an MBR. (D1)
- Root: device 0's first block, after a capacity check. A Motor FS header
  selects the whole device; otherwise require a valid MBR and take its lowest
  Motor FS slot (replacing today's panic on a second one). Missing or invalid
  root fails boot. The shipped root stays slot 3, slot 4 free; a bare root
  boots only on Cloud Hypervisor and Firecracker (kernel and initrd separate).
- Header check, in motor-fs, on the block 0 every open already reads (today
  `TxnLogger::open` validates nothing): magic, version 1, superblock block
  count equal to the extent's; the journal is located from the extent size,
  so a resized backing file would replay the wrong blocks.
- Validate the whole file, then every source, before opening anything. Keep the
  64 KiB/255-entry limits, canonical paths, protected paths, file order and
  root-only on a missing file. Reject unknown fields, memfs keys on `motor-fs`
  and vice versa, a missing `device`, a non-positive-integer `cache_mb`,
  repeated sources, whole/partition mixes on one device including root, and
  unknown `[root]` keys.
- MBR sources: valid signature; every occupied primary extent nonzero, inside
  the capacity, non-overlapping; the selected slot has the Motor FS type and
  a length divisible by eight 512-byte sectors (no new 4 KiB alignment rule).
  This now applies to the root disk. Whole-device sources: capacity divisible
  by eight sectors and large enough; never truncate, add an MBR, format or resize.
- Targets are existing directories resolved through earlier mounts; a later
  mount may sit inside an earlier Motor FS but not hide an earlier mount; a
  mounted root keeps its stored permissions. Any failure aborts startup naming
  entry, path and source before FS listeners publish; recovery writes stay.

### Read-only mounts and a read-only root (D5)

A read-only mount refuses create, write, resize, delete, set permissions, move
with either side on it and copy into it with `NotAllowed` (`PermissionDenied`
in std) for every role including System, before the `CrossesDevices` check;
reads, lookup, listing, locks, exec, demand paging and copies out work, and
flush skips the mount (Motor FS writes nothing on read paths). `read_only` is
rejected on memfs.

Journal recovery is not a client write. Pass an explicit recovery policy into
Motor FS opening based on the device's read-only status, before replay can
queue any writes. When recovery is needed on writable backing, await its
writeback and flush, propagating failures before setting a read-only mount
flag or publishing FS listeners. On VMM read-only backing, inspect the journal
without replay and fail boot if recovery is needed. Such devices may back only
read-only mounts, root included; a writable configuration for one fails
validation. Root uses the same opening policy before reading the file; its
mount flag is set after validation and all mounts, before FS listeners
publish. A read-only root without the writable
`/system/logs` mount fails validation. strobe's logs are the known boot-time
writes under root; later user writes (`known_hosts`, key generation, editor
config) fail with `PermissionDenied`. The shipped file keeps root writable.

### I/O ownership, cache budget and boot cost

- One `BlockDevice` and `block_io::run` task per initialized device; partitions
  share its bounded inbox; each mount keeps its own lock, cache and transaction
  log; a whole-device mount is the same adapter at offset 0. Bounds-check every
  source-relative range, multi-block included, before translation or DMA. Flush
  stays per filesystem, without coalescing, visiting every healthy writable
  mount even after an error.
- Each virtqueue takes one of the 16 IRQ vectors sys-io reserves (64–79), shared
  with net and vsock, so about ten extra disks is the practical ceiling.
- Cache (D2): B is today's `block_cache_blocks()` budget (16 MiB at 256 MiB RAM
  and above), kept for root; each of M additional mounts defaults to B/M in
  whole blocks; `cache_mb` replaces only that mount's share and may exceed the
  budget; a cache below 1 MiB rejects the file. Each Motor FS also pins 64
  journal blocks plus its superblock; measure sys-io memory at small guest
  sizes, stop for review if it exceeds the envelope. OOM floors are unchanged.
- Boot work (D3): open only configured sources, read an MBR only for partition
  sources, reuse the PCI scan and root's first-block read; no scans, prewarming
  or periodic work. Compare [boot-time.md](boot-time.md) milestones to baseline.

### Implementation steps (in order, each with its tests)

0. `sysbox findmnt` plus a `/system/bin/findmnt` wrapper; the root-only `df`
   script runs it too. Table in mount-ID order, `ID TARGET FSTYPE STATE USED
   CAP ENTRIES`: STATE `rw`/`ro`/`quarantined`, `-` when unknown, targets
   escaped to ASCII. Redefine `MountInfo` once with an optional block source
   and a read-only flag (D4: the decoder rejects unknown bits and length
   changes, so it cannot grow later). systest: four mounts, three roles,
   `findmnt`/`df` equivalence, help, bad arguments, synthetic hostile records.
1. Collect all block devices in `runtime/mod.rs`; split root selection,
   device owner, source descriptors and opening in `runtime/fs.rs`; header
   check in motor-fs; lowest-slot rule; MBR/whole-device validation; range
   checks in `virtio_partition.rs`; virtio-async accessors and failed-function
   reporting. sys-io self-tests; raw, qcow2 and `imager resize` images boot.
2. Config: `motor-fs`, `cache_mb`, `read_only`, `[root]`; validate before
   applying; default shares, then overrides. Self-tests for every rule above
   at small and normal RAM; new entries are never silently ignored.
3. Read-only: negotiate `VIRTIO_BLK_F_RO` when offered and expose the resulting
   device flag (today the bit is never acknowledged, so the flag is always
   false); check it against configuration. Add the opening policy above to
   motor-fs and propagate recovery completion/errors to startup. Flag on
   `Mount`, checked in `Resolved::write`; also check both resolved mounts in
   `move_entry` before the `CrossesDevices` branch, which currently returns
   before taking the write lock. Cover both rename variants with a read-only
   source and with a read-only destination. Flush skips; root flip; `ro` in
   the boot line and findmnt. Self-tests: feature present/absent, recovery
   forbidden with no writes queued, and recovery completion/errors. strobe reclaims
   logs by `fs.available_bytes` (data partition only): switch it to the
   `/system/logs` mount's cap and usage from the listing (small `src/sys/strobe`
   change). Image flavor `motor-os-ro-root.yaml` (`BUILD_TEST_IMAGE`, replaces
   `sys-fs.toml`); new `test-block-mounts.sh` boots it on the gate's VMM:
   services log, root `ro`, root writes fail with `PermissionDenied` for System
   and Interactive, reads and exec work, logs rotate against the memfs cap,
   clean reboot. Update `fs-permissions.md`.
4. Partitions on the root device through its owner, in config order. Rust fixture
   builder under `src/imager`: root in slot 3 plus a populated Motor FS in slot 4.
   Checks: IDs, I/O, permissions, cross-mount copy and `CrossesDevices`, flush then
   reboot/readback, `read_only` on a second boot, an unconfigured slot unmounted.
5. Additional devices, initialized once and only when referenced; MBR read only
   for partition sources. Fixtures: data-only MBR disks and bare
   `AsyncFileBlockDevice` files, attached through new extra-disk arguments of
   the three launchers. Root+slot 4, a partitioned second and a bare third
   device concurrently, data verified in both directions across a shutdown;
   unconfigured disks; a read-only whole-device mount. On VMM read-only backing,
   test clean and recovery-required images for root and additional mounts:
   clean images with `read_only = true` boot; recovery-required images fail
   without write submission; writable configurations fail boot. Repeat the
   recovery-required cases on writable backing with read-only mounts, verifying
   completed recovery and readback. Bare root on Cloud Hypervisor and Firecracker
   (image path and format only).
6. SOURCE column in findmnt from the identity stored at mount time (`virtio2`
   vs `virtio2p1`, none for memfs); capacity metrics stay root-only.
7. Every rejection above yields its diagnostic and no FS service; cross-mount
   operations among all kinds, exec and paging on both source forms, flush after
   errors; concurrent I/O at one and four vCPUs with memfs pressure, in
   `test-block-mounts.sh` under its own limit (the one-vCPU debug gate is at
   budget). 256 MiB and 1 GiB; add 128 MiB (B = 4 MiB, a fifth mount rejected)
   only after a verified plain boot there, else stop for review. Record sys-io
   memory, boot time and I/O against the single-root baseline; fixture once on
   the other two VMMs. Gate: three debug and three release `full-test.sh` runs,
   then `full-test-dev.sh --release`; no retries or longer limits.
