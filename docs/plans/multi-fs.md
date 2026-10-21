# Multiple filesystems in sys-io

Status: iteration 1 is done and committed (2026-10-21). The integration
landed as `38e5d72d` (`sys-io: mount /none/tmp`). Review fixes followed in
`fc705881` through `c1890b6a`, one fix per commit.

The full design record (requirements R1-R9, design D1-D15, the answered
questions and the original plan) is in git history:
`git show c1890b6a:docs/plans/multi-fs.md`.

## What works

sys-io serves several filesystems at once through a mount table. The
Motor FS data partition is mount 0 at `/`. Every image mounts an
in-memory filesystem (memfs) at `/none/tmp`, so `/none/tmp` is empty after
every boot. `/user/tmp` and `/system/tmp` stay on disk.

### Configuration

Mounts come from `/system/cfg/sys-fs.toml`, applied in file order at boot.
There is no runtime mount command. The base image ships:

```toml
[[mount]]
path = "/none/tmp"
type = "memfs"
# max_size = "64M"   # absent: RAM-derived cap
# mode = "rwxrwxrwx" # absent: the shadowed directory's mode
```

- A missing file means only the root filesystem is mounted.
- The whole file is parsed and statically validated before any mount is
  applied. A bad file, or a mount that cannot be applied, panics sys-io at
  boot. Entry validation and mount failures name the path, or the entry's
  position if no string path is available. Earlier read/parse failures may lack
  entry context.
- Paths must be absolute and canonical. A mount may not hide `/system/cfg`
  or an earlier mount. At most 255 entries; the file is at most 64 KiB.
- The mount point must be an existing directory. Its contents stay on disk,
  hidden.
- Known parser limitation: unquoted integer `max_size` values above
  `i64::MAX` are rejected by the intermediate TOML table conversion, before
  entry-specific diagnostics. Quoted decimal byte counts accept the full
  `u64` range.

### Entry IDs

- sys-io puts a 24-bit mount id into bits that Motor FS IDs never use.
  memfs IDs leave the same bits clear.
- Clients see opaque IDs. Each boot picks AES-128 (with AES-NI) or a
  weaker XOR fallback, which is obfuscation only. The root ID is always 0.
  Neither codec revokes already-issued IDs.
- sys-io checks every filesystem-produced ID for reserved mount bits. A
  set bit quarantines that mount until reboot: further filesystem access
  fails with `InvalidData`. Lock release and mount listing remain available.
  Invalid client IDs are rejected without quarantining a mount.

### Namespace rules

- Path walks, single lookups and directory listings all reach the mount's
  root at the mount point. Shadowing applies to pathname lookup and
  enumeration; the XOR fallback does not secure hidden descendants against
  deliberate direct-ID access. Ordinary permissions still apply.
- A mount root cannot be deleted, renamed, moved or replaced by a rename:
  `NotAllowed` (`PermissionDenied` in std). Root protection precedes the
  `CrossesDevices` check.
- Renaming across mounts fails with `CrossesDevices` (`EXDEV` in libc) and
  changes nothing. sys-io never emulates a move by copy and delete.
- Copies across mounts work through the existing copy request. sys-io
  copies at most 32 KiB per request; clients already loop.
- File locks, executable locks and the demand pager work on memfs. The test
  gate uploads its binaries to `/none/tmp` and runs them from there.
- Each mount has its own lock; no request holds two mount locks at once.
  Flush attempts every healthy mount even if another fails. Quarantined
  mounts are skipped and make the result `InvalidData`; otherwise flush
  returns the first error, or success if all mounts succeeded.

### memfs

- A standalone crate, `src/sys/lib/memfs`. It shares its permission and
  filename checks with Motor FS through `async-fs`, so the permission rules
  are the same.
- Files are truly sparse: holes cost nothing. Reads and writes go one 4 KiB
  block at a time; a failed block-bounded write changes nothing. Multi-block
  writes and copies may commit a prefix and return a short count. A later
  failure does not roll back earlier chunks.
- The cap counts allocated data plus metadata. The default cap is guest
  RAM rounded down to 16 MiB, minus 16 MiB, at least 8 MiB.
- Freed pages go to a small per-mount cache (its cap depends on RAM). Past
  that cap they go straight back to the kernel.

### Memory protection (accepted for iteration 1)

- The memfs reserve gate refuses allocating requests with `StorageFull`
  when free-for-admission memory remains below 16 MiB after reclamation
  (8 MiB on guests under 32 MiB).
- The FS request gate checks kernel memory pressure before reserve
  admission. If pressure persists, it returns `OutOfMemory`, except for
  the freeing operations below.
- Before a final memory-admission refusal, in the FS and network gates
  alike, sys-io empties the memfs free-page caches and resamples the signal
  once. This is admission-time reclamation; failed operations are not
  replayed, and allocator failures are not universally recoverable.
- Under kernel memory pressure, memfs deletes and shrinking or unchanged
  resizes by already-held IDs, and lock releases, are still served.
  Capability, permission and executable-lock checks still apply. Freed
  data pages return to the kernel before the reply; pathname cleanup can
  still be refused at lookup.
- This is a sampled threshold, not a proof against every out-of-memory
  case. See the first next step.

### Observability

- `CMD_GET_MOUNTS`, through `FsClient::mounts()`, lists every mount: id,
  kind, configured path, quarantine status, and bytes used, entries and cap
  when known. Every role can read it. Quarantined mounts have unknown usage.
  Configured paths can become stale after ancestor renames.
- `fs.capacity_bytes` and `fs.available_bytes` describe only the data
  partition. memfs totals are `fs.memfs.used_bytes`, `fs.memfs.entries`
  and `fs.memfs.cached_free_bytes`; `fs.reserve_refused` counts reserve
  refusals.
- The boot log has one line per mount.

User-facing behavior is also described in `docs/fs-permissions.md`.

### Tests

- memfs host tests, run by `src/tests/full-test.sh`.
- sys-io debug self-tests (`systest sys-io-self-test`): ID packing, aliases,
  quarantine, config validation, admission rules and protections.
- `systest mounts`: namespace, cross-mount operations, and memfs fill to the
  reserve and recovery. Pressure tests cover cache reclamation.
- The rest of the gate runs from `/none/tmp`, so it exercises memfs too.

## Next steps

1. **Out-of-memory review.** Iteration 1 accepted the reserve as enough;
   that deferral has now ended. Define the minimum supported guest RAM and
   the service workload that must remain usable. Assess actual metadata,
   index, name and allocator residency against quota charges, concurrent
   requests and lock waiters, and the 16/8 MiB thresholds. Address
   reclamation when no request reaches sys-io and whether pathname cleanup
   needs safe lookup admission. Measure the cost of large sparse deletes
   and cache drains, and whether the cache earns its keep. Add
   failure-injection and stress tests for whatever guarantee is chosen.
2. **sysbox.** A mount-listing command (with safe escaping of paths) and a
   cross-mount `mv` fallback. A fallback must preserve every file's and
   directory's complete per-role permissions or fail, and never expose
   staged data more widely. Recursive moves must reject destinations
   inside the source and check mount boundaries before traversing children
   during both copying and source cleanup, using entry identity rather
   than paths. Define copy and source-removal failure behavior separately.
3. **More mounts.** A second block device, several Motor FS partitions,
   virtio-fs, read-only and nested mounts, and runtime mount and unmount
   that Interactive users can run under their own role (there is no
   privilege escalation). Runtime mounts need a lifecycle design: busy
   checks, including parents with mounted children; in-flight requests;
   stale handles; and what happens to already-issued IDs inside a newly
   shadowed directory.
4. **Other follow-ups.** Restore the full unsigned integer range for
   unquoted `max_size`. Hole-preserving copies. Sharing memfs pages with a
   process instead of copying them on each page fault. A proposed
   simplification of mount-table ownership is still undecided.
