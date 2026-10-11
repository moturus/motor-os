# Cold spawn prototype: archived record

This document preserves what the two spawn prototypes of 2026-10-01 to
2026-10-03 built, measured, and learned. Their evidence refers to commit
`6ef7737b4a5db34744827694e5c99c0b751ded44`; later design notes are dated
separately. The current design is in
[spawn-optimization.md](spawn-optimization.md).

The archive is self-contained: reconstruction does not depend on keeping
`docs/plans/spawn-cold-prototype/` (cold, 10.09x) or
`docs/plans/spawn-prototype/` (warm, 20.0x). Section 9 records the new
sys-io loading approach; Appendix D preserves the superseded detailed
implementation plan and its review answers.

The appendices hold the complete candidate patch, the six earlier patches,
and every harness and driver script verbatim. The sections before them
explain the design, the measurement method, the experiment ledger with
every recorded number, and the facts that the production plan relies on.

## 1. Results

### 1.1 Final validated cold comparison (2026-10-02)

Snapshot s100 in mode `cold-131072`, release builds, one measured command
per freshly booted VM, baseline and prototype alternating.

| Workload | Pairs | Baseline mean | Prototype mean | Ratio of means |
|---|---:|---:|---:|---:|
| `/devtools/bin/rustc --version` (shell wrapper) | 50 | 374.542 ms | 37.109 ms | 10.09x |
| `/devtools/llvm/bin/llvm clang --version` | 10 | 328.431 ms | 41.738 ms | 7.87x |
| `/system/bin/rush -c exit` | 10 | 6.935 ms | 5.264 ms | 1.32x |

Full statistics (nearest-rank p95; `spawn` is the time until `spawn()`
returned, `total` is spawn through exit, wait, and output collection):

| Series | n | mean | median | p95 | min | max | spawn mean |
|---|---:|---:|---:|---:|---:|---:|---:|
| rustc baseline | 50 | 374.542 | 373.944 | 385.003 | 363.596 | 391.585 | 5.564 |
| rustc prototype | 50 | 37.109 | 37.024 | 40.825 | 32.725 | 42.848 | 2.479 |
| clang baseline | 10 | 328.431 | 328.248 | 333.686 | 322.351 | 333.686 | 313.186 |
| clang prototype | 10 | 41.738 | 41.953 | 43.752 | 39.274 | 43.752 | 3.230 |
| rush baseline | 10 | 6.935 | 7.043 | 8.408 | 4.853 | 8.408 | 5.210 |
| rush prototype | 10 | 5.264 | 4.955 | 6.882 | 3.625 | 6.882 | 2.599 |

All 140 samples passed exact-stdout, empty-stderr, and successful-exit
checks. The baseline is the unmodified build plus nothing; the prototype
build includes the fsync fix, which only matters during installation.
Rush is already running when the VM has booted, so its row checks a
small program with boot-resident data, not a cold executable.

Identity of what was measured:

| Item | SHA-256 |
|---|---|
| rustc ELF, 119,030,776 bytes | `ad70c2605e702066a236d7392e965200efd941b6f5e71537b8bbb11ce14da99f` |
| rustc harness binary (`bench-rustc-confirmation.rs`) | `b25bfb6153312af561d529ced9207696edb5e62e7e82b0dac855333e2472d2e1` |
| clang and rush harness binary (`bench.rs`) | `e8757c5c7f35b77f0ef5dc7f860eb8dc1d37aff54eba48ae11c46e41e7cfc2df` |
| baseline initrd / kernel / kloader / kloader.bin / rt.vdso / sys-io | `6516b87e…beb2` / `ae59ad2b…399e` / `02d7b6c0…0d44` / `2b5aa5c6…81d9` / `eac5ebb9…61b7d` / `67a17a73…2842` |
| validated initrd / kernel / kloader / kloader.bin / rt.vdso / sys-io | `99da40c2…2447` / `b2e917dd…07d0` / `896adff4…45fd` / `e25bdff7…6181` / `6fcebcfe…7cae` / `d36b7785…433f` |
| candidate.patch | `6ae18f4e9bf5fdda70ec4688a9cbecfdce94463082aa422f23665ddc25be887e` |
| fsync-flush.patch | `543fc409ce8d380ca2ab58014fa890c7668489f2240f7108deaebc458bec798a` |
| source-stages.tar.gz | `c41692819e5b7107c9c8a931fd646c6ee95ded8bac1932e7c58f2fcc0802104c` |

The candidate patch reconstructed all 27 final source file hashes when
applied to the base; that check passed ("patch-verification.stdout").

### 1.2 Paired comparisons that preceded the final one

Each was a preselected alternating batch of 20 pairs, fresh VM per
sample, same harness rules.

| Candidate stage | Baseline mean / median / p95 | Prototype mean / median / p95 | Ratio |
|---|---|---|---:|
| Launcher-wide lazy slabs (`parent-paired`) | 373.794 / 372.215 / 381.122 | 39.081 / 38.499 / 41.743 | 9.56x |
| 16-page DMA pool with coalescing (`dma-coalesce-paired`) | 376.281 / 376.276 / 379.563 | 38.971 / 38.015 / 42.705 | 9.66x |
| Plus 128-page first-fault read-ahead (`entry-bg-paired`) | 375.344 / 376.308 / 380.541 | 37.259 / 36.659 / 41.028 | 10.07x |

A five-pair refresh before those measured baseline 368.299, 377.305,
382.364, 383.214, 375.256 ms and the then-current candidate 41.898,
42.037, 41.841, 42.600, 42.065 ms.

### 1.3 The earlier warm prototype (2026-10-01)

Prepared-image cache hits, not cold launches. Same VM configuration;
`bench.rs` of that prototype alternated AB/BA order per round and
excluded round 0 from the distributions.

| Experiment | Samples per mode | Mean completed rustc command | Note |
|---|---:|---:|---|
| Unmodified build, initial control | 30 | 174.544 ms | median 173.606 |
| Unmodified build, final wrapper control | 100 | 178.172 ms | median 177.423, p95 185.487 |
| First file pager, 16-page reads | 30 | 50.803 ms | 3.42x against its 173.719 control |
| Prepared image, eager shared mappings | 30 | 16.201 ms | no repeated reads or relocations, still maps every page |
| Prepared image, sparse mappings | 30 | 10.122 ms | |
| Sparse image + prepared vDSO | 100 | 10.245 ms | same-VM control 170.843; 16.7x |
| Plus learned used-page mapping | 100 | 9.191 ms | control 174.067; 18.9x |
| Plus batched page-table pruning | 100 | 8.627 ms | same-kernel ordinary path 169.105; 19.6x |
| Scoped cache handoff, normal rustc wrapper | 100 | 8.924 ms | wrapper control 171.193; 19.2x; 20.0x against 178.172 |

Preparation of the image took 362.816 ms and was recorded separately.
Including it, the 101-command sequence improved 13.7x against the paired
control. LLVM `clang --version` improved from 150.013 to 9.533 ms (15.7x,
30 samples per mode). A short final smoke run gave 169.741 ms ordinary
and 9.157 ms cached. The final direct-ELF median `spawn()` was 2.494 ms.
A cold first command in that VM took 359.854 ms ordinary and 171.158 ms
on the first cache miss, so none of this is a cold result.

### 1.4 The first lazy pager (before either prototype)

A private per-child file pager with 16-page reads, measured on 2026-10-01:
spawn 11.2 ms, completed command 50.8 ms (3.42x). Every run incurred 403
file-backed faults and filled 6,431 pages (25.1 MiB) into private frames,
each fault costing sys-io scheduling, a cache lookup, a fill, and a
resume; the loaded windows exceeded the 16 MiB block cache. Its log
format was `loader,round,spawn_us,total_us,faults,filled_pages`.

## 2. Measurement method

Everything in this section is what the scripts in Appendix C do, stated
so it can be reimplemented without them.

### 2.1 Virtual machine

- Cloud Hypervisor 52.0 with KVM on an Intel i9-13900H; four vCPUs,
  8 GiB RAM (`MOTO_MEMORY_MIB=8192`), host affinity `taskset -c 0,2,4,6`.
- Guest RAM is memfd with the transparent-hugepage hint, no hugetlbfs
  pool, host `shmem_enabled=never`. Host storage caches were never
  flushed: "cold" means a freshly booted guest, not a cold host.
- The VM directory is an isolated copy: `run-chv.sh` and `vm-options.sh`
  copied from `vm_images/release/` (the warm prototype copied them from
  `src/vm_scripts/`), plus `flat.qcow2`, a flattened copy of the developer
  image made with `qemu-img convert -O qcow2`. A qcow2 overlay was
  rejected by this Cloud Hypervisor with "Maximum disk nesting depth
  exceeded" before boot.
- `kloader` and `initrd` are copied into the VM directory before each
  boot, so a build is selected by copying its artifacts there.
- The VM is started with `MOTO_IMAGE=flat.qcow2 MOTO_CHV_RUNTIME_DIR=<dir>
  run-chv.sh`, its serial output captured to a log, and stopped with
  `curl --unix-socket <dir>/chv -X PUT http://localhost/api/v1/vmm.shutdown`.
- Guest access uses the repository's test identity: `ssh -F /dev/null
  -p 2222 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile=src/tests/test-known-hosts -i vm_images/release/test.key
  motor@192.168.4.2`, and `scp` with the same options.
- The repository's host-wide VM lock applies; never touch a VM you did
  not launch.

### 2.2 Build and initrd

Build with `make -j4 BUILD=release kloader sys-io` and keep `kernel`,
`kloader`, `kloader.bin`, `sys-io`, and `src/sys/lib/rt.vdso/rt.vdso` for
each build. The initrd is packed by `initrd.rs` (Appendix C): seven
little-endian `u32` words (magic `0xf402100f`, kloader start and end,
kernel start and end, sys-io start and end), `kloader.bin` at offset 512,
the kernel at the next 512-byte boundary, sys-io at the next 4096-byte
boundary.

Pitfall: restoring source files with their original timestamps let Cargo
treat them as unchanged, so one batch ran a stale diagnostic kernel. After
any restore, touch every changed input and rebuild; final evidence needs
a verified rebuild with fresh timestamps.

### 2.3 Guest harness

`bench.rs` (Appendix C), cross-built with
`rustc -O --target x86_64-unknown-motor`, is installed as
`/user/spawn-bench-cold` and invoked as
`bench <rounds> <modes> <program> [args...]`. For a cold sample `rounds`
must be 1 and `modes` a single mode. It runs the program with
`MOTOR_SPAWN_PROTO=<mode>` in the child's environment, stdin null, stdout
and stderr piped, measures `spawn()` and the whole run with `Instant`,
asserts the exact expected stdout for the program, a successful status,
and empty stderr, prints `output: <stdout>` to stderr once, and prints one
CSV row `mode,round,spawn_us,total_us,` after a header line.

The environment variable is inherited by the wrapper's nested rustc, which
is how `/devtools/bin/rustc` (a shell script) ends up launching rustc in
the prototype mode.

Expected outputs (the `bench-rustc-confirmation.rs` variant used for the
50-pair rustc run lacked the final Clang line, which is why the first
Clang baseline run failed its assertion and the fixture was corrected):

- `/devtools/bin/rustc`: `rustc 1.99.0-dev (b111eff31 2026-09-24) (1.99.0-beta-f47d5bb-motor.dev.2)\n`
- `/devtools/llvm/bin/llvm`: `clang version 23.1.0-rc1 (https://github.com/moturus/llvm-project.git 7c2a7b21e3dc7be1f0c41d443bc420bcc774b1d4)\nTarget: x86_64-unknown-motor\nThread model: posix\nInstalledDir: /devtools/llvm/bin\nConfiguration file: /devtools/cfg/llvm/x86_64-unknown-motor.cfg\n`
- `/system/bin/rush`: empty.

### 2.4 Host driver and pairing

`run-cold.sh <artifacts> <mode> <label> [count]` does, per sample: copy
the artifacts' `kloader` and `initrd` into the VM directory, boot, sleep
one second, optionally start `perf stat -p <vm pid> -e
cycles:G,cycles:H,instructions:G,instructions:H,context-switches,page-faults`
for 0.4 s (`SPAWN_COLD_PERF=1`), snapshot the hypervisor threads' CPU
accounting (`SPAWN_COLD_CPU=1`, `vm-cpu.py`) and the Cloud Hypervisor
counters (`SPAWN_COLD_COUNTERS=1`, `GET /api/v1/vm.counters`), run
`/user/$SPAWN_COLD_BENCH 1 <mode> <command>` over ssh with stdout to
`<label>-<n>.csv` and stderr to `<label>-<n>.stderr`, take the after
snapshots, optionally sleep `SPAWN_COLD_LOG_DRAIN` seconds, shut the VM
down, and print the CSV. `SPAWN_COLD_WORKLOAD` selects the command:
`rustc` runs `/devtools/bin/rustc --version`, `clang` runs
`/devtools/llvm/bin/llvm clang --version`, `rush` runs
`/system/bin/rush -c exit`. The baseline mode name is `eager`.

`run-pairs.sh <prototype artifacts> <mode> <label> [pairs]` runs
`run-cold.sh` for the baseline artifacts and for the prototype once per
pair, alternating which goes first on odd and even pairs, labelling
samples `<label>-base-NN` and `<label>-proto-NN`.

The counters JSON has `_disk0` with `read_ops`, `read_bytes`,
`write_ops`, `write_bytes`, and cumulative min/avg/max latency fields in
microseconds, plus `_net1` frame and byte counts. They include the ssh
session and the harness launch, so they are not exact rustc-only counts,
and the latency fields are cumulative statistics, not counts to subtract.

### 2.5 Installation and durability

`install-bench.sh <artifacts> [label] [--replace]` boots the VM, with
`--replace` first runs `/system/bin/chmod rwxrwxr-x` on the previously
installed files (the installer leaves them `rwxr-xr-x`, which gives the
Interactive role no write permission; Motor chmod takes the nine-character
role mode), uploads the harness to `/user/spawn-bench-cold` and the flush
helper to `/user/spawn-flush-file`, runs `chmod rwxr-xr-x` on both, runs
`/user/spawn-flush-file /user/spawn-bench-cold` (which opens the file and
calls `sync_all`), lists the file, and shuts down. Installation never runs
rustc or Clang.

`validate-flush.sh` proved durability across reboots: boot, compare the
installed harness with the host binary, write an 8,193-byte pattern
(`byte i = i*37+11`) with `sync_all`; reboot, verify it and write another
with `sync_data`; reboot, verify both. Before the fsync fix the rt.vdso
`fsync` and `datasync` entry points returned success without flushing, so
an installation that shut down right after `sync_all` was lost or
truncated (229,376 of 245,344 bytes observed). The fix routes both through
`posix_flush`, the existing descriptor flush, which also persists metadata.

### 2.6 Statistics

Ratio of baseline mean to prototype mean, median, nearest-rank p95
(`sorted[ceil(n*95/100)-1]`), range. Cold samples are all round 0 and are
all included; no outlier is dropped and minima are never substituted. The
warm prototype's `summarize.rs` printed round 0 separately and computed
its distributions from rounds 1 and later.

### 2.7 Other pitfalls met during measurement

- A diagnostic that wrote into the child's captured stderr failed the
  harness; a diagnostic log syscall without `CAP_LOG` panicked. Route
  diagnostics through kernel counters or SysRay logging, never the
  captured streams.
- Host `perf` failed with `perf_event_paranoid=4`; host `strace` of the
  hypervisor was denied by ptrace policy. No host setting was changed.
- The kernel's fill-byte counter counts submitted fill bytes, including
  pages already mapped; it is not a count of unique storage bytes.
- Instrumented runs overlap and nest; adding their counters double-counts.

## 3. The cold prototype: design of snapshot s100

Twenty-seven files changed; the complete diff is Appendix A. This section
explains what the code does and why, so that the appendix can be read
quickly or reimplemented differently.

### 3.1 Components

```text
launcher (rt.vdso)        kernel                      sys-io (pager)
-----------------         ------                      --------------
open file, read ELF
header + phdrs (4 KiB)
reserve FILE_PAGED  --->  sparse segment per PT_LOAD
segments (op 6/0)         + Mapping{id, owner, space}
read PT_DYNAMIC (<=4 KiB)
register (msg 0x7f00) -------------------------------> check role r+x,
                                                       create Relocations,
                          bind (op 6/6): peer check,   bind each mapping,
                          notify object, pending word  spawn serve() task
                                                       per segment,
                                                       prefetch (ctors,
                                                       relocation tree)
load vDSO (sparse), start child
                          child faults on page p:
                          enqueue(thread, p), park
                          thread, wake notify   ----> dequeue (op 6/2)
                                                       read window from
                                                       motor-fs / cache
                          fill (op 6/3 copy or   <---- supply pages
                          op 6/8 share frames),
                          resume waiters
                          exit: retire(space) --------> dequeue -> BAD_HANDLE,
                                                       task exits
```

### 3.2 Launcher: `rt_process.rs` and `rt_process/cold.rs`

`run_elf` scans the child's environment for `MOTOR_SPAWN_PROTO=cold-N`
with N from the accepted set {1, 2, 4, …, 32768, 65536, 131072, 262144}.
The cold loader is used when the file is at least 256 KiB (N >= 16384) or
50 MiB (smaller N). Otherwise the eager loader runs as before. After the
image is loaded, the vDSO is installed with `load_vdso_sparse(space, 2)`
for N >= 4096 (raw vDSO bytes and read-only loaded segments sparse), with
mode 1 for N >= 2048 (raw bytes only), or eagerly below that. The variable
is not stripped from the child's environment, so descendants inherit the
mode.

`cold::load(fd, size, space, window)`:

1. Reads the first 4 KiB. Requires ELF64, little-endian, version 1,
   `ET_EXEC` or `ET_DYN`, `EM_X86_64`, `e_phentsize == 56`, and
   `1 <= e_phnum <= 32` with the table inside the first page. (This is a
   prototype shortcut; a production parser reads the table wherever it
   is.)
2. Rejects any `PT_INTERP` (3) or `PT_TLS` (7). Records `PT_DYNAMIC` (2).
   For each `PT_LOAD` with nonzero `p_memsz`: requires readable, not
   W+X, `p_memsz <= 256 MiB`, `p_filesz <= p_memsz`, file range inside
   the file, no address overflow, and `p_vaddr % 4096 == p_offset % 4096`.
   Requires page-rounded segments to be ascending and disjoint.
3. For each segment, calls kernel op 6 flag 0 (reserve) with the
   page-aligned start, page count, protection bits (`p_flags & 3`: 1
   execute, 2 write), and `1` as a lazy-heap mode when N >= 65536. The
   kernel returns a mapping id.
4. Reads the dynamic segment (at most one page). Collects `DT_RELA` (7),
   `DT_RELASZ` (8), `DT_RELAENT` (9), `DT_RELACOUNT` (0x6ffffff9),
   `DT_INIT_ARRAY` (25), `DT_INIT_ARRAYSZ` (27); rejects nonzero
   `DT_REL` (17), `DT_JMPREL` (23), or `DT_RELR` (36). Requires
   `DT_RELAENT == 24`, `DT_RELASZ % 24 == 0`, `DT_RELASZ <= 16 MiB`,
   `DT_RELACOUNT == DT_RELASZ / 24`, and the table inside one segment's
   file bytes. Records the virtual addresses of the `DT_RELASZ` and
   `DT_RELACOUNT` value words ("consumed").
5. Takes the file's `EntryId` from the already-open descriptor and sends
   sys-io the registration message (3.8). Returns `e_entry`.

### 3.3 Mode encoding

The single number N selected every behavior. The validated mode was
`cold-131072`. Thresholds, with the final mode's selection in bold:

| Threshold | Behavior |
|---|---|
| N < 128 | Fixed read window of N pages, aligned to N pages within the segment |
| **N >= 128** | Adaptive window: 1 page, doubling on a consecutive fault, capped at 32, reset to 1 otherwise |
| **N >= 1024** | Constructor prefetch of 2 pages per `DT_INIT_ARRAY` target plus a 128-byte code-reference scan; below 1024, `max(N/128, 1)` pages and no scan |
| **N >= 2048** | Sparse raw vDSO bytes (`load_vdso_sparse` mode 1) |
| **N >= 4096** | Also sparse read-only loaded vDSO segments (mode 2) |
| **N >= 8192** | Local zero fill of whole-page BSS tails (op 6/12) after the pager finds no relocations there |
| **N >= 16384** | File-size threshold 256 KiB instead of 50 MiB |
| **N >= 32768** | Shared pending-request word; pager readiness spin source (200 µs budget) |
| **N >= 65536** | 16-page zeroed contiguous DMA pool; 4 interpolation probes and single-search forward scan in relocation lookup; persistent 1 s readiness watcher; prepopulate full read-only pages of files under 1 MiB; first-fault background read-ahead of 256 pages |
| **N == 131072** | First-fault background read-ahead of 128 pages instead of 256; the constructor-prefetch "ready" signal fires after constructor pages rather than after reference pages (vestigial; nothing waits on it) |

Independent of N while any cold session exists: virtio completion polling
with a 200 µs idle budget and descriptor coalescing of physically adjacent
buffers (both enabled by guards taken in `register`). Independent of N
altogether in s100: the rt.vdso allocator's slabs are lazily backed for
every unprivileged process (3.7), user-frame batching, the unrolled zero
loop, and batched page-table pruning.

### 3.4 Kernel

New `MappingOptions` bits: `FILE_PAGED = 1024` (external page fills),
`IMAGE_SPARSE = 2048` (resident read-only backing mapped on fault),
`ANON_SPARSE = 4096` (scratch lazy heap and stack descriptors; measured,
not selected).

`UserAddressSpace` (`mm/user.rs`):

- `reserve_file(start, pages, flags)`: charges `pages` to user stats and
  allocates a fixed segment with `READABLE | USER_ACCESSIBLE | FILE_PAGED`
  plus `EXECUTABLE` (flag 1) or `WRITABLE` (flag 2). No frames, no page
  descriptors.
- `fill_file(start, pages, share)`: admits `mapping_charge(count, count)`
  for the caller's class, then installs pages (below).
- `mark_file_zero(start)`: records the start of a whole-page zero tail in
  a writable file-paged segment.
- `alloc_cold_heap(n)`: lazy user allocation for unprivileged address
  spaces, ordinary eager heap for privileged ones (sys-io). Reached from
  `SysMem::map` flag `0x200`.
- `set_cold_lazy_heap(mode)`: mode 2 adds `ANON_SPARSE` to thread stacks
  and lazy heap; mode 1 does nothing in s100.
- `share_from` with `IMAGE_SPARSE`: allocates the fixed destination range
  and calls `share_with` instead of filling pages.
- `Drop` calls `cold_pager::retire(self)`.

`VmemSegment` (`mm/virt_intrusive.rs`) gained three fields: `image`
(`SpinLock<Option<Arc<Vec<SlabArc<Frame>>>>>`, the resident backing of an
`IMAGE_SPARSE` segment), `image_offset` (page index of this segment
within that backing), and `file_zero_tail`. Behavior:

- `allocate_pages` returns immediately for `FILE_PAGED`, `IMAGE_SPARSE`,
  and `ANON_SPARSE` segments. For ordinary eager user segments it now
  allocates physically contiguous frames in batches of up to 64 when the
  page options are uniform and the segment is not `LAZY`, falling back to
  single pages.
- `vaddr_map_status` and `pin_user_page` resolve `IMAGE_SPARSE` addresses
  through `image_page` (the backing frame at `image_offset + index`), and
  tolerate missing descriptors instead of unwrapping.
- `fill_file(start, sources, share)`: validates the range inside the
  segment and page alignment; rejects sharing into a writable segment;
  for each page not already present, either maps the source's own frame
  (share, only when the pinned source is a whole small non-MMIO frame) or
  allocates a frame, copies 4 KiB from the pinned source through the
  direct map, and maps it with the segment's options minus `FILE_PAGED`
  plus `DONT_ZERO`. Already-present pages are skipped, which makes fills
  idempotent and lets speculative fills land without waiters.
- `fix_pagefault`: for `IMAGE_SPARSE`, validates the error code (only
  not-present and instruction-fetch bits, fetch only on executable
  segments) and maps the 16-page-aligned window around the fault from the
  backing. For `FILE_PAGED`, validates the error code (write only on
  writable, fetch only on executable); if the address is at or past
  `file_zero_tail` and absent, allocates a fresh zeroed frame locally;
  otherwise returns `Ok` if the page is present (a race with a fill) or
  `E_NOT_READY` if absent. For `ANON_SPARSE`, allocates a zeroed frame on
  a user-mode fault.
- `share_with` for an `IMAGE_SPARSE` destination: refuses writable; on
  first use captures the source segment's frames into an `Arc<Vec>`
  (rejecting writable pages, huge or MMIO frames, or a size mismatch),
  then shares that `Arc` with the destination at `first_page` offset. No
  per-page descriptors are created in the destination.
- `unmap`: prunes the page tables of the whole range once
  (`prune_unmapped_range`) before the TLB flush, counts the full segment
  size for sparse kinds, and drops the image reference.
- The compile-time asserts on `SegmentNode` size (72) and nodes per page
  (55) were removed because the descriptor grew.

`UserAddressSpaceBase::fix_pagefault` routes faults in the custom region
(where the vDSO lives) to that region, which sparse vDSO mappings need.

`mm/mod.rs`: `zero_page` writes eight `u64` zeros per 64-byte line with
`write_volatile` instead of one `u64` per iteration.

`arch/x64/paging.rs`: `unmap_page` takes `prune: bool`; the batched path
passes `false` and `prune_range(start, end)` later walks each 2 MiB window
once, freeing empty L1, L2, and L3 tables.

`uspace/process.rs`: in `on_pagefault`, when `fix_pagefault` returns
`E_NOT_READY` and `cold_pager::enqueue(thread, addr)` returns true, the
thread stays `Live(Preempted)` with no resume job posted. New
`resume_file_fault(cpu, success)`: on failure, `post_kill(PageFault)`; on
success, if the thread is still `Live(Preempted)`, post the ordinary
`job_fn_resume_in_userspace` job on the given CPU (or mark it
`PausedDebuggee` if the process is paused).

`uspace/sys_mem.rs`: operation 6 dispatches to `cold_pager::run`;
`sys_map` with flags `R|W|0x200` and no addresses calls `alloc_cold_heap`;
`F_SHARE_SELF` maps with `0x100` set `IMAGE_SPARSE` (requires a source
address); `map_charge` ignores `0x200`.

`uspace/cold_pager.rs` (new, verbatim in Appendix A): a global
`BTreeMap<u64, Mapping>` under a spinlock, ids from an atomic counter
starting at 1. `Mapping` holds weak references to the owning process and
the target address space, the range, the reader thread (weak), a request
queue of page addresses, a waiter list of `(page, thread, cpu)`, fault
and byte counters, an optional notify `SysObject`, and an optional
pinned "pending word" in the reader's memory. Operations are selected by
the syscall `flags` field:

| flags | Caller | Effect |
|---:|---|---|
| 0 | owner | Reserve: `space.reserve_file`; optional lazy-heap mode; insert `Mapping`; returns id. Also purges mappings whose process or space is gone. |
| 1 | owner | Claim reader (parent-serviced mode): the calling thread becomes the reader. |
| 2 | reader | Dequeue: pops the next page of any mapping (or of `id`) whose reader is this thread, decrements the pending word; `E_NOT_READY` if none. |
| 3 | reader or owner | Fill by copy: `count <= 64` pages from a contiguous source buffer in the caller; pins sources, `fill_file(share=false)`, then resumes waiters inside the range with the result. |
| 4, 5 | owner | Diagnostic log lines. |
| 6 | `CAP_IO_MANAGER` | Bind: `args[2]` is the pager's handle to its connection with the client; `peer_owner` must be the mapping's owner and no reader may be set; creates the notify object (handle returned), optionally pins the pending word at `args[3]`; sets the reader. |
| 7, 9, 11 | `CAP_IO_MANAGER` | Diagnostic log lines and per-CPU kernel/user time query. |
| 8 | `CAP_IO_MANAGER` reader | Fill by sharing: `args[3]` points at `count` page addresses in the caller; `fill_file(share=true)`. |
| 12 | `CAP_IO_MANAGER` | `mark_file_zero(addr)` for the mapping's segment. |

`enqueue(thread, addr)` runs with the faulting thread's status lock held:
finds the mapping covering the address in the thread's address space; if
the page is already present (a fill raced), posts a resume job and
returns true; if no reader exists, returns false (the fault is fatal);
otherwise records the waiter, queues the page if not already queued,
increments the pending word, and wakes the notify object (or posts a wake
to the reader thread). Fills take waiters out of the registry under the
lock and resume them after releasing it. `retire(space)` drops every
mapping of a dying address space, stores `u64::MAX` into its pending
word, marks the notify object done, and wakes it.

What the kernel deliberately does not do here: no I/O, no frame
allocation at fault time, no knowledge of files, no per-page descriptors
for absent pages.

### 3.5 sys-io

`runtime/fs.rs`: command `0x7f00` dispatches to `cold_pager::register`;
reads with message flag bit 0 set skip the ordinary read-ahead; a
multi-block read issues the rest of its request as a grouped prefetch
after the first authorized chunk.

`runtime/fs/cold_pager.rs` (new; Appendix A):

- `register`: decodes the message as a write message carrying `len` bytes
  of `u64` words in a donated page (`104 <= len <= 56 + 32*48`,
  `(len-56) % 48 == 0`). Takes the completion-polling guard and, for
  N >= 65536, the 16-page DMA pool guard. Validates N, `DT_RELASZ`,
  init-array range, and each region (`memsz <= 256 MiB`, `filesz <= memsz`,
  not W+X, congruent offsets, file range inside the file). Checks the file
  is a regular file the caller's role may read and execute. Refuses under
  memory pressure. Builds `Relocations`, creates the shared `LaunchPins`
  (batch 64, gap 1), binds each region with op 6/6 passing the client
  connection handle and, for N >= 32768, the address of a per-region
  pending word, and spawns `serve` per region on the local runtime. For
  N >= 65536 and files under 1 MiB, prepopulates every complete read-only
  page by sharing. Starts `prefault::start` and replies with an empty
  success response.
- `serve`: loops on dequeue; when empty, rearms the notify handle, checks
  the pending word, registers a readiness spin source (budget 1 s with
  persistence for N >= 65536, else 200 µs), and awaits the handle.
  `E_BAD_HANDLE` means the mapping was retired. On the first executable
  fault it spawns a background `fetch_map` of the following 127 (or 255)
  pages clipped to the file range. Computes the window (adaptive or
  fixed), clips to the segment, and takes the filesystem read lock. For a
  read-only window entirely inside the file range: prefetch the blocks,
  obtain each as a clean `CheckpointedBlock` through `cold_page`, pin them
  in `LaunchPins`, and fill by sharing (op 6/8). Otherwise: zero a buffer,
  `read_range` the file bytes that intersect it, apply relocations for
  writable regions, and fill by copy (op 6/3).
- `read_range`: prefetches in batches of 128 pages as 16-page runs, then
  reads with ordinary `fs.read` calls, one page at a time, requiring full
  reads.

`cold_pager/prefault.rs` (new; Appendix A):

- `start`: prefetches the top six levels of the relocation search tree;
  for N >= 8192 marks each writable region's whole-page BSS tail (up to
  1 MiB) as locally zero-fillable when no relocation targets it; reads the
  relocation records that target `DT_INIT_ARRAY`, takes each value as a
  constructor address, collects the first 2 pages of each (deduplicated,
  read-only regions only), `fetch_map`s them, and for N >= 1024 scans the
  first 128 bytes of each constructor for references and `fetch_map`s
  those pages too. Panics on error (prototype shortcut).
- `fetch_map`: per batch of 64 pages, sorts them, merges into file runs
  (same region, ascending keys, gap at most 1 page, at most 16 pages per
  run), prefetches all runs concurrently, then for each run pins clean
  pages and fills by sharing, stopping a run at the first page that is
  not clean. Yields to I/O between batches smaller than 64. Stops when the
  session is no longer alive.
- `references`: for each constructor, reads up to 128 bytes (from pinned
  pages when all are pinned, else from the file), stops at two consecutive
  `0xCC` bytes after offset 16, and decodes `E8`/`E9` rel32 calls and
  jumps and REX-prefixed `8D`/`8B` with a RIP-relative ModRM (`& 0xC7 ==
  5`) as targets `function + end_of_instruction + rel32`; pages inside a
  read-only region that were not seen before are returned sorted. False
  positives only cause extra reads.

`cold_pager/relocations.rs` (new; Appendix A): described in detail in
the plan's Q2; in short, a `Relocations` object with the table's file
offset and count, the two "consumed" tag addresses, the writable ranges,
and a page cache of `CheckpointedBlock`s. `entry(i)` reads one record and
validates type 8 and a destination inside a writable range. `lower_bound`
is a binary search with bracket checks and up to 4 interpolation probes
after depth 6. `prefetch_tree` prefetches the pages of the first six
levels' midpoints. `apply(start, bytes)` finds the range (one lower bound
at `start-7` and a forward scan when `linear_end`, else two bounds), reads
records 64 at a time, validates each, checks monotonicity, stores the
addend bytes that fall inside the page, stops at the page end, then
stores zero into the consumed tag words if they fall in the page.

`runtime/fs/block_io.rs`: reads are submitted with `try_read_deferred`;
in-flight requests are a `Vec<InFlight>` polled in order instead of a
`FuturesUnordered`; the worker reclaims the used ring once per poll when
cold polling is on, kicks deferred submissions before pending, and
registers the virtqueue readiness watcher while requests are in flight.

### 3.6 Libraries

- `moto-io/src/fs.rs`: `FsClient::register_cold(file, words)` writes the
  words into a donated page and sends it as a write message with command
  `0x7f00`; `read_cold` is `read` with message flag 1 (no server-side
  read-ahead).
- `motor-fs/src/fs.rs`: `cold_page(role, file, key)` returns a clean
  `CheckpointedBlock` for file block `key` if the entry is a readable
  regular file, the block exists, and the cached block is not dirty;
  `None` for holes and dirty blocks. Existing copy-on-write preserves the
  snapshot.
- `async-fs/src/block_cache.rs`: when the free list is empty and cold I/O
  is active, `pop_free_block` refills it from `IoBuf::cold_read_buffers()`.
- `moto-tooling/src/iobuf.rs`: `ColdIoGuard::new(16|64)` enables the pool;
  `cold_read_buffers` allocates `batch` physically contiguous zeroed pages
  with `SysMem::alloc_contiguous_pages`, resolves the physical address
  once, and returns one `IoBuf` per page sharing an `Rc<ColdPages>` owner
  that frees the mapping when the last buffer drops; `phys_addr_at` adds
  the offset directly for pooled buffers.
- `fittings/src/iobuf.rs`: `unsafe fn from_raw(ptr, size_align)`.
- `moto-async/src/local_runtime.rs`: `SpinSource` gains
  `persist_through_park` and `idle_budget_ns`; the executor's idle spin
  budget is the maximum source budget capped at 200 µs; persistent sources
  that are not ready survive a park; `MAX_SPIN_SOURCES` 8 to 32.
- `virtio-async/src/virtio_blk.rs`: `try_request` merges physically
  adjacent pages into one descriptor while cold polling is on; a `DEFER`
  variant uses the existing `add_buffs_deferred`; `cold_poll(budget)`
  guard, `poll_read_completions`, `watch_read_completions` (a spin source
  on `has_new_used`), and `kick_reads` (`kick_deferred`). The deferred
  kick machinery itself already existed in the base tree.
- `virtio-async/src/virtio_queue.rs`: `cold_watch` registers that source;
  `reclaim_used_and_rearm` became crate-visible.

### 3.7 rt.vdso

- `load.rs`: `load_vdso_sparse(space, mode)`; mode >= 1 maps the raw vDSO
  bytes with `F_SHARE_SELF | 0x100`; mode 2 also maps the read-only loaded
  segments that way. Writable vDSO data is still copied and relocated per
  child.
- `rt_alloc.rs`: the allocator backend maps every slab with
  `R | W | 0x200`, which the kernel backs lazily for unprivileged
  processes. IPC buffers do not go through this path.
- `rt_fs.rs`: `AsyncFsClient::register_cold` runs the client call on the
  I/O runtime; `fsync` and `datasync` call `posix_flush`.

### 3.8 Protocol reference

Syscall encoding used by both sides: `nr = (SYS_MEM << 56) | (6 << 48) |
(op << 16)` with `do_syscall(nr, space_or_SELF, a, b, c, d, 0)`; results
in `data[0..1]`.

Registration message (`0x7f00`, a write message whose payload page holds
little-endian `u64` words): `[N, rela_file_offset, rela_bytes,
init_array_addr, init_array_bytes, consumed_relasz_addr,
consumed_relacount_addr]` followed by six words per region
`[mapping_id, vaddr, file_offset, filesz, memsz, p_flags]`. Up to 32
regions.

Fill semantics: `count <= 64`, page-aligned start inside the mapping,
sources page-aligned in the caller; op 3 takes a contiguous buffer, op 8
a list of page addresses to share. Present pages are skipped. Waiters in
the filled range are resumed with success, or killed if the fill failed.

Error codes seen by the launcher: `E_INVALID_ARGUMENT` for every parse
rejection, `E_BAD_HANDLE` for a non-file descriptor, filesystem errors
from registration (permission denied for non-executable files, invalid
input for bad regions, out of memory under pressure).

### 3.9 Shortcuts and known problems in s100

- `serve` and `prefault::start` `panic!` on errors; `cold_read_buffers`
  and the entry read-ahead use `expect`. A production pager must fail the
  page or the child instead.
- No execution lease or file-version check: a write to the executable
  during a launch can mix versions. `EntryId` generation detects
  replacement, not in-place writes.
- Relocation ordering is an unverified precondition: lld sorts, nothing
  guarantees it. The `consumed` tag rewrite is a Motor ABI extension the
  plan replaced with the mlibc change.
- Program headers must fit in the first page (at most 32).
- Raw numeric flags (`0x100`, `0x200`, op 6, command `0x7f00`) and the
  environment selector are scratch interfaces.
- Any process with `CAP_IO_MANAGER` can fill any mapping it has bound;
  binding requires only that the connection peer owns the mapping.
- Mapping ids are never reused but the registry is only purged on
  reserve; retired entries linger until then.
- The lazy slab hint applies to every unprivileged process, not only to
  cold-loaded children.
- The malformed-ELF panics in the eager loader remain for the eager path.

## 4. Experiment ledger, 2026-10-02

Chronological. Every number is a completed `rustc --version` command in
milliseconds from one fresh VM unless stated otherwise; early rows ran
with diagnostic serial logging enabled. Variants separated by `/` are
sibling runs in the order named. "Reverted" means the change is not in
s100. Sample labels are the result-file prefixes of the deleted archive.

### 4.1 Starting point

Linux maps ELF segments through file-backed `mmap` and serves faults
from the page cache with read-ahead; it never reads the executable into a
parent buffer. The hypothesis was a demand-filled image with metadata
proportional to populated pages, a small checked header and relocation
read, and private writable data. The earlier private pager had read
25.1 MiB for a version command.

Baseline: 378.567, 372.261, 378.405 (so the 10x target was about 37.6).

### 4.2 Fault service placement and sharing

| Variant | ms |
|---|---:|
| Parent-serviced pager, fixed windows of 4 / 16 / 64 pages | 132.647 / 149.149 / 152.954 |
| Grouped reads, w4; direct fills, w4 / w1 | 126.286; 134.982 / 112.619 |
| Service moved into sys-io, w4 / w16 / w1 | 93.587 / 112.880 / 89.553 |
| sys-io profiles, w1 | 87.430 / 91.740 |
| Copy from pinned source pages (no temporary kernel buffer), w4 / w16 / profile w1 | 86.240 / 101.960 / 97.992 |
| Lazy writable pages with relocation in sys-io, adaptive | 120.503 (regression: the relocation read in sys-io was slower than the parent's pipelined read) |
| Handoff, adaptive / w4 | 101.756 / 111.053 |
| Bounded parallel read streams, adaptive | 90.636 (recovered part of the loss) |
| 64 separate single-page requests, adaptive | 110.880 (slower than grouped) |
| Share clean cache pages (`CheckpointedBlock`), adaptive / w4 | 95.361 / 92.139 |
| Constructor prefetch from `DT_INIT_ARRAY`, adaptive / w4 | 92.255 / 105.450 |

Sharing cut read-only page installation from 8 to 12 ms to under 1 ms.
Adaptive windows reduced read-only faults from 2,006 to about 1,113.
Constructor prefetch reduced text faults from 848 to 337 but its cold
reads consumed the saving. Huge-backed source pages fall back to copies.

### 4.3 Notifications, relocation handoff, sorted lookup

| Variant | ms |
|---|---:|
| Batched virtio kicks | 95.514 |
| I/O profile; larger read runs; completion polling | 107.086; 89.957; 93.241 |
| Quiet runs: perf attachment (failed, `perf_event_paranoid=4`) / CPU | 87.101 / 78.214 |
| Buckets | 80.715 |
| Consumed relocations (zero `DT_RELASZ`/`DT_RELACOUNT` in the child's private dynamic data), adaptive / w4 / profile | 79.299 / 85.414 / 85.246 |
| Sorted-table binary search, adaptive / w4 | 55.271 (about 6.8x) / 77.010 |
| Density read-ahead: control / grouped / no idle spin / both | 56.599 / 71.373 / 64.652 / 65.873 |

The consumed-relocation change cut writable input from about 2.9 MB to
0.11 MB for the first writable segment. The 146,639 relative entries are
ordered by destination in this rustc, which the binary search relied on.
Increasing read windows and disabling idle spinning did not help.

### 4.4 Code-reference prefetch and relocation page pins

| Variant | ms |
|---|---:|
| Constructor references, scan depth 1 / 2 / 3 | 59.710 / 84.784 / 68.951 |
| Relocation page pins, adaptive / with depth-1 hints (first pair overlapped a host build) | 63.951 / 50.793 |
| Same without the overlapping build | 67.947 / 64.271 |
| Profiled page-pin modes, adaptive / hints | 70.956 / 60.009 |
| 128-request batches, no scan / 128-byte scan | 63.216 / 60.259 |
| 512-byte / 2048-byte constructor scans | 91.855 / 100.171 |

The profiled 128-byte scan had 87 read-only and 418 text faults against
234 and 458 for its control; registration took 17.7 and 21.7 ms; demand
I/O about 15.5 and 20.3 ms; shared-page fills under 2 ms. The first
code-reference trial crashed sys-io: mode 1024 took the fixed-window path
and requested 4 MiB from a 256 KiB buffer.

### 4.5 Isolation runs

| Variant | ms |
|---|---:|
| Post-fill yield: control / yield / no poll / both | 70.369 / 66.470 / 69.055 / 66.543 |
| Refreshed unmodified controls | 376.605 / 377.990 |
| Refreshed earlier sorted-table prototype | 57.188 / 66.618 |
| Constructor 1 / 2 / 4 pages; no constructor prefetch | 63.231 / 82.422 / 81.527 / 61.140 |
| Up-front filesystem block index (transient, invalidated on mutation), with / without hints | 67.314 / 65.276 (no gain; discarded) |
| 200 µs inline completion polling, with / without hints | 70.839 / 60.861 |
| Background constructor prefetch, 1 / 2 pages; no hints | 54.834 / 52.927 / 62.510 |
| Same, instrumented | 60.723 / 52.122 / 61.973 |

In the instrumented two-page sample, summed fill waits were 25.44 ms
(2.56 ms before the pager fetched the request), resumption delays totalled
2.86 ms, fault counts were 234 read-only, 357 text, 27 + 37 writable, and
background prefetch took 11.96 ms overlapped with startup.

### 4.6 Streaming prefetch, relocation tree, sparse vDSO

Streaming constructor-order prefetch measured 58.218 / 57.770 / 62.569
for 1 / 2 / 4 pages and 53.886 with 128-byte reference hints, but those
runs had kept a stale diagnostic kernel (timestamp-preserving restore);
rebuilt, 56.106 (2 pages) and 50.243 (hints). Prefetching the first six
relocation-tree levels plus relocation page pins: 54.293 / 51.939
(2-page / hints). Coalescing predicted pages into file runs: 52.945 /
50.955.

Sparse resident vDSO mapping: 60.592 ordinary / 45.192 sparse raw bytes /
45.012 sparse raw bytes plus read-only segments, single samples.

| Variant | ms |
|---|---:|
| Interpolation relocation lookup, raw / all-sparse vDSO | 50.178 / 51.781 (reverted at the time) |
| Reused filesystem client plus interpolation, raw / all | 52.891 / 52.210 (reuse kept) |
| Binary lookup control / BSS prefill / also lazy shell | 50.855 / 54.004 / 48.781 |
| Fault lookahead: control / 128 / 256 bytes | 49.590 / 49.602 / 52.529 |

BSS prefill cut the second writable segment's faults from 37 to 4 without
a time gain. Fault-time reference guesses reduced text faults but not
time. Applying the pager to the shell wrapper itself worked.

### 4.7 Mapping, affinity, teardown, local BSS

| Variant | ms |
|---|---:|
| Map coalesced runs: control / pipelined 128 / pipelined 2048 | 48.250 / 50.177 / 52.134 |
| Affinity-aware wakes (FS thread keeps CPU 0, child resumes on its CPU), same modes | 50.526 / 51.934 / 48.361 |
| Background density: control / 64 KiB / 128 KiB | 50.442 / 54.027 / 55.911 |
| Batched teardown with quiet counters / local BSS zero tail / also lazy shell | 47.770 / 47.758 / 46.863 |

Density read-ahead cut text faults from 326 to 179 but increased read
amplification and time. A profile at 55.918 (with diagnostics) had
summed file-fault waits 26.957 ms, queue delay 2.844 ms, resumption
2.263 ms, and demand fill calls about 1.227 ms. The hypervisor counters
around the zero/teardown trials showed 8,093,696 extra bytes in 1,147
extra device requests, including the ssh session.

### 4.8 Allocation and scheduling

| Variant | ms |
|---|---:|
| Idle completion poll budget 20 / 50 / 200 µs | 45.489 / 47.162 / 44.679 |
| Code lookahead: control / one level / two levels | 48.172 / 48.975 / 46.561 |
| Prefetch batch 64 / 16 / 8 | 48.706 / 46.069 / 47.197 |
| Shared pager pending counter: control / enabled | 48.609 / 46.323 |
| sys-io syscall timing diagnostic | 47.533 |
| Allocate the copy scratch buffer only when needed | 45.436 |
| Batch physical frames for user mappings | 41.527 |
| Page-allocation substage diagnostic | 42.514 |
| `ptr::write_bytes` zeroing | 44.458 |

Diagnostics: 103 sys-io map calls cost 9.025 ms; lazy scratch allocation
reduced that to 7.472 ms, of which 29 allocations of 64 pages cost
6.506 ms; zeroing across the launch was 8.414 ms; frame batching itself
0.121 ms; page descriptors 0.318 ms. The first frame-batching build hung
before sys-io started because allocating a vector in the kernel's own
mapping path recursed into its heap; batching was restricted to user
mappings.

Uninitialized DMA buffers (privileged, published only after a complete
read) cut sys-io mapping time from 8.056 to 1.604 ms and zeroing from
9.386 to 2.588 ms, yet the command was 41.512; without diagnostics,
zeroed / raw 41.315 / 41.699; with the executor spin table widened from 8
to 32 slots 41.893 / 39.680; one constructor page 38.406 zeroed versus
41.733 raw, two-page raw control 41.668. Bytes read after the counter
snapshot: 6,963,200 (one page) versus 8,093,696 (two). Raw buffers were
removed.

| Variant | ms |
|---|---:|
| One page per constructor, no references / with references | 50.361 / 43.424 |
| Two pages per constructor, no references | 46.146 |
| Parallel constructor and reference batches, one / two pages | 42.268 / 43.652 |
| Sequential control | 41.533 |
| Padding-bounded reference scans 128 / 256 / 512 bytes | 42.526 / 41.571 / 42.879 |
| Transient virtio interrupt suppression: control / enabled | 44.789 / 41.068 |
| Further control / transient suppression / persistent watcher | 41.510 / 44.940 / 54.276 |
| Runtime timing diagnostic; per-future diagnostic | 42.985; 43.119 |

The runtime diagnostic measured 19.156 ms polling futures, 12.260 ms in
active executor polling, 1.700 ms in kernel waits; the next one 18.849 /
12.059 / 1.982 with nested costs of 5.760 ms demand service, 5.882 ms
prefetch, 6.813 ms block worker (subsets, not additive). The candidate
kept the 128-byte scan stopping at repeated INT3 padding after byte 16,
ordinary interrupt delivery, and the transient completion watcher.

### 4.9 Small-program prefill, worker polling, first-fault window

Small-executable read-only prefill (Rush, under 1 MiB): 45.042 control,
40.834 enabled; block-worker diagnostic 40.112 with submission / doorbell /
reclaim costs 0.319 / 1.213 / 2.129 ms. Cloud Hypervisor registers its
notification address with `NoDatamatch`, so a write-width mismatch was
ruled out. The flat `Vec<InFlight>` worker with one used-ring check per
poll: 41.203, 38.816, 39.194. Read-ahead at the first text fault: one
page 38.919 / 37.724, two 38.646 / 40.467, four 40.875 / 46.474 (larger
windows reverted).

Relocation-search anchors with tree prefetch depth 6 / 3 / 0: 40.659,
44.274 / 39.904, 41.439 / 41.864, 38.216 (reverted). The five-pair
refresh in 1.2 followed.

### 4.10 Lazy allocation

Redirecting every heap allocation of cold children to the lazy mapping
API failed: Rush's `AsyncFsClient::get()` returned `InvalidArgument`
because the filesystem channel's shared ring must be fully backed before
sharing (controls 41.503 / 40.224). Narrowed to the rt.vdso slab backend:
eager 41.447 / 42.677 versus lazy 36.919 / 42.568 / 38.482. Sparse lazy
heap and stack descriptors (`ANON_SPARSE`): ordinary lazy 39.947 / 37.795
versus sparse 38.782 / 40.841 / 38.535 (no gain; guard pages kept).

Reading constructor scan bytes from the launch's pinned pages: 128 bytes
38.605 / 42.626, 192 bytes 41.497 / 40.676, 256 bytes 40.277 / 41.128. A
two-stage pipeline fetching the next constructor batch while scanning the
current one: control 38.210 / 41.048, 16-function 42.594 / 42.864,
32-function 40.757 / 39.771 (negative). Lazy sys-io slabs committing
zeroed DMA pages at physical-address resolution: controls 40.870 / 39.669,
16-page batches 39.118 / 40.025 / 41.680, 8-page 46.323 / 39.817 / 43.131
(reverted). Prefetching before child execution: background 38.888 /
37.208, wait for constructor pages 41.207 / 41.112, wait for constructors
and references 42.172 / 40.650 (negative).

A loader-stage diagnostic (40.757 with logging) timed `run_elf` stages
for Rush at about 52 / 1,129 / 227 / 95 / 55 / 6 µs (address space, ELF
load, vDSO, process creation, stdio, wake) and for the nested rustc at
24 / 752 / 144 / 55 / 206 / 4 µs.

### 4.11 Pager watches, cursors, relocation search variants

Persistent pager readiness watches (one-second registration lifetime):
200 µs control 38.325 / 37.508; persistent with 16-page batches 39.641 /
40.393 / 37.860; persistent with 64-page batches and no inter-batch yield
37.405 / 38.787 / 38.337. Moving the cwd out of the filesystem client:
38.095 / 35.985 / 42.942 (reverted; only Rush opens a filesystem
connection for this command).

A diagnostic at 43.225 ms gave per-region fault counts of 74 read-only,
404 text, 27 first writable, 4 second writable, with total waits 2.940 /
16.774 / 4.441 / 0.191 ms, enqueue-to-reader 0.149 / 1.957 / 0.035 /
0.003 ms, and pager relocation work 3.078 + 0.102 ms.

Relocation search isolation with persistent watches and 64-page batches:
binary search plus top-six-level read-ahead 40.626 / 38.268; four
interpolation probes then binary search without tree read-ahead 42.436 /
45.824 / 44.146; full relocation-table read-ahead 43.802 / 42.386 /
44.984 (both alternatives reverted).

Speculative gaps between read runs: two-page-gap control 38.555 / 38.051;
no gaps 39.930 / 38.708 / 35.281; one-page gaps 37.417 / 40.939 / 34.549,
reading about 6.93 / 6.61 / 6.72 MB in 1,251 / 1,368 / 1,300 device
reads. Overlapping writable-data and relocation reads: sequential 38.134 /
39.803; overlap 42.345 / 38.633 / 39.915; also prefetching the touched
page's record range 39.584 / 43.668 / 42.487 (reverted). Thirty-two
per-file lookup cursors: 42.373 / 37.656 / 38.499 / 39.908 (reverted).
Inspection found 146,638 of 146,639 relocation targets are zero in the
file.

### 4.12 Final tuning before the paired comparisons

Taking the file identity from the open descriptor instead of a second
metadata query: control 37.864 / 40.580; flat boxed completion polling at
batch 64 42.054 / 39.510 / 37.878, at batch 16 39.046 / 38.532 / 40.352
(completion handling reverted, identity reuse kept). A read window only
at the first text fault: 1 page 39.837 / 38.538, 16 pages 37.990 /
42.597 / 40.384, 64 pages 40.146 / 39.633 / 40.090 (discarded). The
kernel's zeroer was a scalar eight-byte loop; alternating scalar /
unrolled pairs 39.745 / 42.636, 39.442 / 37.580, 40.466 / 37.918, means
39.884 / 39.378 (unrolled kept, inconclusive). Background init-array page
filling 40.756 / 40.284 / 38.016 / 37.484 versus controls 36.329 / 39.188
(reverted). Local interpolation inside the six-level bracket: binary
control 39.721 / 38.791; two probes 39.137 / 39.349 / 39.612; four probes
38.427 / 37.364 / 39.145, means 38.312 versus 39.256 (four probes kept).
Type sizes: prefetch future 784 bytes (880-byte task), relocation
application 2,608 bytes, pager task about 3,200 bytes per segment.

Launcher-wide lazy slabs: 48.502 / 36.008 / 37.477 / 41.825, then the
20-pair 9.56x. Contiguous zeroed DMA pool: control 39.757 / 38.180,
64-page pool 43.938 / 38.630 / 38.101 / 40.054, 16-page pool 41.034 /
38.518 / 37.045 / 38.865 (mean 38.866 against 38.969, a tie). Descriptor
coalescing: control 40.220 / 38.500, 64-page 38.205 / 38.966 / 39.652 /
37.421, 16-page 37.274 / 37.950 / 37.608 / 34.793 (mean 36.906), then the
20-pair 9.66x with one 51.208 sample. Single-search relocation (forward
scan from one lower bound): two-bound control 38.086 / 40.360 / 40.474,
forward 38.467 / 40.677 / 37.489 / 37.817 / 38.140, means 39.640 / 38.518
(kept). Constructor read widths with coalescing and forward scans: one
page 37.685 / 51.647 / 39.364, two pages 38.624 / 37.131 / 35.397 /
35.606 (mean 36.690), three pages 39.382 / 40.980 / 40.177 / 38.703 (two
kept). Background first-fault read-ahead: control 35.451 / 38.981 /
40.668, 128 pages 40.002 / 34.252 / 36.649 / 37.163 (mean 37.017), 256
pages 41.345 / 38.778 / 40.362 / 40.656 (128 kept), then the 20-pair
10.07x.

### 4.13 Confirmation

The strict harness, which also byte-compares the first stdout, first
failed before timing: the installed harness was not executable, then
truncated, because the installation shut the VM down after a `sync_all`
that did nothing. The fsync fix was authorized, installation and the
three-boot durability check passed, and s100 differs from s99 only in the
two sync entry points. The 50-pair rustc run gave 10.09x. The first Clang
baseline failed on the fixture's missing "Configuration file" line; the
fixture was corrected, the installer gained `--replace`, and the 10-pair
Clang run gave 7.87x. The 10-pair Rush run gave 1.32x.

## 5. The earlier warm prototype, 2026-10-01

Six opt-in patches (Appendix B), each selected by the value of
`MOTOR_SPAWN_PROTO` in the launch environment: `cache`, `cache-sparse`,
`cache-sparse-vdso`, `cache-sparse-vdso-sparse`, `cache-sparse-hot-vdso`,
`cache-family-vdso`; anything else used the ordinary loader. The variable
was stripped from the child's environment except for `cache-family-vdso`.
Both loaders in rt.vdso were in scope; the kernel's loader of sys-io was
not changed.

### 5.1 Mechanisms

1. **Prepared image in the launcher** (`rt_process/spawn_cache.rs`): one
   static slot keyed by `(entry_id, modified, size)`. On a miss the whole
   file is read, loaded with elfloader into a template address space, and
   the loader's local aliases are retained. On a hit, read-only segments
   are mapped into the child from the template with `SysMem::map`, and
   writable segments are copied from the relocated template through
   `map2` aliases. This avoids repeated reads and relocation but still
   maps every page.
2. **Sparse mappings** (`IMAGE_SPARSE = 1024`, `SysMem` flag `0x100` on a
   `F_SHARE_SELF` map): the destination segment references the source's
   frames once (`share_with` captures them into an `Arc<Vec<SlabArc<
   Frame>>>`) and creates PTEs and page descriptors only on faults, 16
   pages per fault. The same mechanism survived into the cold prototype.
3. **vDSO templates** (`load.rs::load_vdso_prepared`): a pristine,
   already-relocated vDSO image is built once in a template address space;
   each child gets the read-only segments shared (optionally sparse for
   executable ones) and a fresh copy of the writable data from the
   template, never from the live parent. Faults in the custom region had
   to be routed (`UserAddressSpaceBase::fix_pagefault`); the first sparse
   vDSO run killed the child at its first vDSO instruction because that
   route was missing.
4. **Learned pages** (`IMAGE_WARM = 2048`, flag `0x200` with `0x100`): the
   backing records one bit per 16-page window on each fault; a later
   mapping created with the warm flag pre-maps every window that was ever
   used. Unbounded and never aged.
5. **Batched teardown**: `unmap_page(prune=false)` plus `prune_range` once
   per 2 MiB window. Also in the cold prototype.
6. **Family cache** (`sys_mem/image_cache.rs`, `SysMem` operation 5): one
   kernel slot holding a key (five words: entry id, modified, size), the
   publisher's address space, the entry point, and up to 16 segment
   records `[start, pages, flags]`. Only the first process to use the slot
   may publish (flag 1), and only that process or a descendant with the
   same role may acquire (flag 0). Acquisition admits
   `mapping_charge(pages, 2*pages)`, shares read-only segments sparse and
   warm from the publisher's space, and copies writable segments page by
   page through a temporary alias. Lineage is checked by walking
   `process_stats` parents. Cleanup after publisher death happens on the
   next cache operation.

### 5.2 Why it was not adopted

A parent-local hit cannot accelerate the public wrapper, since each new
shell is a new parent (170.380 ordinary versus 172.265 prototype). The
family cache fixed that but is a scoped experiment: identity by mtime and
size, not content version; one entry; unbounded learned windows; the
whole image resident; no production fairness, pressure, or mutation
story; and a first uncached command still took about 171 ms. The cold
prototype replaced it. The plan keeps the shared-backing and sparse
mapping ideas (Steps 9 and 10) and the batched teardown (Step 15c).

### 5.3 Recommendations it recorded

Cache ownership should move to sys-io (identity, permissions, file
version lifetimes) and the kernel (sealed backing, mapping references);
keys need a content generation, not mtime; publication must cover one
consistent version from the first header read through the last byte;
replacement invalidates future acquisitions while running processes keep
their frames; bound bytes and entries and evict under pressure; nothing
on the boot path. Shared read-only leaf page tables (2 MiB windows with
private tables at protection boundaries) were proposed and not
prototyped. Huge executable pages were not measured.

## 6. The original lazy-pager proposal, 2026-10-01

Written before any prototype; its 10x expectation was disproved by the
first pager (3.42x). Its analysis of snapshots, pending faults, and
pressure fed the plan's decisions 1 and 3.

Scope: read-only segments (92 to 97% of pages) demand-loaded through
sys-io with the kernel as broker; writable segments eager, read straight
into `map2` aliases without a file-sized buffer; a `SysMem::populate`
operation; a defined outcome for faults under pressure. Out of scope:
text sharing, the kernel loader, Rust std and moto-rt, reclaiming loaded
pages, lazy writable segments, general `mmap`, RELRO enforcement.

What the eager loader costs today: a file-sized buffer in the parent,
the whole file read through sys-io (block cache to io_page, io_page to
buffer, 48 KiB per request, four in flight), `map2` with fresh zeroed
frames per segment, a copy per segment through the alias, one write per
relocation, then free and unmap: every byte zeroed twice and copied three
times after the device read. About 1.3 ms per MB of binary; a trivial
rustc launch 150 to 180 ms, roughly half of it the device read (1.2 to
1.4 GB/s uncached, 5.2 GB/s from the block cache, which stops at 16 MiB,
so rustc and llvm always come from the device).

Design points worth keeping:

- Naming the target without handle transfer: the pager names the child's
  address space by the client's own handle, resolved through
  `shared::peer_owner`; the kernel accepts only address-space objects and
  refuses a paged segment in the pager's own space.
- Fault outcome "pending": the thread stays `Live(Preempted)` with no
  resume job; a fill posts `job_fn_resume_in_userspace` on the faulting
  CPU; kills and debugger pauses use the existing `Preempted` branches.
- Registry rules: the region lock and the pager lock are never held
  together; waiters are registered under the pager lock with the page
  re-checked; fills resume waiters after releasing the lock; frames are
  allocated and filled before the region lock; released mappings keep
  their registry entry until the next fetch reports them; mapping ids
  are never reused.
- Pressure table: fault while the pressure flag is up, flag rising before
  service, admission refusing frames, I/O error or validation failure all
  kill the process; the same during `populate` return an error and kill
  nothing; spawn under pressure is refused as today. File-backed faults
  die at the 512-page watermark (clearing at 768) while anonymous faults
  survive to the 256-page floor.
- `populate(F_POPULATE_FILE | F_POPULATE_ANON)`: short restartable kernel
  operation (64 anonymous pages per call; file mappings queue an
  "all pages" request and return `E_NOT_READY` for the wrapper to wait
  and retry), so the kernel never blocks inside the syscall.
- A mapped file does not change: before any mutation of a file with live
  mappings, sys-io loads every remaining page of those mappings under the
  filesystem write lock, retires them, then proceeds; refused fills fail
  the mutation with `OutOfMemory`. The plan replaced this with an
  execution lease (decision 1) after review.
- Copy-in from an untouched page: the kernel refuses frame-less pages;
  for `SysObj::get` and `SysRay::log` arguments it would return a retry
  flag with the address, and `do_syscall` would touch the byte and repeat.
- Snapshot consistency during loading: either exclude writers from the
  first header read to the last eager read, or validate a content
  version captured at the header read; `EntryId` generation is not a
  content version.

Open questions it listed: the kill threshold; which services populate at
startup (proposal: sys-init, sys-tty, strobe, dns-resolver, russhd, rush,
systest) or a size threshold for eager loading; populate flags; the
mapped-file rule versus a busy error; the copy-in retry flag; the rollout
environment key; exposing populate beyond moto-sys; the snapshot
protocol. Its patch list ran: parser; single-copy eager loader; moto-sys
API; paged segments; `mm/pager.rs`; fault path; motor-fs cached range;
`CMD_MAP_FILE` codec; sys-io mapping table and mutation rule; pager task;
lazy segments behind a launch-only key with `lazy_image` tests; copy-in
retry; populate; populate in services; lazy by default; documentation.
Its test list covered parser fixtures, malformed executables, a child
self-check of relocated pointers, data, BSS, and constants, concurrent
faults, exits with pages absent, parent exit before the first fault,
role refusal, pending-fault teardown, mutation of a mapped file, mutation
during loading, and pressure tests on the `pressure.rs` helpers.

## 7. Facts about the binaries

Release binaries and the developer image's toolchain, from `readelf`:

| Binary | File | Read-only pages | Writable pages | Relocations |
|---|---:|---:|---:|---:|
| rush | 0.67 MiB | 169 | 5 | 731 |
| russhd | 4.1 MiB | 965 | 82 | 6,411 |
| lorry | 7.7 MiB | 1,929 | 50 | 7,732 |
| rust-analyzer | 28.4 MiB | 6,964 | 322 | 72,985 |
| rustc | 113.5 MiB | 28,359 | 859 | 146,639 |

- All are static PIEs linked at address zero, no interpreter, no TLS
  segment. Two layouts occur: GNU ld `R, R+X, R, RW` and lld
  `R, R+X, RW, RW`.
- Every relocation is `R_X86_64_RELATIVE` and lands in a writable
  segment. In every `PT_LOAD`, offset and address are congruent modulo
  4 KiB; segments never share a page in memory but may share one in the
  file.
- The RELRO part of the writable segments has a relocation in every page
  (rustc 696 of 696, rust-analyzer 294 of 294). 146,638 of rustc's
  146,639 relocation targets hold zero in the file.
- rustc's read-only part is 82.5 MiB of text, 10.3 MiB of constants,
  14.6 MiB of unwind tables, and a 3.4 MiB relocation table
  (`.rela.dyn` 3,519,336 bytes at file offset 0x290; `.data.rel.ro`
  2,835,344 bytes at 0x6ec7310; `.dynamic` at 0x717c3f0). The same
  relocations in `DT_RELR` form would be about 45 KB.
- A `rustc --version` run under the pager touched 74 read-only, 404
  text, and 31 writable pages; the relocation table itself is never read
  by the program and the unwind tables only when unwinding.
- mlibc-linked programs (rustc, Clang) enter through crt1.o's
  `motor_start` into `__dlapi_enter`, whose `linkObjects` walks the whole
  relocation table twice; Rust-only programs use std's weak `motor_start`
  and never re-relocate. Base is 0, so the repeat is idempotent.

## 8. Reconstruction notes

- Apply Appendix A to `6ef7737b` to recover s100 exactly; the manifest
  hashes in 1.1 verify the result. Appendix B applies in order to the same
  base for the warm prototype. The fsync fix is the `rt_fs.rs` hunk of
  Appendix A and is the only change the production tree kept.
- The 2026-10-03 implementation proposal and its open questions are
  preserved in Appendix D. Section 9 records the 2026-10-04 change to
  sys-io loading; follow the current main plan for component ownership,
  file locks, scope, and gates. Historical step and Q numbers elsewhere
  in this archive refer to Appendix D.
- The numbers to reproduce first are the baseline (about 375 ms) and the
  per-fault profile (3.11): 404 text faults at about 40 µs each, 16.8 ms,
  dominate; relocation work is about 3 ms; everything else is a few ms.
- Measured truths that constrain any redesign: a private per-child pager
  reads 25 MiB for a version command and lands at 3.4x; service must be
  in sys-io, not the parent; clean read-only pages must be shared, not
  copied; the C runtime must not re-walk the relocation table; prefetch
  pays only when it is cheap (two constructor pages plus a 128-byte
  reference scan) and loses when it is wide; whole-table relocation reads
  cost about 5 ms; raw DMA buffers, wide first-fault windows, extra
  cursors, parallel prefetch pipelines, and persistent watchers did not
  pay.
- Stage snapshots s0 to s100 existed in the deleted tarball; only s99
  (before the sync fix, 20 pairs at 10.07x) and s100 matter.

## 9. Architecture revision (2026-10-04)

The current [plan](spawn-optimization.md) moves executable loading and
target address-space construction into sys-io. The parent calls a spawn
service through rt.vdso and keeps its stdio relays. This revision has not
been prototyped or measured. The earlier mechanisms and results above
remain evidence for individual design choices, not results for this
architecture.

### 9.1 What the prototype did not explore

The original lazy-pager proposal scoped user-binary loading to
`rt.vdso/src/rt_process.rs`; the warm prototype also kept loading in
rt.vdso. The cold experiment ledger then records moving fault service
and page-local relocation into sys-io while leaving ELF metadata reads,
segment reservations, vDSO setup, and process creation in the launcher
(sections 3.1, 3.2, and 4.2).

Neither the archived record nor the prototype README/design notes record
a trial of complete ELF loading and child construction in sys-io, or a
reason for rejecting it. Continuing the existing loader architecture is
a plausible explanation, but the agent's reason is not documented. There
is no measured comparison that rules out the new approach.

### 9.2 Delegation and startup details

- Today `Process::new_child` in
  `src/sys/kernel/src/uspace/process.rs` takes its parent and capability
  authority from the calling thread, and `sys_obj.rs` returns a handle
  in that caller's table. Service construction must separate the builder
  from the logical parent. Authenticate the requester through its IPC
  connection; never accept a client-supplied PID as authority. The
  delegated kernel operation is restricted to the authorized sys-io
  service and checks the requester's spawn, capability, role, and detached
  permissions. Admission remains tied to the child, not sys-io's reserves.
- Transfer/install a caller-valid process handle and the necessary pipe
  endpoints. A numeric handle in sys-io's table is not a handle in the
  parent's table. Keep the child stopped until all startup data and stdio
  wiring are ready. Exact handle handoff and start coordination belong to
  the private spawn protocol; they do not require a new application API.
- `rt.vdso/src/stdio.rs` and `stdio_relay.rs` keep the parent-side
  descriptors, relay tasks, terminal behavior, completion groups, and
  drain-before-wait-completion behavior. Borrowed stdio descriptors stay
  open on success and failure. sys-io installs the child-side startup
  descriptions; it does not acquire the parent's relay role.
- Snapshot the launch inputs before using them. Preserve current path,
  PATH, and script resolution, distinguishing the caller's lookup context
  from the child's requested environment and working directory. Never use
  sys-io's environment, cwd, descriptor table, or extra privileges.
- Construction owns a temporary executable lease; kernel mappings own
  lasting references before that temporary ownership is released. Abort
  releases incomplete mappings, handles, startup buffers, endpoints, and
  leases. Define one completion point and serialize requester exit,
  disconnect, and cancellation with it. Once committed, normal child and
  detached-child lifetime rules apply; the IPC connection does not own the
  running child's backing.
- The kernel still loads sys-io eagerly. Its spawn handler calls the
  internal loader directly, without calling the public spawn entry again.
  sys-io's own launch of sys-init must work after its service runtime
  starts, without recursive service waits or new boot-time preparation.

### 9.3 Decisions carried forward and superseded

- No numeric performance gate; retain correctness checks and report the
  measured ratio. The 10.09x result belongs to s100, not this revision.
- The reviewed executable lock rejects all mutations with
  `E_NOT_ALLOWED`, including writes through existing handles, truncate,
  unlink, rename, replacement, and metadata changes. This supersedes the
  old plan's Linux-style rename/unlink allowance and open Q8. Lock the
  file identity before reading metadata and keep it until all construction,
  mapping, pending cleanup, and I/O/backing references are gone.
- General mmap and public reserve/bind/populate/unmap APIs are not
  prerequisites. Segment layout and relocation descriptors stay inside
  sys-io and its privileged kernel protocol. Kernel teardown revokes access
  and queues release; sys-io completes cleanup without delaying unmap.
- The approved runtime handoff changes **`../toolchain-src/mlibc`**:
  omit the redundant executable relocation walks and relink the developer
  tools. Loader ownership means relocation before access to each page;
  it does not require eagerly relocating every page before entry. Old
  binaries remain correct but may touch all relocated pages at startup.
  The exact mlibc form and safe relocation indexing/validation policy
  remain review items; packed relocations and extra linker changes have
  not been approved by this architecture revision.
- The sync fix is already committed as `14733ed8` (`rt.vdso: flush FS`).
  Establish a fresh baseline from the actual implementation tree; do not
  reapply the archived hunk or treat old Q3 as a current blocker.
- Before dependent implementation, settle the private completion/handoff
  protocol, aggregate resource limits, safe preparation of missing syscall
  buffer pages, relocation validation, and the mlibc change's exact form.
  Other historical review questions and tuning constants in Appendix D
  are context, not newly approved requirements. Apply current AGENTS.md
  gates and make no commits unless requested.

## Appendices

Appendix A is the complete cold-prototype patch against
`6ef7737b4a5db34744827694e5c99c0b751ded44` (27 files, 2,318 added and 128
removed lines). Appendix B holds the six warm-prototype patches in
application order. Appendix C holds the guest harness, the host drivers,
the installer, the durability check, the flush helper, the CPU sampler,
the initrd packer, and the warm prototype's summarizer and harness.
Appendix D is the superseded detailed implementation plan.

## Appendix A: cold prototype patch (snapshot s100)

Apply with `git apply` to `6ef7737b4a5db34744827694e5c99c0b751ded44`.

### candidate.patch

````diff
diff --git a/src/sys/kernel/src/arch/x64/paging.rs b/src/sys/kernel/src/arch/x64/paging.rs
index ed3cf352..f733bd59 100644
--- a/src/sys/kernel/src/arch/x64/paging.rs
+++ b/src/sys/kernel/src/arch/x64/paging.rs
@@ -385,7 +385,14 @@ impl PageTableImpl {
 
     // With `flush: false` the caller must flush the TLB (e.g. via
     // `flush_pages`) before the unmapped physical frame is freed/reused.
-    fn unmap_page(&mut self, phys_addr: u64, virt_addr: u64, kind: PageType, flush: bool) {
+    fn unmap_page(
+        &mut self,
+        phys_addr: u64,
+        virt_addr: u64,
+        kind: PageType,
+        flush: bool,
+        prune: bool,
+    ) {
         assert_eq!(0, phys_addr & (kind.page_size() - 1));
         assert_eq!(0, virt_addr & (kind.page_size() - 1));
 
@@ -401,7 +408,7 @@ impl PageTableImpl {
         if kind == PageType::LargePage {
             assert!(pte_l3.is_huge_page());
             table_l3.set(idx_l3, PTE::empty());
-            if table_l3.is_empty() {
+            if prune && table_l3.is_empty() {
                 self.table_l4.set(idx_l4, PTE::empty());
                 phys_deallocate_frameless(table_l3.self_phys_addr(), PageType::SmallPage);
             }
@@ -420,7 +427,7 @@ impl PageTableImpl {
         if kind == PageType::MidPage {
             assert!(pte_l2.is_huge_page());
             table_l2.set(idx_l2, PTE::empty());
-            if table_l2.is_empty() {
+            if prune && table_l2.is_empty() {
                 table_l3.set(idx_l3, PTE::empty());
                 phys_deallocate_frameless(table_l2.self_phys_addr(), PageType::SmallPage);
                 if table_l3.is_empty() {
@@ -441,7 +448,7 @@ impl PageTableImpl {
         let idx_l1 = PageTableImpl::idx_l1(virt_addr);
         assert!(!table_l1.get(idx_l1).is_empty());
         table_l1.set(idx_l1, PTE::empty());
-        if table_l1.is_empty() {
+        if prune && table_l1.is_empty() {
             table_l2.set(idx_l2, PTE::empty());
             phys_deallocate_frameless(table_l1.self_phys_addr(), PageType::SmallPage);
             if table_l2.is_empty() {
@@ -458,6 +465,43 @@ impl PageTableImpl {
         }
     }
 
+    // Scratch batched teardown: inspect a leaf table once after all of the
+    // segment's PTEs have been removed, rather than after each 4 KiB page.
+    fn prune_range(&mut self, start: u64, end: u64) {
+        let mut addr = start & !(PAGE_SIZE_MID - 1);
+        while addr < end {
+            let l4 = Self::idx_l4(addr);
+            let l3 = Self::idx_l3(addr);
+            let l2 = Self::idx_l2(addr);
+            addr += PAGE_SIZE_MID;
+            let p4 = self.table_l4.get(l4);
+            if !p4.is_present() {
+                continue;
+            }
+            let t3 = HwPageTable::from_pte(p4);
+            let p3 = t3.get(l3);
+            if p3.is_present() && !p3.is_huge_page() {
+                let t2 = HwPageTable::from_pte(p3);
+                let p2 = t2.get(l2);
+                if p2.is_present() && !p2.is_huge_page() {
+                    let t1 = HwPageTable::from_pte(p2);
+                    if t1.is_empty() {
+                        t2.set(l2, PTE::empty());
+                        phys_deallocate_frameless(t1.self_phys_addr(), PageType::SmallPage);
+                    }
+                }
+                if t2.is_empty() {
+                    t3.set(l3, PTE::empty());
+                    phys_deallocate_frameless(t2.self_phys_addr(), PageType::SmallPage);
+                }
+            }
+            if t3.is_empty() {
+                self.table_l4.set(l4, PTE::empty());
+                phys_deallocate_frameless(t3.self_phys_addr(), PageType::SmallPage);
+            }
+        }
+    }
+
     fn is_readable(&self, virt_addr: u64) -> bool {
         let idx_l4 = PageTableImpl::idx_l4(virt_addr);
         let pte_l4 = self.table_l4.get(idx_l4);
@@ -847,7 +891,7 @@ impl PageTable {
             self.inst
                 .get()
                 .lock(4)
-                .unmap_page(phys_addr, virt_addr, kind, true);
+                .unmap_page(phys_addr, virt_addr, kind, true, true);
         }
     }
 
@@ -859,7 +903,13 @@ impl PageTable {
             self.inst
                 .get()
                 .lock(line!())
-                .unmap_page(phys_addr, virt_addr, kind, false);
+                .unmap_page(phys_addr, virt_addr, kind, false, false);
+        }
+    }
+
+    pub fn prune_unmapped_range(&self, start: u64, end: u64) {
+        unsafe {
+            self.inst.get().lock(line!()).prune_range(start, end);
         }
     }
 
diff --git a/src/sys/kernel/src/mm/mod.rs b/src/sys/kernel/src/mm/mod.rs
index b5011121..49a47bd1 100644
--- a/src/sys/kernel/src/mm/mod.rs
+++ b/src/sys/kernel/src/mm/mod.rs
@@ -87,9 +87,13 @@ pub fn zero_page(virt_addr: u64, kind: PageType) {
         let mut pos = virt_addr as usize;
         let end = (virt_addr + kind.page_size()) as usize;
         while pos < end {
+            // Fixed-width stores keep the kernel's no-SIMD zero path
+            // unrolled; page sizes are multiples of a cache line.
             let ptr = pos as *mut u64;
-            *ptr = 0;
-            pos += 8;
+            for offset in 0..8 {
+                ptr.add(offset).write_volatile(0);
+            }
+            pos += 64;
         }
     }
 }
@@ -286,6 +290,9 @@ bitflags! {
         // A segment's creation policy, never a per-page hardware option:
         // 2 MiB-aligned placement and huge candidates for its mapping.
         const HUGE_ELIGIBLE   = 512;
+        const FILE_PAGED      = 1024; // Cold-spawn experiment: external page fills.
+        const IMAGE_SPARSE    = 2048; // Resident, read-only vDSO backing.
+        const ANON_SPARSE     = 4096; // Scratch lazy heap/stack descriptors.
     }
 }
 
diff --git a/src/sys/kernel/src/mm/user.rs b/src/sys/kernel/src/mm/user.rs
index 506cf825..e07ead7f 100644
--- a/src/sys/kernel/src/mm/user.rs
+++ b/src/sys/kernel/src/mm/user.rs
@@ -14,6 +14,13 @@ pub struct PinnedUserPage {
 }
 
 impl PinnedUserPage {
+    pub(super) fn small_frame(&self) -> Option<super::slab::SlabArc<super::phys::Frame>> {
+        (self.offset == 0
+            && self.frame.get()?.kind() == super::PageType::SmallPage
+            && !self.frame.get()?.is_mmio())
+        .then(|| self.frame.clone())
+    }
+
     pub fn kernel_addr(&self) -> u64 {
         self.frame.get().unwrap().start()
             + self.offset
@@ -51,6 +58,7 @@ pub struct UserAddressSpace {
     // System and I/O-manager address spaces use the lower admission floor.
     // Set from CAP_SYS | CAP_IO_MANAGER when the process is created.
     privileged: AtomicBool,
+    cold_lazy_heap: AtomicU64,
 
     // User mem stats are tracked via @inner.
     // Kernel mem stats (kernel stacks) are tracked here.
@@ -65,6 +73,7 @@ unsafe impl Sync for UserAddressSpace {}
 
 impl Drop for UserAddressSpace {
     fn drop(&mut self) {
+        crate::uspace::cold_pager::retire(self);
         // W6b: CPUs no longer leave a process's page table on syscall/
         // preempt, so this CPU (running the teardown) and idle remote CPUs
         // may still have it as CR3. Teardown mutates the table — including
@@ -104,6 +113,7 @@ impl UserAddressSpace {
             ),
             total_usage: AtomicU64::new(0),
             privileged: AtomicBool::new(false),
+            cold_lazy_heap: AtomicU64::new(0),
             kernel_mem_stats: Arc::new(MemStats::new_kernel()),
 
             kernel_stacks: super::cache::SegmentCache::new(),
@@ -333,9 +343,17 @@ impl UserAddressSpace {
         // When dropping, we count the full segment, with guard pages, so when adding,
         // we need to do the same.
         self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;
+        let options = (self.cold_lazy_heap.load(Ordering::Relaxed) >= 2).then_some(
+            MappingOptions::READABLE
+                | MappingOptions::WRITABLE
+                | MappingOptions::USER_ACCESSIBLE
+                | MappingOptions::LAZY
+                | MappingOptions::GUARD
+                | MappingOptions::ANON_SPARSE,
+        );
         let segment = self
             .inner
-            .vmem_allocate_pages(VmemKind::UserStack, num_pages, None);
+            .vmem_allocate_pages(VmemKind::UserStack, num_pages, options);
 
         if let Err(err) = segment {
             self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
@@ -412,6 +430,18 @@ impl UserAddressSpace {
         }
     }
 
+    pub fn set_cold_lazy_heap(&self, mode: u64) {
+        self.cold_lazy_heap.store(mode, Ordering::Relaxed);
+    }
+
+    pub fn alloc_cold_heap(&self, num_pages: u64) -> Result<super::MemorySegment, ErrorCode> {
+        if !self.privileged.load(Ordering::Relaxed) {
+            self.alloc_user_lazy(num_pages)
+        } else {
+            self.alloc_user_heap(num_pages)
+        }
+    }
+
     pub fn alloc_user_heap(&self, num_pages: u64) -> Result<super::MemorySegment, ErrorCode> {
         // Ordinary eager private heap above 1 MiB may map huge pages; the
         // policy is the segment's, not inferred from anything else. Its
@@ -464,6 +494,22 @@ impl UserAddressSpace {
         num_pages: u64,
         mapping_options: super::MappingOptions,
     ) -> Result<(), ErrorCode> {
+        if mapping_options.contains(MappingOptions::IMAGE_SPARSE) {
+            self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;
+            if let Err(err) = self
+                .inner
+                .vmem_allocate_user_fixed(vaddr, num_pages, mapping_options)
+            {
+                self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
+                return Err(err);
+            }
+            return source
+                .inner
+                .share_with(source_addr, &self.inner, vaddr, mapping_options)
+                .inspect_err(|_| {
+                    let _ = self.unmap(vaddr);
+                });
+        }
         self.fill_fixed(vaddr, num_pages, |inner| {
             source
                 .inner
@@ -498,7 +544,12 @@ impl UserAddressSpace {
                     MappingOptions::READABLE
                         | MappingOptions::WRITABLE
                         | MappingOptions::USER_ACCESSIBLE
-                        | MappingOptions::LAZY,
+                        | MappingOptions::LAZY
+                        | if self.cold_lazy_heap.load(Ordering::Relaxed) >= 2 {
+                            MappingOptions::ANON_SPARSE
+                        } else {
+                            MappingOptions::empty()
+                        },
                 ),
             )
             .inspect_err(|_| {
@@ -561,6 +612,38 @@ impl UserAddressSpace {
             })
     }
 
+    pub fn reserve_file(&self, start: u64, pages: u64, flags: u64) -> Result<(), ErrorCode> {
+        self.stats_user_add(pages * PAGE_SIZE_SMALL)?;
+        let mut options =
+            MappingOptions::READABLE | MappingOptions::USER_ACCESSIBLE | MappingOptions::FILE_PAGED;
+        if flags & 1 != 0 {
+            options |= MappingOptions::EXECUTABLE;
+        }
+        if flags & 2 != 0 {
+            options |= MappingOptions::WRITABLE;
+        }
+        self.allocate_user_fixed(start, pages, options)
+            .inspect_err(|_| self.stats_user_sub(pages * PAGE_SIZE_SMALL))
+    }
+
+    pub fn mark_file_zero(&self, start: u64) -> Result<(), ErrorCode> {
+        self.inner.mark_file_zero(start)
+    }
+
+    pub fn fill_file(
+        &self,
+        start: u64,
+        pages: &[super::user::PinnedUserPage],
+        share: bool,
+    ) -> Result<(), ErrorCode> {
+        let count = pages.len() as u64;
+        let _admission = super::admission::admit(
+            self.mem_class(),
+            super::admission::mapping_charge(count, count),
+        )?;
+        self.inner.fill_file(start, pages, share)
+    }
+
     pub fn fix_pagefault(&self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
         // A refused fault cannot be reported to the faulting instruction, so
         // the faulting thread is killed. Deliberate: there is no OOM killer,
diff --git a/src/sys/kernel/src/mm/virt.rs b/src/sys/kernel/src/mm/virt.rs
index db4a9498..9069b7fd 100644
--- a/src/sys/kernel/src/mm/virt.rs
+++ b/src/sys/kernel/src/mm/virt.rs
@@ -581,6 +581,27 @@ impl VmemRegion {
         Ok(memory_segment)
     }
 
+    fn mark_file_zero(&self, start: u64) -> Result<(), ErrorCode> {
+        self.used_segments
+            .lock(line!())
+            .find_mut(start)
+            .ok_or(moto_rt::E_INVALID_ARGUMENT)?
+            .mark_file_zero(start)
+    }
+
+    fn fill_file(
+        &self,
+        start: u64,
+        pages: &[super::user::PinnedUserPage],
+        share: bool,
+    ) -> Result<(), ErrorCode> {
+        let mut segments = self.used_segments.lock(line!());
+        segments
+            .find_mut(start)
+            .ok_or(moto_rt::E_INVALID_ARGUMENT)?
+            .fill_file(start, pages, share)
+    }
+
     fn fix_pagefault(&self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
         if !self.segment.contains(pf_addr) {
             return Err(moto_rt::E_INVALID_ARGUMENT);
@@ -1158,8 +1179,25 @@ impl UserAddressSpaceBase {
         )
     }
 
+    pub(super) fn mark_file_zero(&self, start: u64) -> Result<(), ErrorCode> {
+        self.normal_memory.mark_file_zero(start)
+    }
+
+    pub(super) fn fill_file(
+        &self,
+        start: u64,
+        pages: &[super::user::PinnedUserPage],
+        share: bool,
+    ) -> Result<(), ErrorCode> {
+        self.normal_memory.fill_file(start, pages, share)
+    }
+
     pub(super) fn fix_pagefault(&self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
-        self.normal_memory.fix_pagefault(pf_addr, error_code)
+        if self.custom_memory.segment.contains(pf_addr) {
+            self.custom_memory.fix_pagefault(pf_addr, error_code)
+        } else {
+            self.normal_memory.fix_pagefault(pf_addr, error_code)
+        }
     }
 
     /// Maps the kernel-static pages starting at `kernel_vaddr` into the
diff --git a/src/sys/kernel/src/mm/virt_intrusive.rs b/src/sys/kernel/src/mm/virt_intrusive.rs
index 6501b298..5df3abe1 100644
--- a/src/sys/kernel/src/mm/virt_intrusive.rs
+++ b/src/sys/kernel/src/mm/virt_intrusive.rs
@@ -2,6 +2,7 @@
 // utilize intrusive collections: using normal vectors/maps is not right, as
 // they involve heap allocations, and we don't want to do heap allocations
 // while allocating virtual memory, as it results in nasty recursion.
+use alloc::{sync::Arc, vec::Vec};
 use core::mem::MaybeUninit;
 
 use intrusive_collections::{intrusive_adapter, Bound, UnsafeRef};
@@ -260,6 +261,9 @@ pub(super) struct VmemSegment {
     pages: RBTree<PageTreeAdapter>,
     owner: crate::util::UnsafeRef<super::virt::VmemRegion>,
     mapping_options: MappingOptions,
+    image: SpinLock<Option<Arc<Vec<SlabArc<Frame>>>>>,
+    image_offset: usize,
+    file_zero_tail: u64,
 }
 
 impl Drop for VmemSegment {
@@ -279,6 +283,9 @@ impl VmemSegment {
             owner: crate::util::UnsafeRef::from(owner),
             mapping_options,
             pages: RBTree::new(PageTreeAdapter::new()),
+            image: SpinLock::new(None),
+            image_offset: 0,
+            file_zero_tail: 0,
         }
     }
 
@@ -310,7 +317,17 @@ impl VmemSegment {
     pub(super) fn vaddr_map_status(&self, vmem_addr: u64) -> VaddrMapStatus {
         assert!(self.segment.contains(vmem_addr));
 
-        let page = self.find_page(vmem_addr).unwrap();
+        if self.mapping_options.contains(MappingOptions::IMAGE_SPARSE) {
+            return self
+                .image_page(vmem_addr)
+                .map_or(VaddrMapStatus::Unmapped, |(frame, offset)| {
+                    VaddrMapStatus::Shared(frame.get().unwrap().start() + offset)
+                });
+        }
+
+        let Some(page) = self.find_page(vmem_addr) else {
+            return VaddrMapStatus::Unmapped;
+        };
 
         if let Some(frame) = page.frame.get() {
             if frame.is_mmio() {
@@ -330,6 +347,9 @@ impl VmemSegment {
     }
 
     pub(super) fn pin_user_page(&self, vmem_addr: u64) -> Option<(SlabArc<Frame>, u64)> {
+        if self.mapping_options.contains(MappingOptions::IMAGE_SPARSE) {
+            return self.image_page(vmem_addr);
+        }
         let page = self.find_page(vmem_addr)?;
         let frame = page.frame.get()?;
         if frame.is_mmio() {
@@ -340,6 +360,15 @@ impl VmemSegment {
         Some((page.frame.clone(), vmem_addr - page.start))
     }
 
+    fn image_page(&self, addr: u64) -> Option<(SlabArc<Frame>, u64)> {
+        let index = ((addr - self.segment.start) / PAGE_SIZE_SMALL) as usize + self.image_offset;
+        let image = self.image.lock(line!());
+        Some((
+            image.as_ref()?.get(index)?.clone(),
+            addr & (PAGE_SIZE_SMALL - 1),
+        ))
+    }
+
     pub(super) fn unmap(mut self) -> u64 {
         // Note: it is important to unmap pages before freeing the segment
         // in the VMemRegion, otherwise a concurrent allocation may try
@@ -366,6 +395,9 @@ impl VmemSegment {
             }
         }
         if mapped_pages > 0 {
+            self.address_space()
+                .page_table
+                .prune_unmapped_range(self.segment.start, self.segment.end());
             self.address_space().page_table.flush_pages(
                 self.segment.start,
                 self.segment.size >> PAGE_SIZE_SMALL_LOG2,
@@ -388,6 +420,14 @@ impl VmemSegment {
             self.address_space().page_allocator.free_page(page_ptr);
         }
 
+        if self.mapping_options.intersects(
+            MappingOptions::FILE_PAGED | MappingOptions::IMAGE_SPARSE | MappingOptions::ANON_SPARSE,
+        ) {
+            sz = self.segment.size;
+        }
+        self.image.lock(line!()).take();
+        self.image_offset = 0;
+        self.file_zero_tail = 0;
         self.segment = MemorySegment::empty_segment();
         self.owner.clear();
 
@@ -419,6 +459,12 @@ impl VmemSegment {
         assert!(self.segment.size > 0);
         assert!(self.pages.is_empty());
 
+        if self.mapping_options.intersects(
+            MappingOptions::FILE_PAGED | MappingOptions::IMAGE_SPARSE | MappingOptions::ANON_SPARSE,
+        ) {
+            return Ok(());
+        }
+
         let num_pages = self.segment.size >> PAGE_SIZE_SMALL_LOG2;
         let huge = self.huge_candidates();
         let mut start = self.segment.start;
@@ -451,12 +497,30 @@ impl VmemSegment {
             }
         }
         let first_small = huge * (PAGE_SIZE_MID / PAGE_SIZE_SMALL);
-        for idx in first_small..num_pages {
-            self.map_small(
-                start,
-                page_mapping_options(self.mapping_options, idx, num_pages),
-            )?;
+        let mut idx = first_small;
+        while idx < num_pages {
+            let options = page_mapping_options(self.mapping_options, idx, num_pages);
+            let count = (num_pages - idx).min(64);
+            if count > 1
+                && !options.is_empty()
+                && options.contains(MappingOptions::USER_ACCESSIBLE)
+                && !self.mapping_options.contains(MappingOptions::LAZY)
+                && options == page_mapping_options(self.mapping_options, idx + count - 1, num_pages)
+            {
+                if let Ok(frames) =
+                    super::phys::phys_allocate_contiguous_frames(PageType::SmallPage, count)
+                {
+                    for frame in frames {
+                        self.map_frame(start, frame, options)?;
+                        start += PAGE_SIZE_SMALL;
+                    }
+                    idx += count;
+                    continue;
+                }
+            }
+            self.map_small(start, options)?;
             start += PAGE_SIZE_SMALL;
+            idx += 1;
         }
 
         Ok(())
@@ -520,6 +584,65 @@ impl VmemSegment {
         Ok(())
     }
 
+    pub(super) fn mark_file_zero(&mut self, start: u64) -> Result<(), ErrorCode> {
+        if !self
+            .mapping_options
+            .contains(MappingOptions::FILE_PAGED | MappingOptions::WRITABLE)
+            || start & 4095 != 0
+            || start < self.segment.start
+            || start >= self.segment.end()
+        {
+            return Err(moto_rt::E_INVALID_ARGUMENT);
+        }
+        self.file_zero_tail = start;
+        Ok(())
+    }
+
+    pub(super) fn fill_file(
+        &mut self,
+        start: u64,
+        pages: &[super::user::PinnedUserPage],
+        share: bool,
+    ) -> Result<(), ErrorCode> {
+        if !self.mapping_options.contains(MappingOptions::FILE_PAGED)
+            || !start.is_multiple_of(PAGE_SIZE_SMALL)
+            || start < self.segment.start
+            || start
+                .checked_add(pages.len() as u64 * PAGE_SIZE_SMALL)
+                .is_none_or(|end| end > self.segment.end())
+        {
+            return Err(moto_rt::E_INVALID_ARGUMENT);
+        }
+        let options =
+            (self.mapping_options - MappingOptions::FILE_PAGED) | MappingOptions::DONT_ZERO;
+        if share && options.contains(MappingOptions::WRITABLE) {
+            return Err(moto_rt::E_NOT_ALLOWED);
+        }
+        for (idx, source) in pages.iter().enumerate() {
+            let addr = start + idx as u64 * PAGE_SIZE_SMALL;
+            if self.find_page(addr).is_some() {
+                continue;
+            }
+            if share {
+                if let Some(frame) = source.small_frame() {
+                    self.map_frame(addr, frame, options)?;
+                    continue;
+                }
+            }
+            let frame = super::phys::allocate_frame(PageType::SmallPage)?;
+            let dst = frame.get().unwrap().start() + super::PAGING_DIRECT_MAP_OFFSET;
+            unsafe {
+                core::ptr::copy_nonoverlapping(
+                    source.kernel_addr() as *const u8,
+                    dst as *mut u8,
+                    PAGE_SIZE_SMALL as usize,
+                );
+            }
+            self.map_frame(addr, frame, options)?;
+        }
+        Ok(())
+    }
+
     pub fn mmio_map(&mut self, phys_addr: u64, user: bool) -> Result<(), ErrorCode> {
         let start = self.segment.start;
 
@@ -557,6 +680,54 @@ impl VmemSegment {
     pub(super) fn fix_pagefault(&mut self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
         debug_assert!(self.segment.contains(pf_addr));
 
+        if self.mapping_options.contains(MappingOptions::IMAGE_SPARSE) {
+            if error_code & !0x14 != 0
+                || (error_code & 0x10 != 0
+                    && !self.mapping_options.contains(MappingOptions::EXECUTABLE))
+            {
+                return Err(moto_rt::E_INVALID_ARGUMENT);
+            }
+            let options =
+                (self.mapping_options - MappingOptions::IMAGE_SPARSE) | MappingOptions::DONT_ZERO;
+            let first = ((pf_addr - self.segment.start) / PAGE_SIZE_SMALL) & !15;
+            let end = (first + 16).min(self.segment.size / PAGE_SIZE_SMALL);
+            for index in first..end {
+                let addr = self.segment.start + index * PAGE_SIZE_SMALL;
+                if self.find_page(addr).is_none() {
+                    let (frame, _) = self.image_page(addr).ok_or(moto_rt::E_INVALID_ARGUMENT)?;
+                    self.map_frame(addr, frame, options)?;
+                }
+            }
+            return Ok(());
+        }
+
+        if self.mapping_options.contains(MappingOptions::FILE_PAGED) {
+            if error_code & !0x16 != 0
+                || (error_code & 2 != 0 && !self.mapping_options.contains(MappingOptions::WRITABLE))
+                || (error_code & 0x10 != 0
+                    && !self.mapping_options.contains(MappingOptions::EXECUTABLE))
+            {
+                return Err(moto_rt::E_INVALID_ARGUMENT);
+            }
+            if self.file_zero_tail != 0
+                && pf_addr >= self.file_zero_tail
+                && self.find_page(pf_addr).is_none()
+            {
+                let frame = super::phys::allocate_frame(PageType::SmallPage)?;
+                self.map_frame(
+                    pf_addr & !4095,
+                    frame,
+                    self.mapping_options - MappingOptions::FILE_PAGED,
+                )?;
+                return Ok(());
+            }
+            return if self.find_page(pf_addr).is_some() {
+                Ok(())
+            } else {
+                Err(moto_rt::E_NOT_READY)
+            };
+        }
+
         // Note: this is run under spinlock on self.
 
         if (((pf_addr & !(PAGE_SIZE_SMALL - 1)) == self.segment.start)
@@ -567,6 +738,24 @@ impl VmemSegment {
             return Err(moto_rt::E_INVALID_ARGUMENT);
         }
 
+        if self.mapping_options.contains(MappingOptions::ANON_SPARSE) {
+            if error_code & !6 != 0
+                || error_code & 4 == 0
+                || (error_code & 2 != 0 && !self.mapping_options.contains(MappingOptions::WRITABLE))
+            {
+                return Err(moto_rt::E_INVALID_ARGUMENT);
+            }
+            if self.find_page(pf_addr).is_none() {
+                let frame = super::phys::allocate_frame(PageType::SmallPage)?;
+                let options = self.mapping_options
+                    - MappingOptions::ANON_SPARSE
+                    - MappingOptions::LAZY
+                    - MappingOptions::GUARD;
+                self.map_frame(pf_addr & !4095, frame, options)?;
+            }
+            return Ok(());
+        }
+
         debug_assert_eq!(error_code & 4, 4);
         let error_code = error_code ^ 4;
 
@@ -670,6 +859,35 @@ impl VmemSegment {
         if start + other.segment.size > self.segment.end() {
             return Err(moto_rt::E_INVALID_ARGUMENT);
         }
+        if other.mapping_options.contains(MappingOptions::IMAGE_SPARSE) {
+            if mapping_options.contains(MappingOptions::WRITABLE) {
+                return Err(moto_rt::E_NOT_ALLOWED);
+            }
+            let mut image = self.image.lock(line!());
+            if image.is_none() {
+                let mut frames = Vec::new();
+                frames
+                    .try_reserve_exact((self.segment.size / PAGE_SIZE_SMALL) as usize)
+                    .map_err(|_| moto_rt::E_OUT_OF_MEMORY)?;
+                for page in self.pages.iter() {
+                    if page.mapping_options.contains(MappingOptions::WRITABLE) {
+                        return Err(moto_rt::E_NOT_ALLOWED);
+                    }
+                    let frame = page.frame.get().ok_or(moto_rt::E_INVALID_ARGUMENT)?;
+                    if frame.kind() != PageType::SmallPage || frame.is_mmio() {
+                        return Err(moto_rt::E_INVALID_ARGUMENT);
+                    }
+                    frames.push(page.frame.clone());
+                }
+                if frames.len() as u64 * PAGE_SIZE_SMALL != self.segment.size {
+                    return Err(moto_rt::E_INVALID_ARGUMENT);
+                }
+                *image = Some(Arc::new(frames));
+            }
+            *other.image.lock(line!()) = image.clone();
+            other.image_offset = self.image_offset + first_page as usize;
+            return Ok(());
+        }
         // Segment provenance decides, whatever the actual backing: a huge
         // page must never reach the small-page replacement loop below.
         if (self.mapping_options | other.mapping_options).contains(MappingOptions::HUGE_ELIGIBLE) {
@@ -758,11 +976,10 @@ impl SegmentNode {
 }
 
 const SEGMENT_NODE_SZ: usize = core::mem::size_of::<SegmentNode>();
-const _SEGMENT_NODE_SZ: () = assert!(core::mem::size_of::<SegmentNode>() == 72);
+// Scratch image backing extends the descriptor; packing follows its actual size.
 
 const SEGMENT_NODES_IN_SMALL_PAGE: usize =
     ((PAGE_SIZE_SMALL as usize) - STRUCT_PAGE_SZ) / SEGMENT_NODE_SZ; // == 55.
-const _SEGMENT_NODES_IN_SMALL_PAGE: () = assert!(SEGMENT_NODES_IN_SMALL_PAGE == 55);
 
 intrusive_adapter!(SegmentListAdapter = UnsafeRef<SegmentNode>: SegmentNode { free_list_link: SinglyLinkedListLink });
 intrusive_adapter!(pub(super) SegmentTreeAdapter = UnsafeRef<SegmentNode>: SegmentNode { tree_link: RBTreeLink });
diff --git a/src/sys/kernel/src/uspace/mod.rs b/src/sys/kernel/src/uspace/mod.rs
index 43b2ade6..f90e1e88 100644
--- a/src/sys/kernel/src/uspace/mod.rs
+++ b/src/sys/kernel/src/uspace/mod.rs
@@ -12,6 +12,7 @@ mod sysobject;
 pub use sysobject::SysObject;
 
 // Syscalls.
+pub(crate) mod cold_pager;
 mod sys_cpu;
 mod sys_mem;
 mod sys_obj;
diff --git a/src/sys/kernel/src/uspace/process.rs b/src/sys/kernel/src/uspace/process.rs
index a5128513..8dccd5ce 100644
--- a/src/sys/kernel/src/uspace/process.rs
+++ b/src/sys/kernel/src/uspace/process.rs
@@ -2150,12 +2150,11 @@ impl Thread {
             let mut status = self.status.lock(line!());
             match *status {
                 ThreadStatus::Live(LiveThreadStatus::Running) => {
-                    if self
+                    let fault_result = self
                         .owner()
                         .address_space
-                        .fix_pagefault(pf_addr, error_code)
-                        .is_ok()
-                    {
+                        .fix_pagefault(pf_addr, error_code);
+                    if fault_result.is_ok() {
                         log::trace!("#PF fixed!");
                         if self.owner().paused_debuggee.load(Ordering::Relaxed) {
                             *status = ThreadStatus::PausedDebuggee(LiveThreadStatus::Preempted);
@@ -2163,6 +2162,10 @@ impl Thread {
                             *status = ThreadStatus::Live(LiveThreadStatus::Preempted);
                             resume_in_userspace = true;
                         }
+                    } else if fault_result == Err(moto_rt::E_NOT_READY)
+                        && super::cold_pager::enqueue(self, pf_addr)
+                    {
+                        *status = ThreadStatus::Live(LiveThreadStatus::Preempted);
                     } else {
                         killed_now = true;
                         *status = ThreadStatus::Killed(ThreadKilledReason::PageFault);
@@ -2204,6 +2207,26 @@ impl Thread {
         }
     }
 
+    pub(super) fn resume_file_fault(&self, cpu: uCpus, success: bool) {
+        if !success {
+            self.post_kill(ThreadKilledReason::PageFault);
+            return;
+        }
+        let mut status = self.status.lock(line!());
+        if *status == ThreadStatus::Live(LiveThreadStatus::Preempted) {
+            if self.owner().paused_debuggee.load(Ordering::Relaxed) {
+                *status = ThreadStatus::PausedDebuggee(LiveThreadStatus::Preempted);
+            } else {
+                crate::sched::post(crate::sched::Job::new(
+                    Self::job_fn_resume_in_userspace,
+                    self.get_weak(),
+                    self.tid.as_u64(),
+                    cpu,
+                ));
+            }
+        }
+    }
+
     fn on_thread_descheduled(&self, tocr: ThreadOffCpuReason) {
         crate::util::full_fence();
         self.trace("on_thread_descheduled", 0, 0);
diff --git a/src/sys/kernel/src/uspace/sys_mem.rs b/src/sys/kernel/src/uspace/sys_mem.rs
index 76e044e9..36ecd1a7 100644
--- a/src/sys/kernel/src/uspace/sys_mem.rs
+++ b/src/sys/kernel/src/uspace/sys_mem.rs
@@ -50,7 +50,7 @@ fn map_charge(flags: u32, phys_addr: u64, page_size: u64, num_pages: u64) -> u64
         } else {
             (0, num_pages) // The caller's existing frames: descriptors only.
         }
-    } else if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE)
+    } else if (flags & !0x200) == (SysMem::F_READABLE | SysMem::F_WRITABLE)
         && page_size == sys_mem::PAGE_SIZE_SMALL
     {
         // The ordinary heap maps the rounded size; charge that, aggregated
@@ -186,6 +186,16 @@ fn sys_map(
         };
     }
 
+    if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE | 0x200) {
+        if phys_addr != u64::MAX || virt_addr != u64::MAX {
+            return ResultBuilder::invalid_argument();
+        }
+        return match address_space.alloc_cold_heap(num_pages) {
+            Ok(segment) => ResultBuilder::ok_2(segment.start, segment.size),
+            Err(error) => ResultBuilder::result(error),
+        };
+    }
+
     if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE) {
         if phys_addr == u64::MAX && virt_addr == u64::MAX {
             // This is a normal user heap allocation.
@@ -238,6 +248,13 @@ fn sys_map(
         // (the vdso's text and read-only data).
         let mut flags = flags & !SysMem::F_SHARE_SELF;
         let mut opts = MappingOptions::USER_ACCESSIBLE;
+        if flags & 0x100 != 0 {
+            if phys_addr == u64::MAX {
+                return ResultBuilder::invalid_argument();
+            }
+            opts |= MappingOptions::IMAGE_SPARSE;
+            flags &= !0x100;
+        }
         if (flags & SysMem::F_READABLE) != 0 {
             opts |= MappingOptions::READABLE;
             flags &= !SysMem::F_READABLE;
@@ -460,6 +477,10 @@ pub fn sys_mem_impl(thread: &super::process::Thread, args: &SyscallArgs) -> Sysc
 
     let address_space_handle = SysHandle::from_u64(args.args[0]);
 
+    if args.operation == 6 {
+        return super::cold_pager::run(thread, args);
+    }
+
     if address_space_handle == SysHandle::NONE {
         if args.operation != SysMem::OP_QUERY {
             log::debug!("sys_mem_impl: NONE handle and not OP_QUERY.");
diff --git a/src/sys/lib/async-fs/src/block_cache.rs b/src/sys/lib/async-fs/src/block_cache.rs
index 56836256..a58433c9 100644
--- a/src/sys/lib/async-fs/src/block_cache.rs
+++ b/src/sys/lib/async-fs/src/block_cache.rs
@@ -313,6 +313,17 @@ impl SupportingCaches {
     }
 
     fn pop_free_block(&mut self) -> Rc<BlockHolder> {
+        #[cfg(target_os = "motor")]
+        if self.free_blocks.is_empty()
+            && let Some(buffers) = IoBuf::cold_read_buffers()
+        {
+            self.free_blocks.extend(
+                buffers
+                    .into_iter()
+                    .rev()
+                    .map(|iobuf| Rc::new(BlockHolder { iobuf })),
+            );
+        }
         self.free_blocks
             .pop()
             .unwrap_or_else(|| Rc::new(BlockHolder::new()))
diff --git a/src/sys/lib/fittings/src/iobuf.rs b/src/sys/lib/fittings/src/iobuf.rs
index 6e3bbb64..00bfe9c1 100644
--- a/src/sys/lib/fittings/src/iobuf.rs
+++ b/src/sys/lib/fittings/src/iobuf.rs
@@ -33,6 +33,18 @@ impl Drop for IoBuf {
 }
 
 impl IoBuf {
+    /// # Safety
+    /// The pointer covers a uniquely writable region with this size and
+    /// alignment for this object's lifetime. Suppress Drop when the region
+    /// belongs to a different allocator or is part of a larger allocation.
+    pub unsafe fn from_raw(ptr: *mut u8, size_align: usize) -> Self {
+        Self {
+            ptr,
+            layout_size_align: size_align,
+            len: size_align,
+        }
+    }
+
     pub fn new_from_size_align(layout_size_align: usize) -> Option<Self> {
         // SAFETY: save by construction.
         let ptr = unsafe {
diff --git a/src/sys/lib/moto-async/src/local_runtime.rs b/src/sys/lib/moto-async/src/local_runtime.rs
index f3a2d9bf..76f9bfe2 100644
--- a/src/sys/lib/moto-async/src/local_runtime.rs
+++ b/src/sys/lib/moto-async/src/local_runtime.rs
@@ -145,6 +145,15 @@ pub fn timer_queue_len() -> usize {
 /// when readiness is observed, when the registration is replaced or expires,
 /// or before the executor parks or leaves `block_on`.
 pub trait SpinSource {
+    // Scratch pure-readiness sources keep peer notifications enabled and may
+    // remain registered across a park. They still end on runtime exit.
+    fn persist_through_park(&self) -> bool {
+        false
+    }
+    /// Scratch per-source idle polling budget, capped by the executor.
+    fn idle_budget_ns(&self) -> u64 {
+        SPIN_BEFORE_PARK_NS
+    }
     fn ready(&self) -> bool;
     /// The executor now watches the source (e.g. clear the channel's
     /// "waiting" flag so the peer skips its wake syscall).
@@ -166,7 +175,7 @@ struct SpinEntry {
 const SPIN_BEFORE_PARK_NS: u64 = 20_000;
 /// Registrations beyond this keep the normal wake path: a pass over more
 /// sources would eat the spin window.
-const MAX_SPIN_SOURCES: usize = 8;
+const MAX_SPIN_SOURCES: usize = 32;
 
 fn tsc_now() -> u64 {
     moto_rt::time::Instant::now().as_u64()
@@ -464,15 +473,21 @@ impl LocalRuntimeInner {
 
     // About to park: nobody will watch the sources, so end every
     // registration. True if one turned ready.
-    fn park_spin_sources(&self) -> bool {
+    fn park_spin_sources(&self, keep_persistent: bool) -> bool {
         let entries = core::mem::take(&mut *self.spin_sources.borrow_mut());
         let mut woke = false;
+        let mut retained = Vec::new();
         for entry in entries {
+            if keep_persistent && entry.source.persist_through_park() && !entry.source.ready() {
+                retained.push(entry);
+                continue;
+            }
             if entry.source.end() {
                 entry.waker.wake_by_ref();
                 woke = true;
             }
         }
+        *self.spin_sources.borrow_mut() = retained;
         woke
     }
 
@@ -515,7 +530,13 @@ impl LocalRuntimeInner {
             }
             false
         });
-        let deadline = now + ns_to_tsc(SPIN_BEFORE_PARK_NS);
+        let budget = entries
+            .iter()
+            .map(|entry| entry.source.idle_budget_ns())
+            .max()
+            .unwrap_or(SPIN_BEFORE_PARK_NS)
+            .min(200_000);
+        let deadline = now + ns_to_tsc(budget);
         while !resume && !entries.is_empty() {
             if entries.iter().any(|entry| entry.source.ready()) {
                 break;
@@ -815,7 +836,7 @@ impl Drop for LocalRuntimeContextGuard {
         assert_eq!(self.context, get_local_runtime_context() as usize);
         // No source is watched outside block_on, even if the runtime is kept.
         // End it while callback wakers still have their runtime context.
-        LocalRuntimeInner::current().park_spin_sources();
+        LocalRuntimeInner::current().park_spin_sources(false);
         clear_local_runtime_context();
     }
 }
@@ -927,7 +948,7 @@ impl LocalRuntime {
             }
             // A parked executor watches nothing: end the registrations
             // (one that turned ready meanwhile makes us resume).
-            if inner.park_spin_sources() {
+            if inner.park_spin_sources(true) {
                 continue;
             }
 
diff --git a/src/sys/lib/moto-io/src/fs.rs b/src/sys/lib/moto-io/src/fs.rs
index 013d453a..ecb02482 100644
--- a/src/sys/lib/moto-io/src/fs.rs
+++ b/src/sys/lib/moto-io/src/fs.rs
@@ -492,6 +492,32 @@ impl FsClient {
         file_id: EntryId,
         offset: u64,
         buf: &mut [u8],
+    ) -> Result<usize> {
+        self.read_impl(file_id, offset, buf, false).await
+    }
+
+    /// Scratch delegation of one cold image segment to the filesystem pager.
+    pub async fn register_cold(self: &Rc<Self>, file_id: EntryId, words: &[u64]) -> Result<()> {
+        if words.len() > 512 { return Err(moto_rt::E_INVALID_ARGUMENT.into()); }
+        let page = self.io_sender.alloc_page(u64::MAX).await?;
+        for (idx, word) in words.iter().enumerate() {
+            page.bytes_mut()[idx * 8..idx * 8 + 8].copy_from_slice(&word.to_le_bytes());
+        }
+        let mut msg = api_fs::write_msg_encode(file_id, 0, (words.len() * 8) as u16, page);
+        msg.command = 0x7f00;
+        msg.id = self.new_request_id();
+        self.clone().send_recv(msg).await?.status()
+    }
+
+    /// Scratch pager read: group requested blocks without streaming ahead.
+    pub async fn read_cold(
+        self: &Rc<Self>, file_id: EntryId, offset: u64, buf: &mut [u8],
+    ) -> Result<usize> {
+        self.read_impl(file_id, offset, buf, true).await
+    }
+
+    async fn read_impl(
+        self: &Rc<Self>, file_id: EntryId, offset: u64, buf: &mut [u8], cold: bool,
     ) -> Result<usize> {
         // Multi-block reads: each request asks for up to READ_MAX_PAGES
         // io_pages of data (48K) and gets one multi-page response (or the
@@ -534,6 +560,7 @@ impl FsClient {
                 debug_assert!(req_len as usize <= api_fs::READ_MAX_BYTES);
 
                 let mut msg = api_fs::read_msg_encode(file_id, send_offset, req_len as u16);
+                msg.flags = u32::from(cold);
                 let msg_id = self.new_request_id();
                 msg.id = msg_id;
                 if let Err(err) = self.clone().send(msg).await {
diff --git a/src/sys/lib/moto-tooling/src/iobuf.rs b/src/sys/lib/moto-tooling/src/iobuf.rs
index b947490b..2c4fbb00 100644
--- a/src/sys/lib/moto-tooling/src/iobuf.rs
+++ b/src/sys/lib/moto-tooling/src/iobuf.rs
@@ -1,4 +1,10 @@
+#[cfg(not(feature = "std"))]
+use alloc::rc::Rc;
+use core::mem::ManuallyDrop;
+use core::sync::atomic::{AtomicUsize, Ordering};
 use fittings::iobuf::IoBuf as InnerBuf;
+#[cfg(feature = "std")]
+use std::rc::Rc;
 
 #[cfg(not(feature = "std"))]
 use alloc::vec::Vec;
@@ -6,17 +12,76 @@ use alloc::vec::Vec;
 /// Extends fittings::iobuf to support caching the physical address
 /// of the underlying buffer.
 pub struct IoBuf {
-    inner: InnerBuf,
+    inner: ManuallyDrop<InnerBuf>,
+    cold_owner: Option<Rc<ColdPages>>,
     phys_addr: core::cell::Cell<usize>, // The physical address of inner::ptr.
     // Per-4K-page physical addresses (see phys_addr_at); resolved lazily,
     // 0 = not yet resolved. Empty until first phys_addr_at call.
     phys_pages: core::cell::RefCell<Vec<u64>>,
 }
 
+static COLD_IO: AtomicUsize = AtomicUsize::new(0);
+static COLD_BATCH: AtomicUsize = AtomicUsize::new(64);
+pub struct ColdIoGuard;
+impl ColdIoGuard {
+    pub fn new(batch: usize) -> Self {
+        assert!(matches!(batch, 16 | 64));
+        COLD_BATCH.store(batch, Ordering::Relaxed);
+        COLD_IO.fetch_add(1, Ordering::Relaxed);
+        Self
+    }
+}
+impl Drop for ColdIoGuard {
+    fn drop(&mut self) {
+        COLD_IO.fetch_sub(1, Ordering::Relaxed);
+    }
+}
+struct ColdPages(u64);
+impl Drop for ColdPages {
+    fn drop(&mut self) {
+        moto_sys::SysMem::free(self.0).unwrap();
+    }
+}
+impl Drop for IoBuf {
+    fn drop(&mut self) {
+        if self.cold_owner.is_none() {
+            unsafe {
+                ManuallyDrop::drop(&mut self.inner);
+            }
+        }
+    }
+}
+
 impl IoBuf {
+    /// Scratch privileged pool: fully zeroed, physically contiguous backing.
+    /// One translation supplies the per-page addresses. Ownership keeps the
+    /// entire mapping alive until every buffer has been released.
+    pub fn cold_read_buffers() -> Option<Vec<Self>> {
+        if COLD_IO.load(Ordering::Relaxed) == 0 {
+            return None;
+        }
+        let batch = COLD_BATCH.load(Ordering::Relaxed) as u64;
+        let addr = moto_sys::SysMem::alloc_contiguous_pages(batch * 4096).ok()?;
+        let owner = Rc::new(ColdPages(addr));
+        let phys = moto_sys::SysMem::virt_to_phys(addr).expect("backed contiguous DMA mapping");
+        Some(
+            (0..batch)
+                .map(|idx| Self {
+                    inner: ManuallyDrop::new(unsafe {
+                        InnerBuf::from_raw((addr + idx * 4096) as *mut u8, 4096)
+                    }),
+                    cold_owner: Some(owner.clone()),
+                    phys_addr: ((phys + idx * 4096) as usize).into(),
+                    phys_pages: core::cell::RefCell::new(Vec::new()),
+                })
+                .collect(),
+        )
+    }
+
     pub fn new_from_size_align(layout_size_align: usize) -> Option<Self> {
         InnerBuf::new_from_size_align(layout_size_align).map(|inner| Self {
-            inner,
+            inner: ManuallyDrop::new(inner),
+            cold_owner: None,
             phys_addr: 0.into(),
             phys_pages: core::cell::RefCell::new(Vec::new()),
         })
@@ -67,6 +132,9 @@ impl IoBuf {
     pub fn phys_addr_at(&self, offset: usize) -> u64 {
         const PAGE_SIZE: u64 = moto_sys::sys_mem::PAGE_SIZE_SMALL;
         assert!(offset < self.inner.capacity());
+        if self.cold_owner.is_some() {
+            return self.phys_addr.get() as u64 + offset as u64;
+        }
 
         let virt_start = self.raw_ptr() as usize as u64;
         let virt_addr = virt_start + offset as u64;
diff --git a/src/sys/lib/motor-fs/src/fs.rs b/src/sys/lib/motor-fs/src/fs.rs
index 1686d0e3..e04ff6f9 100644
--- a/src/sys/lib/motor-fs/src/fs.rs
+++ b/src/sys/lib/motor-fs/src/fs.rs
@@ -409,6 +409,34 @@ impl<BD: AsyncBlockDevice + 'static> MotorFs<BD> {
         Txn::test_remove_block_txn(self, file_id.into(), offset).await
     }
 
+    /// Scratch cold pager: pin a clean, full file page. Existing COW writes
+    /// preserve this snapshot; dirty and sparse pages use the copy path.
+    pub async fn cold_page(
+        &self,
+        role: Role,
+        file: EntryId,
+        key: u64,
+    ) -> Result<Option<async_fs::block_cache::CheckpointedBlock>> {
+        let metadata = self.metadata(role, file).await?;
+        if metadata.try_kind()? != EntryKind::File
+            || !metadata.access(role)?.can_read()
+            || key
+                .checked_mul(4096)
+                .and_then(|v| v.checked_add(4096))
+                .is_none_or(|end| end > metadata.size)
+        {
+            return Err(ErrorKind::PermissionDenied.into());
+        }
+        let Some(block) = self.data_block_at_key_cached(file.into(), key).await? else {
+            return Ok(None);
+        };
+        let cached = self.block_cache.get_block(block.as_u64()).await?;
+        if cached.is_dirty() {
+            return Ok(None);
+        }
+        Ok(Some(async_fs::block_cache::CheckpointedBlock::new(&cached)))
+    }
+
     /// Warm the block cache with up to `count` data blocks of `file_id`,
     /// starting at file block `first_key` (a file block key is
     /// `offset / BLOCK_SIZE`). Best-effort readahead: errors are swallowed,
diff --git a/src/sys/lib/rt.vdso/src/load.rs b/src/sys/lib/rt.vdso/src/load.rs
index 7cba7a83..3b730bd4 100644
--- a/src/sys/lib/rt.vdso/src/load.rs
+++ b/src/sys/lib/rt.vdso/src/load.rs
@@ -5,20 +5,28 @@ use elfloader::ElfBinary;
 use moto_sys::{ErrorCode, SysHandle, SysMem, sys_mem};
 
 pub fn load_vdso(address_space: u64) -> ErrorCode {
+    load_vdso_sparse(address_space, 0)
+}
+
+pub fn load_vdso_sparse(address_space: u64, sparse: u8) -> ErrorCode {
     let address_space = SysHandle::from_u64(address_space);
 
-    let entry_point = match load_binary(address_space) {
+    let entry_point = match load_binary(address_space, sparse) {
         Ok(e) => e,
         Err(err) => return err,
     };
 
-    match init_remote_vdso(address_space, entry_point) {
+    match init_remote_vdso(address_space, entry_point, sparse != 0) {
         Ok(()) => moto_rt::E_OK,
         Err(err) => err,
     }
 }
 
-fn init_remote_vdso(address_space: SysHandle, entry_point: u64) -> Result<(), ErrorCode> {
+fn init_remote_vdso(
+    address_space: SysHandle,
+    entry_point: u64,
+    sparse: bool,
+) -> Result<(), ErrorCode> {
     // The vdso bytes: a child needs them to load the vdso into its own
     // children, and every process holds the same bytes at the same address,
     // so share ours read-only instead of copying.
@@ -28,7 +36,7 @@ fn init_remote_vdso(address_space: SysHandle, entry_point: u64) -> Result<(), Er
     let num_pages = (vdso_bytes_sz + sys_mem::PAGE_SIZE_SMALL - 1) >> sys_mem::PAGE_SIZE_SMALL_LOG2;
     let remote = SysMem::map(
         address_space,
-        SysMem::F_SHARE_SELF | SysMem::F_READABLE,
+        SysMem::F_SHARE_SELF | SysMem::F_READABLE | if sparse { 0x100 } else { 0 },
         moto_rt::RT_VDSO_BYTES_ADDR,
         moto_rt::RT_VDSO_BYTES_ADDR,
         sys_mem::PAGE_SIZE_SMALL,
@@ -65,7 +73,7 @@ fn init_remote_vdso(address_space: SysHandle, entry_point: u64) -> Result<(), Er
 }
 
 // On success, return the _vdso_entry.
-fn load_binary(address_space: SysHandle) -> Result<u64, ErrorCode> {
+fn load_binary(address_space: SysHandle, sparse: u8) -> Result<u64, ErrorCode> {
     let vdso_bytes = unsafe {
         core::slice::from_raw_parts(
             moto_rt::RT_VDSO_BYTES_ADDR as usize as *const u8,
@@ -91,6 +99,7 @@ fn load_binary(address_space: SysHandle) -> Result<u64, ErrorCode> {
 
     let mut elf_loader = RemoteLoader {
         address_space,
+        sparse: sparse > 1,
         relocated: false,
         offset: moto_rt::RT_VDSO_START,
         mapped_regions: BTreeMap::default(),
@@ -106,6 +115,7 @@ fn load_binary(address_space: SysHandle) -> Result<u64, ErrorCode> {
 
 struct RemoteLoader {
     address_space: SysHandle,
+    sparse: bool,
     relocated: bool,
     offset: u64,
 
@@ -177,7 +187,8 @@ impl elfloader::ElfLoader for RemoteLoader {
                 // of its relocations land in the writable segment, so the
                 // read-only segments are identical everywhere: map ours into
                 // the child instead of allocating and copying.
-                let mut flags = SysMem::F_SHARE_SELF | SysMem::F_READABLE;
+                let mut flags =
+                    SysMem::F_SHARE_SELF | SysMem::F_READABLE | if self.sparse { 0x100 } else { 0 };
                 if header.flags().is_execute() {
                     flags |= SysMem::F_EXECUTABLE;
                 }
diff --git a/src/sys/lib/rt.vdso/src/rt_alloc.rs b/src/sys/lib/rt.vdso/src/rt_alloc.rs
index 0b667ad0..b2ed5542 100644
--- a/src/sys/lib/rt.vdso/src/rt_alloc.rs
+++ b/src/sys/lib/rt.vdso/src/rt_alloc.rs
@@ -18,7 +18,16 @@ pub fn sys_alloc(size: usize) -> *mut u8 {
 
 unsafe impl GlobalAlloc for BackEndAllocator {
     unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
-        sys_alloc(layout.size())
+        // Scratch hint applies only to allocator slabs, never IPC buffers.
+        moto_sys::SysMem::map(
+            moto_sys::SysHandle::SELF,
+            moto_sys::SysMem::F_READABLE | moto_sys::SysMem::F_WRITABLE | 0x200,
+            u64::MAX,
+            u64::MAX,
+            4096,
+            (layout.size() as u64).div_ceil(4096),
+        )
+        .map_or(core::ptr::null_mut(), |addr| addr as *mut u8)
     }
 
     unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
diff --git a/src/sys/lib/rt.vdso/src/rt_fs.rs b/src/sys/lib/rt.vdso/src/rt_fs.rs
index efc589d4..52af0155 100644
--- a/src/sys/lib/rt.vdso/src/rt_fs.rs
+++ b/src/sys/lib/rt.vdso/src/rt_fs.rs
@@ -410,6 +410,10 @@ impl AsyncFsClient {
         rx_result.await.unwrap()
     }
 
+    pub(crate) fn register_cold(&self, file: EntryId, words: Vec<u64>) -> Result<()> {
+        self.blocking_run(move |client| async move { client.register_cold(file, &words).await })
+    }
+
     pub(crate) async fn read_owned(
         &self,
         file_id: EntryId,
@@ -1611,11 +1615,12 @@ pub extern "C" fn is_terminal(rt_fd: i32) -> i32 {
 }
 
 pub extern "C" fn fsync(rt_fd: i32) -> moto_rt::ErrorCode {
-    moto_rt::E_OK
+    crate::posix::posix_flush(rt_fd)
 }
 
 pub extern "C" fn datasync(rt_fd: i32) -> moto_rt::ErrorCode {
-    moto_rt::E_OK
+    // The native flush also persists metadata; use that stronger operation.
+    crate::posix::posix_flush(rt_fd)
 }
 
 pub extern "C" fn rmdir(path_ptr: *const u8, path_size: usize) -> moto_rt::ErrorCode {
diff --git a/src/sys/lib/rt.vdso/src/rt_process.rs b/src/sys/lib/rt.vdso/src/rt_process.rs
index 4263a8f8..034d24c5 100644
--- a/src/sys/lib/rt.vdso/src/rt_process.rs
+++ b/src/sys/lib/rt.vdso/src/rt_process.rs
@@ -1,3 +1,4 @@
+mod cold;
 use alloc::borrow::ToOwned;
 use alloc::collections::BTreeMap;
 use alloc::string::String;
@@ -597,34 +598,6 @@ fn run_elf(
     stdio: &mut crate::stdio::PreparedChildStdio,
     result_rt: &mut moto_rt::process::SpawnResult,
 ) -> Result<(), ErrorCode> {
-    // TODO: currently the binary is first fully loaded into RAM, and then
-    //       the bytes are copied again as part of ELF loading. There should
-    //       be a way to avoid the extra copying. Or even do lazy loading,
-    //       i.e. don't load anything from storage until it is actually
-    //       needed (this is what Linux does, I believe).
-
-    // First, load the binary into RAM.
-    let (page_size, num_pages) = {
-        (
-            moto_sys::sys_mem::PAGE_SIZE_SMALL,
-            moto_sys::align_up(file_sz, moto_sys::sys_mem::PAGE_SIZE_SMALL)
-                >> moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2,
-        )
-    };
-    let buf_addr = moto_sys::SysMem::alloc(page_size, num_pages)?;
-    let buf: &mut [u8] =
-        unsafe { core::slice::from_raw_parts_mut(buf_addr as usize as *mut u8, file_sz as usize) };
-    crate::util::scopeguard::defer! {
-        // Free the allocated buffer.
-        moto_sys::SysMem::free(buf_addr).unwrap();
-    }
-
-    let sz = read_all(fd, buf)?;
-    if sz != file_sz as usize {
-        log::warn!("Unexpected EOF reading exe '{exe}'");
-        return Err(moto_rt::E_UNEXPECTED_EOF);
-    }
-
     let args = unsafe { ProcessData::deserialize_vec(args_rt.args) };
 
     let mut exe_plus = Vec::new();
@@ -645,14 +618,97 @@ fn run_elf(
         0,
         &full_url,
     )?);
-    let load_result = load_binary(buf, address_space.syshandle()).inspect_err(|err| {
-        let hash = moto_rt::fnv1a_hash_64(buf);
-        log::warn!(
-            "\n\tError loading ELF for '{exe}': {err:?}; buf len: {} hash: 0x{hash:x}.",
-            buf.len()
+    let raw_env = unsafe { ProcessData::deserialize_vec(args_rt.env) };
+    let mut cold_window = None;
+    for (key, value) in raw_env[..raw_env.len() / 2]
+        .iter()
+        .zip(&raw_env[raw_env.len() / 2..])
+    {
+        if *key == b"MOTOR_SPAWN_PROTO" && value.starts_with(b"cold-") {
+            cold_window = core::str::from_utf8(&value[5..])
+                .ok()
+                .and_then(|s| s.parse::<u64>().ok())
+                .filter(|v| {
+                    matches!(
+                        v,
+                        1 | 2
+                            | 4
+                            | 8
+                            | 16
+                            | 32
+                            | 64
+                            | 128
+                            | 256
+                            | 512
+                            | 768
+                            | 1024
+                            | 2048
+                            | 4096
+                            | 8192
+                            | 16384
+                            | 32768
+                            | 65536
+                            | 131072
+                            | 262144
+                    )
+                });
+        }
+    }
+    let load_result = if let Some(window) = cold_window.filter(|w| {
+        file_sz
+            >= if *w >= 16384 {
+                256 * 1024
+            } else {
+                50 * 1024 * 1024
+            }
+    }) {
+        cold::load(fd, file_sz, &exe, address_space.syshandle(), window)?
+    } else {
+        // TODO: currently the binary is first fully loaded into RAM, and then
+        //       the bytes are copied again as part of ELF loading. There should
+        //       be a way to avoid the extra copying. Or even do lazy loading,
+        //       i.e. don't load anything from storage until it is actually
+        //       needed (this is what Linux does, I believe).
+
+        // First, load the binary into RAM.
+        let (page_size, num_pages) = {
+            (
+                moto_sys::sys_mem::PAGE_SIZE_SMALL,
+                moto_sys::align_up(file_sz, moto_sys::sys_mem::PAGE_SIZE_SMALL)
+                    >> moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2,
+            )
+        };
+        let buf_addr = moto_sys::SysMem::alloc(page_size, num_pages)?;
+        let buf: &mut [u8] = unsafe {
+            core::slice::from_raw_parts_mut(buf_addr as usize as *mut u8, file_sz as usize)
+        };
+        crate::util::scopeguard::defer! {
+            // Free the allocated buffer.
+            moto_sys::SysMem::free(buf_addr).unwrap();
+        }
+
+        let sz = read_all(fd, buf)?;
+        if sz != file_sz as usize {
+            log::warn!("Unexpected EOF reading exe '{exe}'");
+            return Err(moto_rt::E_UNEXPECTED_EOF);
+        }
+
+        load_binary(buf, address_space.syshandle()).inspect_err(|err| {
+            let hash = moto_rt::fnv1a_hash_64(buf);
+            log::warn!(
+                "\n\tError loading ELF for '{exe}': {err:?}; buf len: {} hash: 0x{hash:x}.",
+                buf.len()
+            )
+        })?
+    };
+    let res = if cold_window.is_some_and(|w| w >= 2048) {
+        crate::load::load_vdso_sparse(
+            address_space.syshandle().as_u64(),
+            if cold_window.unwrap() >= 4096 { 2 } else { 1 },
         )
-    })?;
-    let res = crate::load::load_vdso(address_space.syshandle().as_u64());
+    } else {
+        crate::load::load_vdso(address_space.syshandle().as_u64())
+    };
     if res != moto_rt::E_OK {
         log::warn!("Spawn '{exe}': VDSO error: {res}.");
         return Err(res);
diff --git a/src/sys/lib/virtio-async/src/virtio_blk.rs b/src/sys/lib/virtio-async/src/virtio_blk.rs
index 4ee4beda..36546e7a 100644
--- a/src/sys/lib/virtio-async/src/virtio_blk.rs
+++ b/src/sys/lib/virtio-async/src/virtio_blk.rs
@@ -22,6 +22,15 @@ compile_error!("Little Endian is often assumed here.");
 pub const BLOCK_SIZE: usize = 4096;
 
 /// A block request whose DMA buffers are kept alive by its caller.
+static COLD_IDLE_NS: AtomicU64 = AtomicU64::new(20_000);
+static COLD_POLL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
+pub struct ColdPollGuard;
+impl Drop for ColdPollGuard {
+    fn drop(&mut self) {
+        COLD_POLL.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
+    }
+}
+
 pub type RawCompletion = WriteCompletion<()>;
 
 /*
@@ -105,7 +114,7 @@ impl BlockDevice {
     /// until the returned completion resolves.
     pub unsafe fn try_read(&self, sector: u64, pages: &[u64]) -> Option<RawCompletion> {
         assert!(!pages.is_empty());
-        self.try_request(0, sector, pages) // VIRTIO_BLK_T_IN
+        self.try_request::<false>(0, sector, pages) // VIRTIO_BLK_T_IN
     }
 
     /// Submit a write without waiting for descriptors or registering a waiter.
@@ -116,20 +125,39 @@ impl BlockDevice {
     /// until the returned completion resolves.
     pub unsafe fn try_write(&self, sector: u64, pages: &[u64]) -> Option<RawCompletion> {
         assert!(!pages.is_empty());
-        self.try_request(1, sector, pages) // VIRTIO_BLK_T_OUT
+        self.try_request::<false>(1, sector, pages) // VIRTIO_BLK_T_OUT
     }
 
     /// Call only when [`Self::flush_supported`] is true.
     pub fn try_flush(&self) -> Option<RawCompletion> {
         assert!(self.flush_supported());
-        self.try_request(4, 0, &[]) // VIRTIO_BLK_T_FLUSH
+        self.try_request::<false>(4, 0, &[]) // VIRTIO_BLK_T_FLUSH
     }
 
-    fn try_request(&self, type_: u32, sector: u64, pages: &[u64]) -> Option<RawCompletion> {
+    fn try_request<const DEFER: bool>(
+        &self,
+        type_: u32,
+        sector: u64,
+        pages: &[u64],
+    ) -> Option<RawCompletion> {
         use super::virtio_queue::UserData;
 
         assert!(pages.len() <= self.seg_max);
-        let chain_len = (pages.len() + 2) as u16;
+        let mut data: Vec<UserData> = Vec::with_capacity(pages.len());
+        for &phys_addr in pages {
+            if let Some(last) = data.last_mut()
+                && Self::cold_polling()
+                && last.phys_addr.checked_add(last.len as u64) == Some(phys_addr)
+            {
+                last.len += BLOCK_SIZE as u32;
+            } else {
+                data.push(UserData {
+                    phys_addr,
+                    len: BLOCK_SIZE as u32,
+                });
+            }
+        }
+        let chain_len = (data.len() + 2) as u16;
         let mut virtqueue = self.virtqueue.borrow_mut();
         assert!(chain_len <= virtqueue.queue_size() / 2);
         let chain_head = virtqueue.alloc_descriptor_chain(chain_len)?;
@@ -144,11 +172,8 @@ impl BlockDevice {
             phys_addr,
             len: core::mem::size_of::<BlkHeader>() as u32,
         });
-        for &phys_addr in pages {
-            buffs.push(UserData {
-                phys_addr,
-                len: BLOCK_SIZE as u32,
-            });
+        for buffer in data {
+            buffs.push(buffer);
             next_idx = virtqueue.next_idx(next_idx);
         }
         // Reserve a whole u64: CHV can write more than the status byte.
@@ -157,8 +182,8 @@ impl BlockDevice {
         buffs.push(UserData { phys_addr, len: 1 });
         let writable = if type_ == 0 { chain_len - 1 } else { 1 };
         drop(virtqueue);
-        Some(WriteCompletion {
-            vq_completion: Virtqueue::add_buffs(
+        let completion = if DEFER {
+            Virtqueue::add_buffs_deferred(
                 self.virtqueue.clone(),
                 &buffs,
                 chain_len - writable,
@@ -166,10 +191,56 @@ impl BlockDevice {
                 chain_head,
                 (),
             )
-            .expect_blk_status(),
+        } else {
+            Virtqueue::add_buffs(
+                self.virtqueue.clone(),
+                &buffs,
+                chain_len - writable,
+                writable,
+                chain_head,
+                (),
+            )
+        };
+        Some(WriteCompletion {
+            vq_completion: completion.expect_blk_status(),
         })
     }
 
+    /// Scratch batching API: same DMA lifetime rules as try_read; the
+    /// single submitter must kick before awaiting any completion.
+    ///
+    /// # Safety
+    /// Buffers obey try_read DMA ownership through completion.
+    pub unsafe fn try_read_deferred(&self, sector: u64, pages: &[u64]) -> Option<RawCompletion> {
+        self.try_request::<true>(0, sector, pages)
+    }
+
+    pub fn cold_poll(budget_ns: u64) -> ColdPollGuard {
+        COLD_IDLE_NS.store(budget_ns, Ordering::Relaxed);
+        COLD_POLL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
+        ColdPollGuard
+    }
+
+    pub(crate) fn cold_idle_ns() -> u64 {
+        COLD_IDLE_NS.load(Ordering::Relaxed)
+    }
+
+    pub fn cold_polling() -> bool {
+        COLD_POLL.load(core::sync::atomic::Ordering::Relaxed) != 0
+    }
+
+    pub fn poll_read_completions(&self) {
+        self.virtqueue.borrow_mut().reclaim_used_and_rearm();
+    }
+
+    pub fn watch_read_completions(&self, cx: &mut std::task::Context<'_>) {
+        Virtqueue::cold_watch(self.virtqueue.clone(), cx);
+    }
+
+    pub fn kick_reads(&self) {
+        self.virtqueue.borrow_mut().kick_deferred();
+    }
+
     pub fn from(dev: VirtioDevice) -> Result<Rc<Self>> {
         let dev = Rc::new(RefCell::new(dev));
         let dev_clone = dev.clone();
diff --git a/src/sys/lib/virtio-async/src/virtio_queue.rs b/src/sys/lib/virtio-async/src/virtio_queue.rs
index 93f521ba..cf391bd5 100644
--- a/src/sys/lib/virtio-async/src/virtio_queue.rs
+++ b/src/sys/lib/virtio-async/src/virtio_queue.rs
@@ -345,6 +345,19 @@ impl Virtqueue {
         Ok(self_)
     }
 
+    pub(crate) fn cold_watch(this: Rc<RefCell<Self>>, cx: &mut std::task::Context<'_>) {
+        struct Ready(Rc<RefCell<Virtqueue>>);
+        impl moto_async::SpinSource for Ready {
+            fn idle_budget_ns(&self) -> u64 {
+                crate::BlockDevice::cold_idle_ns()
+            }
+            fn ready(&self) -> bool {
+                self.0.borrow().has_new_used()
+            }
+        }
+        moto_async::register_spin_source(Box::new(Ready(this)), cx, 200_000);
+    }
+
     /// Start a complete device's queue tasks. A returned error leaves every
     /// queue unstarted; validation precedes all task ownership.
     pub(crate) fn start_tasks(queues: &[Rc<RefCell<Self>>]) -> Result<()> {
@@ -830,7 +843,7 @@ impl Virtqueue {
     /// Drain complete chains and leave interrupts armed at the stable cursor.
     /// Every reclamation path must update EVENT_IDX before returning, including
     /// opportunistic callers outside the main reclaimer task.
-    fn reclaim_used_and_rearm(&mut self) -> usize {
+    pub(crate) fn reclaim_used_and_rearm(&mut self) -> usize {
         let mut reclaimed = 0;
         loop {
             self.disable_irq();
diff --git a/src/sys/sys-io/src/runtime/fs.rs b/src/sys/sys-io/src/runtime/fs.rs
index 0bfb1cea..076108dd 100644
--- a/src/sys/sys-io/src/runtime/fs.rs
+++ b/src/sys/sys-io/src/runtime/fs.rs
@@ -20,6 +20,7 @@ use crate::util::map_err_into_native;
 use crate::util::map_native_error;
 
 mod block_io;
+mod cold_pager;
 mod lock_manager;
 mod mbr;
 pub mod stats;
@@ -595,6 +596,7 @@ async fn on_msg(
     }
 
     if let Err(err) = match msg.command {
+        0x7f00 => cold_pager::register(msg, &sender, runtime, role).await,
         moto_sys_io::api_fs::CMD_STAT => on_cmd_stat(msg, &sender, runtime, role).await,
         moto_sys_io::api_fs::CMD_STAT_PATH => on_cmd_stat_path(msg, &sender, runtime, role).await,
         moto_sys_io::api_fs::CMD_CREATE_FILE => {
@@ -1093,7 +1095,9 @@ async fn on_cmd_read(
             .set(runtime.fs_stats.read_ticks.get() + elapsed);
     }
 
-    maybe_readahead(runtime, file_id, offset, read);
+    if msg.flags & 1 == 0 {
+        maybe_readahead(runtime, file_id, offset, read);
+    }
     Ok(())
 }
 
@@ -1148,6 +1152,17 @@ async fn on_cmd_read_multi(
                     &mut io_page.bytes_mut()[..size],
                 )
                 .await?; // On error: `pages` drops, freeing them; on_msg sends the error response.
+            // Cold-spawn experiment: after the first authorized read, issue
+            // the rest of this request as grouped device reads.
+            if chunk_offset == offset && read == size && num_chunks > 1 {
+                fs_guard
+                    .prefetch(
+                        file_id,
+                        (offset + read as u64) / 4096,
+                        (num_chunks - 1) as u64,
+                    )
+                    .await;
+            }
             total += read as u32;
             chunk_offset += read as u64;
             if read < size {
@@ -1185,7 +1200,8 @@ async fn on_cmd_read_multi(
     // end of this message's window (the cursor + cached-window probe make
     // the per-message trigger cheap).
     let end = offset + total as u64;
-    if total == len as u32 && end.is_multiple_of(async_fs::BLOCK_SIZE as u64) {
+    if msg.flags & 1 == 0 && total == len as u32 && end.is_multiple_of(async_fs::BLOCK_SIZE as u64)
+    {
         runtime
             .fs_stats
             .readahead_spawns
diff --git a/src/sys/sys-io/src/runtime/fs/block_io.rs b/src/sys/sys-io/src/runtime/fs/block_io.rs
index 6f9b48d2..366cfa19 100644
--- a/src/sys/sys-io/src/runtime/fs/block_io.rs
+++ b/src/sys/sys-io/src/runtime/fs/block_io.rs
@@ -1,6 +1,5 @@
 //! One submitter owns every filesystem request on a block device's queue.
 use super::stats;
-use futures::{StreamExt, stream::FuturesUnordered};
 use moto_async::{channel, oneshot};
 use std::cell::RefCell;
 use std::future::poll_fn;
@@ -134,7 +133,7 @@ impl Request {
         // owns the page buffers and panics on early drop, until every chunk
         // has completed and the response below is delivered.
         let completion = match self.operation {
-            Operation::Read => unsafe { device.try_read(sector, pages) },
+            Operation::Read => unsafe { device.try_read_deferred(sector, pages) },
             Operation::Write => unsafe { device.try_write(sector, pages) },
             Operation::Flush => device.try_flush(),
         }?;
@@ -159,14 +158,20 @@ impl Request {
 
 type Done = (Rc<RefCell<Response>>, usize, Result<()>);
 
-async fn complete(
+struct InFlight {
     completion: RawCompletion,
     response: Rc<RefCell<Response>>,
     chunk: usize,
-) -> Done {
-    // Consuming the completion releases its descriptors before delivery.
-    let ((), result) = completion.await;
-    (response, chunk, result)
+}
+
+fn poll_done(inflight: &mut Vec<InFlight>, cx: &mut Context<'_>) -> Poll<Done> {
+    for idx in 0..inflight.len() {
+        if let Poll::Ready(((), result)) = Pin::new(&mut inflight[idx].completion).poll(cx) {
+            let done = inflight.swap_remove(idx);
+            return Poll::Ready((done.response, done.chunk, result));
+        }
+    }
+    Poll::Pending
 }
 
 fn deliver((response, chunk, result): Done, fs_stats: &stats::FsStats) {
@@ -209,12 +214,17 @@ pub(super) async fn run(
     fs_stats: Rc<stats::FsStats>,
 ) {
     let mut pending: Option<Request> = None;
-    let mut inflight = FuturesUnordered::new();
+    let mut inflight = Vec::new();
+    let mut reclaim = true;
     let mut inbox_open = true;
     loop {
         let event = poll_fn(|cx| {
+            if BlockDevice::cold_polling() && reclaim {
+                device.poll_read_completions();
+                reclaim = false;
+            }
             if !inflight.is_empty()
-                && let Poll::Ready(Some(done)) = inflight.poll_next_unpin(cx)
+                && let Poll::Ready(done) = poll_done(&mut inflight, cx)
             {
                 return Poll::Ready(Event::Done(done));
             }
@@ -228,6 +238,11 @@ pub(super) async fn run(
             if inflight.is_empty() && (pending.is_some() || !inbox_open) {
                 unreachable!("a pending block request must fit an empty queue");
             }
+            device.kick_reads();
+            if BlockDevice::cold_polling() && !inflight.is_empty() {
+                device.watch_read_completions(cx);
+            }
+            reclaim = true;
             Poll::Pending
         })
         .await;
@@ -241,7 +256,11 @@ pub(super) async fn run(
                 break;
             };
             let chunk = request.next_page / device.seg_max();
-            inflight.push(complete(completion, request.response.clone(), chunk));
+            inflight.push(InFlight {
+                completion,
+                response: request.response.clone(),
+                chunk,
+            });
             request.next_page = (request.next_page + device.seg_max()).min(request.pages.len());
             if request.next_page == request.pages.len() {
                 pending = None;
diff --git a/src/sys/kernel/src/uspace/cold_pager.rs b/src/sys/kernel/src/uspace/cold_pager.rs
new file mode 100644
--- /dev/null
+++ b/src/sys/kernel/src/uspace/cold_pager.rs
@@ -0,0 +1,344 @@
+//! Disposable parent-serviced pager. No executable cache or learned pages.
+use super::{
+    process::{Process, Thread},
+    syscall::{ResultBuilder, SyscallArgs},
+};
+use crate::{mm::user::UserAddressSpace, util::SpinLock};
+use alloc::{
+    collections::{BTreeMap, VecDeque},
+    sync::{Arc, Weak},
+    vec::Vec,
+};
+use core::sync::atomic::{AtomicU64, Ordering};
+use moto_sys::{syscalls::SyscallResult, ErrorCode, SysHandle};
+
+struct Mapping {
+    owner: Weak<Process>,
+    space: Weak<UserAddressSpace>,
+    start: u64,
+    end: u64,
+    reader: Weak<Thread>,
+    requests: VecDeque<u64>,
+    waiters: Vec<(u64, Weak<Thread>, crate::config::uCpus)>,
+    faults: u64,
+    bytes: u64,
+    notify: Option<Arc<super::SysObject>>,
+    pending_word: Option<(crate::mm::user::PinnedUserPage, usize)>,
+}
+static MAPPINGS: SpinLock<BTreeMap<u64, Mapping>> = SpinLock::new(BTreeMap::new());
+static NEXT: AtomicU64 = AtomicU64::new(1);
+
+pub(super) fn run(thread: &Thread, args: &SyscallArgs) -> SyscallResult {
+    match run_impl(thread, args) {
+        Ok((a, b)) => ResultBuilder::ok_2(a, b),
+        Err(e) => ResultBuilder::result(e),
+    }
+}
+
+fn run_impl(thread: &Thread, args: &SyscallArgs) -> Result<(u64, u64), ErrorCode> {
+    let caller = thread.owner();
+    let id = args.args[1];
+    if args.flags == 0 {
+        let space = super::sysobject::object_from_handle::<UserAddressSpace>(
+            &caller,
+            SysHandle::from_u64(args.args[0]),
+        )
+        .ok_or(moto_rt::E_INVALID_ARGUMENT)?;
+        let start = args.args[1];
+        let pages = args.args[2];
+        if start & 4095 != 0 || pages == 0 || pages > 65536 || args.args[3] > 2 {
+            return Err(moto_rt::E_INVALID_ARGUMENT);
+        }
+        let end = start
+            .checked_add(pages * 4096)
+            .ok_or(moto_rt::E_INVALID_ARGUMENT)?;
+        space.reserve_file(start, pages, args.args[3])?;
+        if (1..=2).contains(&args.args[4]) {
+            space.set_cold_lazy_heap(args.args[4]);
+        }
+        let id = NEXT.fetch_add(1, Ordering::Relaxed);
+        let mut maps = MAPPINGS.lock(line!());
+        maps.retain(|_, m| m.space.strong_count() != 0 && m.owner.strong_count() != 0);
+        maps.insert(
+            id,
+            Mapping {
+                owner: Arc::downgrade(&caller),
+                space: Arc::downgrade(&space),
+                start,
+                end,
+                reader: Weak::new(),
+                requests: VecDeque::new(),
+                waiters: Vec::new(),
+                faults: 0,
+                bytes: 0,
+                notify: None,
+                pending_word: None,
+            },
+        );
+        return Ok((id, 0));
+    }
+    if args.flags == 11 && caller.capabilities() & moto_sys::caps::CAP_IO_MANAGER != 0 {
+        let stats = crate::xray::stats::stats_from_pid(caller.pid().as_u64()).unwrap();
+        let (mut k, mut u) = (0, 0);
+        let now = crate::arch::time::Instant::now().as_u64();
+        for cpu in 0..crate::arch::num_cpus() {
+            let entry = stats.get_percpu_stats_entry(cpu);
+            k += entry.cpu_kernel.load(Ordering::Relaxed);
+            u += entry.cpu_uspace.load(Ordering::Relaxed);
+            let started = entry.started_k.load(Ordering::Relaxed);
+            if started != 0 {
+                k += now.saturating_sub(started);
+            }
+            let started = entry.started_u.load(Ordering::Relaxed);
+            if started != 0 {
+                u += now.saturating_sub(started);
+            }
+        }
+        return Ok((k, u));
+    }
+    if args.flags == 9 && caller.capabilities() & moto_sys::caps::CAP_IO_MANAGER != 0 {
+        log::info!(
+            "cold-bucket: id={} mib={} requests={} bytes={}",
+            id,
+            args.args[2],
+            args.args[3],
+            args.args[4]
+        );
+        return Ok((0, 0));
+    }
+    if args.flags == 7 && caller.capabilities() & moto_sys::caps::CAP_IO_MANAGER != 0 {
+        log::debug!(
+            "cold-service: id={} io_us={} fill_us={} bytes={}",
+            id,
+            args.args[2],
+            args.args[3],
+            args.args[4]
+        );
+        return Ok((0, 0));
+    }
+    if args.flags == 2 {
+        let mut maps = MAPPINGS.lock(line!());
+        if id != 0 && !maps.contains_key(&id) {
+            return Err(moto_rt::E_BAD_HANDLE);
+        }
+        for (map_id, m) in maps.iter_mut() {
+            if id != 0 && id != *map_id {
+                continue;
+            }
+            if core::ptr::eq(m.reader.as_ptr(), thread) {
+                if let Some(addr) = m.requests.pop_front() {
+                    if let Some((page, offset)) = &m.pending_word {
+                        let word = unsafe {
+                            &*((page.kernel_addr() + *offset as u64) as *const AtomicU64)
+                        };
+                        word.fetch_sub(1, Ordering::Release);
+                    }
+                    return Ok((*map_id, addr));
+                }
+            }
+        }
+        return Err(moto_rt::E_NOT_READY);
+    }
+    let (space, start, end) = {
+        let mut maps = MAPPINGS.lock(line!());
+        let m = maps.get_mut(&id).ok_or(moto_rt::E_INVALID_ARGUMENT)?;
+        let io_manager = caller.capabilities() & moto_sys::caps::CAP_IO_MANAGER != 0;
+        if args.flags == 6 && io_manager {
+            let connection = caller
+                .get_object(&SysHandle::from_u64(args.args[2]))
+                .ok_or(moto_rt::E_BAD_HANDLE)?;
+            let peer = super::shared::peer_owner(caller.pid(), &connection.sys_object)
+                .ok_or(moto_rt::E_NOT_ALLOWED)?;
+            if m.owner.as_ptr() != Arc::as_ptr(&peer) || m.reader.strong_count() != 0 {
+                return Err(moto_rt::E_NOT_ALLOWED);
+            }
+            let notify = super::SysObject::new(Arc::new(alloc::string::String::from("cold-pager")));
+            let handle = caller.add_object(notify.clone());
+            let pending_addr = args.args[3];
+            if pending_addr != 0 {
+                if pending_addr & 7 != 0 {
+                    return Err(moto_rt::E_INVALID_ARGUMENT);
+                }
+                let page = caller
+                    .address_space()
+                    .get_user_page_as_kernel(pending_addr & !4095)?;
+                m.pending_word = Some((page, (pending_addr & 4095) as usize));
+            }
+            m.reader = thread.get_weak();
+            m.notify = Some(notify);
+            return Ok((handle.as_u64(), 0));
+        }
+        if m.owner.as_ptr() != Arc::as_ptr(&caller)
+            && !(io_manager && core::ptr::eq(m.reader.as_ptr(), thread))
+        {
+            return Err(moto_rt::E_NOT_ALLOWED);
+        }
+        if args.flags == 4 || args.flags == 5 {
+            log::debug!(
+                "cold-loader: diagnostic={} a={} b={} c={}",
+                args.flags,
+                args.args[2],
+                args.args[3],
+                args.args[4]
+            );
+            return Ok((0, 0));
+        }
+        if args.flags == 1 {
+            if m.reader.strong_count() != 0 {
+                return Err(moto_rt::E_ALREADY_IN_USE);
+            }
+            m.reader = thread.get_weak();
+            return Ok((0, 0));
+        }
+        (
+            m.space.upgrade().ok_or(moto_rt::E_INVALID_ARGUMENT)?,
+            m.start,
+            m.end,
+        )
+    };
+    if args.flags == 12 && caller.capabilities() & moto_sys::caps::CAP_IO_MANAGER != 0 {
+        let addr = args.args[2];
+        if addr < start || addr >= end {
+            return Err(moto_rt::E_INVALID_ARGUMENT);
+        }
+        return space.mark_file_zero(addr).map(|_| (0, 0));
+    }
+    if args.flags != 3 && args.flags != 8 {
+        return Err(moto_rt::E_INVALID_ARGUMENT);
+    }
+    let addr = args.args[2];
+    let count = args.args[4];
+    if count == 0
+        || count > 64
+        || addr & 4095 != 0
+        || addr < start
+        || addr.checked_add(count * 4096).is_none_or(|v| v > end)
+    {
+        return Err(moto_rt::E_INVALID_ARGUMENT);
+    }
+    let source = args.args[3];
+    let sources = if args.flags == 8 {
+        if caller.capabilities() & moto_sys::caps::CAP_IO_MANAGER == 0 {
+            return Err(moto_rt::E_NOT_ALLOWED);
+        }
+        caller
+            .address_space()
+            .read_from_user(source, count * 8)?
+            .as_chunks::<8>()
+            .0
+            .iter()
+            .map(|v| u64::from_le_bytes(*v))
+            .collect::<Vec<_>>()
+    } else {
+        if source.checked_add(count * 4096).is_none() {
+            return Err(moto_rt::E_INVALID_ARGUMENT);
+        }
+        (0..count).map(|page| source + page * 4096).collect()
+    };
+    let mut pages = Vec::with_capacity(count as usize);
+    for source in sources {
+        if source & 4095 != 0 {
+            return Err(moto_rt::E_INVALID_ARGUMENT);
+        }
+        pages.push(caller.address_space().get_user_page_as_kernel(source)?);
+    }
+    let result = space.fill_file(addr, &pages, args.flags == 8);
+    let waiters = {
+        let mut maps = MAPPINGS.lock(line!());
+        let m = maps.get_mut(&id).ok_or(moto_rt::E_INVALID_ARGUMENT)?;
+        m.bytes += count * 4096;
+        let mut ready = Vec::new();
+        m.waiters.retain(|(page, thread, cpu)| {
+            if (addr..addr + count * 4096).contains(page) {
+                ready.push((thread.clone(), *cpu));
+                false
+            } else {
+                true
+            }
+        });
+        ready
+    };
+    for (thread, cpu) in waiters {
+        if let Some(thread) = thread.upgrade() {
+            thread.resume_file_fault(cpu, result.is_ok());
+        }
+    }
+    result.map(|_| (0, 0))
+}
+
+// Called with the faulting thread's status locked. Fills release the registry
+// lock before resuming a waiter, preventing a lost wake during registration.
+pub(super) fn enqueue(thread: &Thread, addr: u64) -> bool {
+    let owner = thread.owner();
+    let page = addr & !4095;
+    let mut maps = MAPPINGS.lock(line!());
+    for m in maps.values_mut() {
+        if m.space.as_ptr() != Arc::as_ptr(owner.address_space())
+            || !(m.start..m.end).contains(&addr)
+        {
+            continue;
+        }
+        // A concurrent fill may have completed after the original lookup.
+        if owner.address_space().virt_to_phys(page).is_some() {
+            let weak = thread.get_weak();
+            crate::sched::post(crate::sched::Job::new(
+                resume_raced,
+                weak,
+                0,
+                crate::arch::current_cpu(),
+            ));
+            return true;
+        }
+        let Some(reader) = m.reader.upgrade() else {
+            return false;
+        };
+        m.faults += 1;
+        m.waiters
+            .push((page, thread.get_weak(), crate::arch::current_cpu()));
+        if !m.requests.contains(&page) {
+            m.requests.push_back(page);
+            if let Some((backing, offset)) = &m.pending_word {
+                let word =
+                    unsafe { &*((backing.kernel_addr() + *offset as u64) as *const AtomicU64) };
+                word.fetch_add(1, Ordering::Release);
+            }
+        }
+        if let Some(notify) = &m.notify {
+            notify.wake(false);
+        } else {
+            reader.post_wake(false);
+        }
+        return true;
+    }
+    false
+}
+
+fn resume_raced(thread: Weak<Thread>, _: u64) {
+    if let Some(thread) = thread.upgrade() {
+        thread.resume_file_fault(crate::arch::current_cpu(), true);
+    }
+}
+
+pub(crate) fn retire(space: &UserAddressSpace) {
+    MAPPINGS.lock(line!()).retain(|_, m| {
+        if core::ptr::eq(m.space.as_ptr(), space) {
+            if let Some((page, offset)) = &m.pending_word {
+                let word = unsafe { &*((page.kernel_addr() + *offset as u64) as *const AtomicU64) };
+                word.store(u64::MAX, Ordering::Release);
+            }
+            if let Some(notify) = &m.notify {
+                notify.mark_done();
+                notify.wake(false);
+            }
+            log::debug!(
+                "cold-pager: start={:x} faults={} bytes={}",
+                m.start,
+                m.faults,
+                m.bytes
+            );
+            false
+        } else {
+            true
+        }
+    });
+}
diff --git a/src/sys/lib/rt.vdso/src/rt_process/cold.rs b/src/sys/lib/rt.vdso/src/rt_process/cold.rs
new file mode 100644
--- /dev/null
+++ b/src/sys/lib/rt.vdso/src/rt_process/cold.rs
@@ -0,0 +1,216 @@
+//! Disposable cold loader; known unchanged benchmark files only.
+use super::*;
+use moto_sys::SysHandle;
+
+const PAGE: u64 = 4096;
+const BAD: ErrorCode = moto_rt::E_INVALID_ARGUMENT;
+
+fn word(bytes: &[u8], pos: usize) -> Result<u64, ErrorCode> {
+    Ok(u64::from_le_bytes(
+        bytes.get(pos..pos + 8).ok_or(BAD)?.try_into().unwrap(),
+    ))
+}
+fn half(bytes: &[u8], pos: usize) -> Result<u16, ErrorCode> {
+    Ok(u16::from_le_bytes(
+        bytes.get(pos..pos + 2).ok_or(BAD)?.try_into().unwrap(),
+    ))
+}
+fn read_at(fd: moto_rt::RtFd, offset: u64, bytes: &mut [u8]) -> Result<(), ErrorCode> {
+    moto_rt::fs::seek(fd, offset as i64, moto_rt::fs::SEEK_SET)?;
+    let mut done = 0;
+    while done < bytes.len() {
+        let n = moto_rt::fs::read(fd, &mut bytes[done..])?;
+        if n == 0 {
+            return Err(moto_rt::E_UNEXPECTED_EOF);
+        }
+        done += n;
+    }
+    Ok(())
+}
+fn call(space: SysHandle, op: u32, a: u64, b: u64, c: u64, d: u64) -> Result<[u64; 6], ErrorCode> {
+    let nr = ((moto_sys::syscalls::SYS_MEM as u64) << 56) | (6 << 48) | ((op as u64) << 16);
+    let r = moto_sys::syscalls::do_syscall(nr, space.as_u64(), a, b, c, d, 0);
+    if r.is_ok() {
+        Ok(r.data)
+    } else {
+        Err(r.error_code())
+    }
+}
+
+#[derive(Clone)]
+struct Segment {
+    addr: u64,
+    file: u64,
+    filesz: u64,
+    memsz: u64,
+    flags: u32,
+}
+struct Paged {
+    id: u64,
+    segment: Segment,
+}
+pub(super) fn load(
+    fd: moto_rt::RtFd,
+    size: u64,
+    _path: &str,
+    space: SysHandle,
+    window: u64,
+) -> Result<u64, ErrorCode> {
+    let mut header = alloc::vec![0; (size.min(PAGE)) as usize];
+    read_at(fd, 0, &mut header)?;
+    if header.get(..7) != Some(&b"\x7fELF\x02\x01\x01"[..])
+        || !matches!(half(&header, 16)?, 2 | 3)
+        || half(&header, 18)? != 62
+        || half(&header, 54)? != 56
+    {
+        return Err(BAD);
+    }
+    let phoff = word(&header, 32)? as usize;
+    let phnum = half(&header, 56)? as usize;
+    if phnum == 0 || phnum > 32 {
+        return Err(BAD);
+    }
+    let table = header
+        .get(phoff..phoff.checked_add(phnum * 56).ok_or(BAD)?)
+        .ok_or(BAD)?;
+    let mut segments = Vec::new();
+    let mut dynamic = None;
+    for ph in table.as_chunks::<56>().0 {
+        let kind = u32::from_le_bytes(ph[..4].try_into().unwrap());
+        let flags = u32::from_le_bytes(ph[4..8].try_into().unwrap());
+        if kind == 3 || kind == 7 {
+            return Err(BAD);
+        }
+        let segment = Segment {
+            file: word(ph, 8)?,
+            addr: word(ph, 16)?,
+            filesz: word(ph, 32)?,
+            memsz: word(ph, 40)?,
+            flags,
+        };
+        if kind == 2 {
+            dynamic = Some(segment.clone());
+        }
+        if kind != 1 || segment.memsz == 0 {
+            continue;
+        }
+        if flags & 4 == 0
+            || flags & 3 == 3
+            || segment.memsz > 256 * 1024 * 1024
+            || segment.filesz > segment.memsz
+            || segment
+                .file
+                .checked_add(segment.filesz)
+                .is_none_or(|end| end > size)
+            || segment.addr.checked_add(segment.memsz + 4095).is_none()
+            || segment.addr % PAGE != segment.file % PAGE
+        {
+            return Err(BAD);
+        }
+        segments.push(segment);
+    }
+    if segments.is_empty() {
+        return Err(BAD);
+    }
+    for pair in segments.windows(2) {
+        if moto_sys::align_up(pair[0].addr + pair[0].memsz, PAGE) > (pair[1].addr & !4095) {
+            return Err(BAD);
+        }
+    }
+    let mut regions = Vec::new();
+    for segment in &segments {
+        let start = segment.addr & !4095;
+        let pages = (moto_sys::align_up(segment.addr + segment.memsz, PAGE) - start) / PAGE;
+        let id = call(
+            space,
+            0,
+            start,
+            pages,
+            (segment.flags & 3) as u64,
+            u64::from(window >= 65536),
+        )?[0];
+        regions.push(Paged {
+            id,
+            segment: segment.clone(),
+        });
+    }
+    let mut relocation = (0, 0);
+    let mut init = (0, 0);
+    let mut consumed = [0, 0];
+    if let Some(dynamic) = dynamic {
+        if dynamic.filesz > PAGE
+            || dynamic
+                .file
+                .checked_add(dynamic.filesz)
+                .is_none_or(|end| end > size)
+        {
+            return Err(BAD);
+        }
+        let mut bytes = alloc::vec![0; dynamic.filesz as usize];
+        read_at(fd, dynamic.file, &mut bytes)?;
+        let (mut rela, mut relasz, mut relaent, mut relacount) = (0, 0, 24, 0);
+        for (index, entry) in bytes.as_chunks::<16>().0.iter().enumerate() {
+            let tag = word(entry, 0)?;
+            let value = word(entry, 8)?;
+            match tag {
+                0 => break,
+                7 => rela = value,
+                8 => {
+                    relasz = value;
+                    consumed[0] = dynamic.addr + index as u64 * 16 + 8;
+                }
+                0x6fff_fff9 => {
+                    relacount = value;
+                    consumed[1] = dynamic.addr + index as u64 * 16 + 8;
+                }
+                9 => relaent = value,
+                25 => init.0 = value,
+                27 => init.1 = value,
+                17 | 23 | 36 if value != 0 => return Err(BAD),
+                _ => {}
+            }
+        }
+        if relaent != 24
+            || relasz % 24 != 0
+            || relasz > 16 * 1024 * 1024
+            || relacount != relasz / 24
+        {
+            return Err(BAD);
+        }
+        if relasz != 0 {
+            let source = segments
+                .iter()
+                .find(|s| {
+                    rela >= s.addr
+                        && rela
+                            .checked_add(relasz)
+                            .is_some_and(|end| end <= s.addr + s.filesz)
+                })
+                .ok_or(BAD)?;
+            relocation = (source.file + rela - source.addr, relasz);
+        }
+    }
+    let file = crate::posix::get_file(fd).ok_or(moto_rt::E_BAD_HANDLE)?;
+    let file_id = (file.as_ref() as &dyn core::any::Any)
+        .downcast_ref::<crate::rt_fs::File>()
+        .ok_or(moto_rt::E_BAD_HANDLE)?
+        .entry_id();
+    let mut words = alloc::vec![
+        window,
+        relocation.0,
+        relocation.1,
+        init.0,
+        init.1,
+        consumed[0],
+        consumed[1]
+    ];
+    for region in &regions {
+        let s = &region.segment;
+        words.extend_from_slice(&[region.id, s.addr, s.file, s.filesz, s.memsz, s.flags as u64]);
+    }
+    crate::rt_fs::AsyncFsClient::get()
+        .map_err(ErrorCode::from)?
+        .register_cold(file_id, words)
+        .map_err(ErrorCode::from)?;
+    word(&header, 24)
+}
diff --git a/src/sys/sys-io/src/runtime/fs/cold_pager.rs b/src/sys/sys-io/src/runtime/fs/cold_pager.rs
new file mode 100644
--- /dev/null
+++ b/src/sys/sys-io/src/runtime/fs/cold_pager.rs
@@ -0,0 +1,368 @@
+//! Scratch demand pager. No boot preparation or persistent executable cache.
+use super::*;
+mod prefault;
+mod relocations;
+use moto_sys::{SysHandle, syscalls};
+use relocations::Relocations;
+use std::sync::atomic::{AtomicU64, Ordering};
+struct ReadyRequest(Rc<AtomicU64>, bool);
+impl moto_async::SpinSource for ReadyRequest {
+    fn persist_through_park(&self) -> bool {
+        self.1
+    }
+    fn ready(&self) -> bool {
+        self.0.load(Ordering::Acquire) != 0
+    }
+}
+
+fn call(
+    op: u32,
+    a: u64,
+    b: u64,
+    c: u64,
+    d: u64,
+) -> std::result::Result<[u64; 6], moto_rt::ErrorCode> {
+    let nr = ((syscalls::SYS_MEM as u64) << 56) | (6 << 48) | ((op as u64) << 16);
+    let r = syscalls::do_syscall(nr, SysHandle::SELF.as_u64(), a, b, c, d, 0);
+    if r.is_ok() {
+        Ok(r.data)
+    } else {
+        Err(r.error_code())
+    }
+}
+
+async fn read_range(
+    fs: &FS,
+    role: Role,
+    file: EntryId,
+    offset: u64,
+    bytes: &mut [u8],
+) -> Result<()> {
+    if bytes.is_empty() {
+        return Ok(());
+    }
+    let first = offset / 4096;
+    let count = (offset % 4096 + bytes.len() as u64).div_ceil(4096);
+    for batch in (0..count).step_by(128) {
+        futures::future::join_all(
+            (batch..(batch + 128).min(count))
+                .step_by(16)
+                .map(|part| fs.prefetch(file, first + part, 16.min(count - part))),
+        )
+        .await;
+    }
+    let mut copied = 0;
+    while copied < bytes.len() {
+        let part = (4096 - ((offset as usize + copied) % 4096)).min(bytes.len() - copied);
+        let n = fs
+            .read(
+                role,
+                file,
+                offset + copied as u64,
+                &mut bytes[copied..copied + part],
+            )
+            .await?;
+        if n != part {
+            return Err(ErrorKind::UnexpectedEof.into());
+        }
+        copied += part;
+    }
+    Ok(())
+}
+
+pub(super) async fn register(
+    msg: moto_ipc::io_channel::Msg,
+    sender: &channel_budget::ClientSender,
+    runtime: FsRuntime,
+    role: Role,
+) -> Result<()> {
+    let (file, _, len, page) = api_fs::write_msg_decode(msg, sender).map_err(map_native_error)?;
+    if !(104..=7 * 8 + 32 * 48).contains(&len) || (len - 56) % 48 != 0 {
+        return Err(ErrorKind::InvalidInput.into());
+    }
+    let words: Vec<u64> = page.bytes()[..len as usize]
+        .as_chunks::<8>()
+        .0
+        .iter()
+        .map(|word| u64::from_le_bytes(*word))
+        .collect();
+    drop(page);
+    let (window, rela, relasz) = (words[0], words[1], words[2]);
+    let poll_guard = Rc::new(virtio_async::BlockDevice::cold_poll(200_000));
+    let dma_guard = Rc::new((window >= 65536).then(|| moto_tooling::iobuf::ColdIoGuard::new(16)));
+    if !matches!(
+        window,
+        1 | 2
+            | 4
+            | 8
+            | 16
+            | 32
+            | 64
+            | 128
+            | 256
+            | 512
+            | 1024
+            | 2048
+            | 4096
+            | 8192
+            | 16384
+            | 32768
+            | 65536
+            | 131072
+            | 262144
+    ) || relasz > 16 * 1024 * 1024
+        || relasz % 24 != 0
+    {
+        return Err(ErrorKind::InvalidInput.into());
+    }
+    let init = words[3]
+        ..words[3]
+            .checked_add(words[4])
+            .ok_or(ErrorKind::InvalidInput)?;
+    let regions: Vec<[u64; 6]> = words[7..].as_chunks::<6>().0.to_vec();
+    let fs = runtime.fs.read().await;
+    let meta = fs.metadata(role, file).await?;
+    if meta.try_kind()? != EntryKind::File
+        || !meta.access(role)?.can_execute()
+        || !meta.access(role)?.can_read()
+        || rela.checked_add(relasz).is_none_or(|end| end > meta.size)
+    {
+        return Err(ErrorKind::PermissionDenied.into());
+    }
+    for &[_, addr, offset, filesz, memsz, flags] in &regions {
+        if memsz > 256 * 1024 * 1024
+            || filesz > memsz
+            || flags & 3 == 3
+            || addr.checked_add(memsz + 4095).is_none()
+            || addr % 4096 != offset % 4096
+            || offset.checked_add(filesz).is_none_or(|end| end > meta.size)
+        {
+            return Err(ErrorKind::InvalidInput.into());
+        }
+    }
+    if moto_sys::memory_pressure() {
+        return Err(ErrorKind::OutOfMemory.into());
+    }
+    let mut relocations =
+        Relocations::new(file, role, rela, relasz, [words[5], words[6]], &regions)?;
+    relocations.interpolation = if window >= 65536 { 4 } else { 0 };
+    relocations.linear_end = window >= 65536;
+    let relocations = Rc::new(relocations);
+    drop(fs);
+    let pins = Rc::new(prefault::LaunchPins {
+        pages: std::cell::RefCell::new(std::collections::BTreeMap::new()),
+        batch: 64,
+        gap: 1,
+    });
+    let alive = Rc::new(std::cell::Cell::new(true));
+    for region in regions.iter().copied() {
+        let pins = pins.clone();
+        let alive = alive.clone();
+        let pending = Rc::new(AtomicU64::new(0));
+        let handle = call(
+            6,
+            region[0],
+            sender.remote_handle().as_u64(),
+            if window >= 32768 {
+                Rc::as_ptr(&pending) as u64
+            } else {
+                0
+            },
+            0,
+        )
+        .map_err(|e| map_native_error(e.into()))?[0];
+        let relocations = relocations.clone();
+        let runtime = runtime.clone();
+        let poll_guard = poll_guard.clone();
+        let dma_guard = dma_guard.clone();
+        moto_async::LocalRuntime::spawn(async move {
+            let _poll_guard = poll_guard;
+            let _dma_guard = dma_guard;
+            if let Err(err) = serve(
+                runtime,
+                role,
+                file,
+                region,
+                window,
+                relocations,
+                handle.into(),
+                pins,
+                alive,
+                pending,
+            )
+            .await
+            {
+                panic!("cold filesystem pager: {err:?}");
+            }
+            moto_sys::SysObj::put(handle.into()).unwrap();
+        });
+    }
+    if window >= 65536 && meta.size < 1024 * 1024 {
+        let fs = runtime.fs.read().await;
+        for region in &regions {
+            if region[5] & 2 != 0 {
+                continue;
+            }
+            let start = moto_sys::align_up(region[1], 4096);
+            let end = (region[1] + region[3]) & !4095;
+            let pages: Vec<u64> = (start..end).step_by(4096).collect();
+            prefault::fetch_map(
+                &fs,
+                role,
+                file,
+                std::slice::from_ref(region),
+                &pages,
+                &pins,
+                &alive,
+            )
+            .await?;
+        }
+    }
+    let prepared = prefault::start(
+        runtime.clone(),
+        role,
+        file,
+        regions.clone(),
+        relocations.clone(),
+        init,
+        window,
+        pins.clone(),
+        alive.clone(),
+    );
+    drop(prepared);
+    sender
+        .send(api_fs::empty_resp_encode(msg.id, Ok(())))
+        .await
+        .map_err(map_native_error)
+}
+
+#[allow(clippy::too_many_arguments)]
+async fn serve(
+    runtime: FsRuntime,
+    role: Role,
+    file: EntryId,
+    region: [u64; 6],
+    window: u64,
+    relocations: Rc<Relocations>,
+    handle: SysHandle,
+    cache_pins: prefault::Pins,
+    alive: Rc<std::cell::Cell<bool>>,
+    pending: Rc<AtomicU64>,
+) -> Result<()> {
+    let [id, addr, offset, filesz, memsz, flags] = region;
+    let lo = addr & !4095;
+    let hi = moto_sys::align_up(addr + memsz, 4096);
+    let mut buffer = Vec::new();
+    let mut signal = moto_async::SysHandleFuture::new_disarmed(handle);
+    let (mut last_end, mut adaptive_window) = (u64::MAX, 1_u64);
+    loop {
+        let request = match call(2, id, 0, 0, 0) {
+            Ok(r) => r,
+            Err(moto_rt::E_NOT_READY) => {
+                signal.rearm();
+                std::future::poll_fn(|cx| {
+                    if pending.load(Ordering::Acquire) != 0 {
+                        return std::task::Poll::Ready(Ok(()));
+                    }
+                    if window >= 32768 {
+                        moto_async::register_spin_source(
+                            Box::new(ReadyRequest(pending.clone(), window >= 65536)),
+                            cx,
+                            if window >= 65536 {
+                                1_000_000_000
+                            } else {
+                                200_000
+                            },
+                        );
+                    }
+                    std::pin::Pin::new(&mut signal).poll(cx)
+                })
+                .await
+                .map_err(map_native_error)?;
+                continue;
+            }
+            Err(moto_rt::E_BAD_HANDLE) => {
+                alive.set(false);
+                return Ok(());
+            }
+            Err(e) => return Err(map_native_error(e.into())),
+        };
+        // First-use read-ahead overlaps the demanded entry page and execution.
+        // Its range comes from this fault, never a stored executable trace.
+        if last_end == u64::MAX && flags & 1 != 0 && matches!(window, 65536 | 131072) {
+            let count = if window == 131072 { 128 } else { 256 };
+            let pages: Vec<_> = (1..count)
+                .map(|i| request[1] + i * 4096)
+                .filter(|&page| page >= addr && page + 4096 <= addr + filesz)
+                .collect();
+            let runtime = runtime.clone();
+            let pins = cache_pins.clone();
+            let alive = alive.clone();
+            moto_async::LocalRuntime::spawn(async move {
+                let fs = runtime.fs.read().await;
+                prefault::fetch_map(&fs, role, file, &[region], &pages, &pins, &alive)
+                    .await
+                    .expect("entry read-ahead");
+            });
+        }
+        let (start, pages) = if window >= 128 {
+            adaptive_window = if request[1] == last_end {
+                (adaptive_window * 2).min(32)
+            } else {
+                1
+            };
+            (request[1], adaptive_window)
+        } else {
+            (
+                lo + (request[1] - lo) / (window * 4096) * window * 4096,
+                window,
+            )
+        };
+        let end = (start + pages * 4096).min(hi);
+        last_end = end;
+        let from = start.max(addr);
+        let to = end.min(addr + filesz);
+        let fs = runtime.fs.read().await;
+        if flags & 2 == 0 && from == start && to == end {
+            let first = (offset + start - addr) / 4096;
+            fs.prefetch(file, first, (end - start) / 4096).await;
+            let mut sources = Vec::new();
+            for key in first..first + (end - start) / 4096 {
+                let snapshot = match &*fs {
+                    FS::MotorFs(fs) => fs.cold_page(role, file, key).await?,
+                };
+                let Some(snapshot) = snapshot else {
+                    break;
+                };
+                let data: &[u8] = snapshot.as_ref();
+                sources.push(data.as_ptr() as u64);
+                cache_pins.pages.borrow_mut().insert(key, snapshot);
+            }
+            if sources.len() == ((end - start) / 4096) as usize {
+                drop(fs);
+                call(8, id, start, sources.as_ptr() as u64, sources.len() as u64)
+                    .map_err(|e| map_native_error(e.into()))?;
+                continue;
+            }
+        }
+        buffer.resize((end - start) as usize, 0);
+        let bytes = &mut buffer[..];
+        bytes.fill(0);
+        if to > from {
+            read_range(
+                &fs,
+                role,
+                file,
+                offset + from - addr,
+                &mut bytes[(from - start) as usize..(to - start) as usize],
+            )
+            .await?;
+        }
+        if flags & 2 != 0 {
+            relocations.apply(&fs, start, bytes).await?;
+        }
+        drop(fs);
+        call(3, id, start, bytes.as_ptr() as u64, (end - start) / 4096)
+            .map_err(|e| map_native_error(e.into()))?;
+    }
+}
diff --git a/src/sys/sys-io/src/runtime/fs/cold_pager/prefault.rs b/src/sys/sys-io/src/runtime/fs/cold_pager/prefault.rs
new file mode 100644
--- /dev/null
+++ b/src/sys/sys-io/src/runtime/fs/cold_pager/prefault.rs
@@ -0,0 +1,233 @@
+//! Constructor-order, streaming prefetch. All input comes from this launch.
+use super::*;
+use std::cell::{Cell, RefCell};
+use std::collections::BTreeSet;
+
+pub(super) struct LaunchPins {
+    pub pages: RefCell<std::collections::BTreeMap<u64, async_fs::block_cache::CheckpointedBlock>>,
+    pub batch: usize,
+    pub gap: u64,
+}
+pub(super) type Pins = Rc<LaunchPins>;
+
+#[allow(clippy::too_many_arguments)]
+pub(super) fn start(
+    runtime: FsRuntime,
+    role: Role,
+    file: EntryId,
+    regions: Vec<[u64; 6]>,
+    relocations: Rc<Relocations>,
+    init: std::ops::Range<u64>,
+    window: u64,
+    pins: Pins,
+    alive: Rc<Cell<bool>>,
+) -> moto_async::oneshot::Receiver<()> {
+    let (ready, result) = moto_async::oneshot::oneshot();
+    moto_async::LocalRuntime::spawn(async move {
+        let mut ready = Some(ready);
+        let result: Result<()> = async {
+            let fs = runtime.fs.read().await;
+            relocations.prefetch_tree(&fs).await;
+            for &[id, addr, _, filesz, memsz, flags] in &regions {
+                let start = moto_sys::align_up(addr + filesz, 4096);
+                let end = moto_sys::align_up(addr + memsz, 4096);
+                if window < 8192 || flags & 2 == 0 || start >= end || end - start > 1024 * 1024 {
+                    continue;
+                }
+                if !relocations.bounds(&fs, start, end).await?.is_empty() {
+                    continue;
+                }
+                if let Err(error) = call(12, id, start, 0, 0) {
+                    if call(2, id, 0, 0, 0) == Err(moto_rt::E_BAD_HANDLE) {
+                        return Ok(());
+                    }
+                    return Err(map_native_error(error.into()));
+                }
+            }
+            let mut seen = BTreeSet::new();
+            let mut pages = Vec::new();
+            let mut functions = Vec::new();
+            let indices = relocations.bounds(&fs, init.start, init.end).await?;
+            let count = if window >= 1024 {
+                2
+            } else {
+                (window / 128).max(1)
+            };
+            for index in indices {
+                let [target, _, value] = relocations.entry(&fs, index).await?;
+                if init.contains(&target) {
+                    functions.push(value);
+                    for extra in 0..count {
+                        let page = (value & !4095) + extra * 4096;
+                        if region_for(&regions, page).is_some() && seen.insert(page) {
+                            pages.push(page);
+                        }
+                    }
+                }
+            }
+            fetch_map(&fs, role, file, &regions, &pages, &pins, &alive).await?;
+            if window == 131072 {
+                let _ = ready.take().unwrap().send(());
+            }
+            if window >= 1024 {
+                let extra = references(
+                    &fs, role, file, &regions, &functions, 128, &mut seen, &alive, &pins,
+                )
+                .await?;
+                fetch_map(&fs, role, file, &regions, &extra, &pins, &alive).await?;
+            }
+            Ok(())
+        }
+        .await;
+        if let Err(error) = result {
+            panic!("cold prefetch: {error:?}");
+        }
+        if let Some(ready) = ready {
+            let _ = ready.send(());
+        }
+    });
+    result
+}
+
+fn region_for(regions: &[[u64; 6]], page: u64) -> Option<&[u64; 6]> {
+    regions.iter().find(|&&[_, addr, _, size, _, flags]| {
+        flags & 2 == 0 && page >= addr && page + 4096 <= addr + size
+    })
+}
+
+pub(super) async fn fetch_map(
+    fs: &FS,
+    role: Role,
+    file: EntryId,
+    regions: &[[u64; 6]],
+    pages: &[u64],
+    pins: &Pins,
+    alive: &Cell<bool>,
+) -> Result<()> {
+    for batch in pages.chunks(pins.batch) {
+        if !alive.get() {
+            return Ok(());
+        }
+        let mut ordered = batch.to_vec();
+        ordered.sort_unstable();
+        let mut runs: Vec<(u64, u64, u64)> = Vec::new();
+        for page in ordered {
+            let region = region_for(regions, page).unwrap();
+            let key = (region[2] + page - region[1]) / 4096;
+            if let Some((first, count, id)) = runs.last_mut()
+                && *id == region[0]
+                && key >= *first + *count
+                && key <= *first + *count + pins.gap
+                && key < *first + 16
+            {
+                *count = key + 1 - *first;
+            } else {
+                runs.push((key, 1, region[0]));
+            }
+        }
+        futures::future::join_all(
+            runs.iter()
+                .map(|&(first, count, _)| fs.prefetch(file, first, count)),
+        )
+        .await;
+        for &(first, count, id) in &runs {
+            if !alive.get() {
+                return Ok(());
+            }
+            let region = regions.iter().find(|r| r[0] == id).unwrap();
+            let page = region[1] + first * 4096 - region[2];
+            let mut sources = Vec::new();
+            for key in first..first + count {
+                let snapshot = match fs {
+                    FS::MotorFs(fs) => fs.cold_page(role, file, key).await?,
+                };
+                let Some(snapshot) = snapshot else {
+                    break;
+                };
+                let bytes: &[u8] = snapshot.as_ref();
+                sources.push(bytes.as_ptr() as u64);
+                pins.pages.borrow_mut().insert(key, snapshot);
+            }
+            if sources.is_empty() {
+                continue;
+            }
+            if let Err(error) = call(8, id, page, sources.as_ptr() as u64, sources.len() as u64) {
+                if call(2, id, 0, 0, 0) == Err(moto_rt::E_BAD_HANDLE) {
+                    return Ok(());
+                }
+                return Err(map_native_error(error.into()));
+            }
+        }
+        if pins.batch < 64 {
+            moto_async::yield_to_io().await;
+        }
+    }
+    Ok(())
+}
+
+#[allow(clippy::too_many_arguments)]
+async fn references(
+    fs: &FS,
+    role: Role,
+    file: EntryId,
+    regions: &[[u64; 6]],
+    functions: &[u64],
+    length: usize,
+    seen: &mut BTreeSet<u64>,
+    alive: &Cell<bool>,
+    pins: &Pins,
+) -> Result<Vec<u64>> {
+    let mut extra = Vec::new();
+    for &function in functions {
+        if !alive.get() {
+            break;
+        }
+        let Some(region) = region_for(regions, function & !4095) else {
+            continue;
+        };
+        let mut bytes = vec![0_u8; length.min((region[1] + region[3] - function) as usize)];
+        let offset = region[2] + function - region[1];
+        let cached = {
+            let pinned = pins.pages.borrow();
+            let range = offset / 4096..(offset + bytes.len() as u64).div_ceil(4096);
+            if range.clone().all(|key| pinned.contains_key(&key)) {
+                let mut copied = 0;
+                for key in range {
+                    let source: &[u8] = pinned[&key].as_ref();
+                    let from = ((offset + copied as u64) & 4095) as usize;
+                    let count = (4096 - from).min(bytes.len() - copied);
+                    bytes[copied..copied + count].copy_from_slice(&source[from..from + count]);
+                    copied += count;
+                }
+                true
+            } else {
+                false
+            }
+        };
+        if !cached {
+            read_range(fs, role, file, offset, &mut bytes).await?;
+        }
+        for i in 0..bytes.len().saturating_sub(7) {
+            if i > 16 && bytes[i..i + 2] == [0xcc, 0xcc] {
+                break;
+            }
+            let (disp, end) = if matches!(bytes[i], 0xe8 | 0xe9) {
+                (i + 1, i + 5)
+            } else if bytes[i] & 0xf0 == 0x40
+                && matches!(bytes[i + 1], 0x8d | 0x8b)
+                && bytes[i + 2] & 0xc7 == 5
+            {
+                (i + 3, i + 7)
+            } else {
+                continue;
+            };
+            let rel = i32::from_le_bytes(bytes[disp..disp + 4].try_into().unwrap());
+            let page = (function + end as u64).wrapping_add_signed(rel as i64) & !4095;
+            if region_for(regions, page).is_some() && seen.insert(page) {
+                extra.push(page);
+            }
+        }
+    }
+    extra.sort_unstable();
+    Ok(extra)
+}
diff --git a/src/sys/sys-io/src/runtime/fs/cold_pager/relocations.rs b/src/sys/sys-io/src/runtime/fs/cold_pager/relocations.rs
new file mode 100644
--- /dev/null
+++ b/src/sys/sys-io/src/runtime/fs/cold_pager/relocations.rs
@@ -0,0 +1,222 @@
+//! Prototype precondition: RELATIVE entries ordered by target address.
+//! The benchmark ELF satisfies this; arbitrary ELF support needs a verified
+//! ordering contract or a full scan. No learned pages or persisted index.
+use super::*;
+use async_fs::block_cache::CheckpointedBlock;
+use std::cell::RefCell;
+use std::collections::BTreeMap;
+use std::ops::Range;
+
+pub(super) struct Relocations {
+    pub(super) interpolation: usize,
+    pub(super) linear_end: bool,
+    file: EntryId,
+    role: Role,
+    offset: u64,
+    count: usize,
+    consumed: [u64; 2],
+    writable: Vec<Range<u64>>,
+    pages: RefCell<BTreeMap<u64, CheckpointedBlock>>,
+}
+
+impl Relocations {
+    pub(super) fn new(
+        file: EntryId,
+        role: Role,
+        offset: u64,
+        bytes: u64,
+        consumed: [u64; 2],
+        regions: &[[u64; 6]],
+    ) -> Result<Self> {
+        let writable: Vec<_> = regions
+            .iter()
+            .filter(|v| v[5] & 2 != 0)
+            .map(|v| v[1]..v[1] + v[4])
+            .collect();
+        let result = Self {
+            interpolation: 0,
+            linear_end: false,
+            file,
+            role,
+            offset,
+            count: bytes as usize / 24,
+            consumed,
+            writable,
+            pages: RefCell::new(BTreeMap::new()),
+        };
+        for &target in &consumed {
+            if target != 0 {
+                result.validate([target, 8, 0])?;
+            }
+        }
+        Ok(result)
+    }
+
+    fn validate(&self, entry: [u64; 3]) -> Result<()> {
+        if entry[1] != 8
+            || !self.writable.iter().any(|v| {
+                entry[0] >= v.start && entry[0].checked_add(8).is_some_and(|end| end <= v.end)
+            })
+        {
+            return Err(ErrorKind::InvalidInput.into());
+        }
+        Ok(())
+    }
+
+    pub(super) async fn entry(&self, fs: &FS, index: usize) -> Result<[u64; 3]> {
+        if index >= self.count {
+            return Err(ErrorKind::InvalidInput.into());
+        }
+        let mut bytes = [0_u8; 24];
+        self.read(fs, self.offset + index as u64 * 24, &mut bytes)
+            .await?;
+        let entry = core::array::from_fn(|i| {
+            u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap())
+        });
+        self.validate(entry)?;
+        Ok(entry)
+    }
+
+    async fn read(&self, fs: &FS, offset: u64, bytes: &mut [u8]) -> Result<()> {
+        let mut copied = 0;
+        while copied < bytes.len() {
+            let pos = offset as usize + copied;
+            let key = pos as u64 / 4096;
+            if !self.pages.borrow().contains_key(&key) {
+                let snapshot = match fs {
+                    FS::MotorFs(fs) => fs.cold_page(self.role, self.file, key).await?,
+                };
+                let Some(snapshot) = snapshot else {
+                    return read_range(fs, self.role, self.file, offset, bytes).await;
+                };
+                self.pages.borrow_mut().insert(key, snapshot);
+            }
+            let pages = self.pages.borrow();
+            let source: &[u8] = pages[&key].as_ref();
+            let count = (4096 - pos % 4096).min(bytes.len() - copied);
+            bytes[copied..copied + count].copy_from_slice(&source[pos % 4096..pos % 4096 + count]);
+            copied += count;
+        }
+        Ok(())
+    }
+
+    async fn lower_bound(&self, fs: &FS, target: u64) -> Result<usize> {
+        if self.count == 0 || target <= self.entry(fs, 0).await?[0] {
+            return Ok(0);
+        }
+        if target > self.entry(fs, self.count - 1).await?[0] {
+            return Ok(self.count);
+        }
+        let (mut lo, mut hi) = (0, self.count);
+        let (mut low_target, mut high_target) = (0, u64::MAX);
+        let mut depth = 0;
+        while lo < hi {
+            // Start with the six prefetched binary levels. Interpolate only
+            // inside that local bracket, then restore binary progress.
+            let mid = if depth >= 6
+                && depth < 6 + self.interpolation
+                && lo != 0
+                && hi < self.count
+                && high_target > low_target
+            {
+                let distance = (target - low_target) as u128 * (hi - lo + 1) as u128;
+                ((lo - 1) + (distance / (high_target - low_target) as u128) as usize)
+                    .clamp(lo, hi - 1)
+            } else {
+                lo + (hi - lo) / 2
+            };
+            depth += 1;
+            let addr = self.entry(fs, mid).await?[0];
+            if addr < low_target || addr > high_target {
+                return Err(ErrorKind::InvalidInput.into());
+            }
+            if addr < target {
+                lo = mid + 1;
+                low_target = addr;
+            } else {
+                hi = mid;
+                high_target = addr;
+            }
+        }
+        Ok(lo)
+    }
+
+    pub(super) async fn prefetch_tree(&self, fs: &FS) {
+        let mut nodes = vec![(0, self.count, 0)];
+        let mut pages = std::collections::BTreeSet::new();
+        while let Some((lo, hi, depth)) = nodes.pop() {
+            if lo >= hi || depth == 6 {
+                continue;
+            }
+            let mid = lo + (hi - lo) / 2;
+            pages.insert((self.offset + mid as u64 * 24) / 4096);
+            nodes.push((lo, mid, depth + 1));
+            nodes.push((mid + 1, hi, depth + 1));
+        }
+        let pages: Vec<_> = pages.into_iter().collect();
+        for batch in pages.chunks(32) {
+            futures::future::join_all(batch.iter().map(|&page| fs.prefetch(self.file, page, 1)))
+                .await;
+        }
+    }
+
+    pub(super) async fn bounds(&self, fs: &FS, start: u64, end: u64) -> Result<Range<usize>> {
+        let lo = self.lower_bound(fs, start.saturating_sub(7)).await?;
+        let hi = self.lower_bound(fs, end).await?;
+        if hi < lo {
+            return Err(ErrorKind::InvalidInput.into());
+        }
+        Ok(lo..hi)
+    }
+
+    pub(super) async fn apply(&self, fs: &FS, start: u64, bytes: &mut [u8]) -> Result<()> {
+        let end = start + bytes.len() as u64;
+        let range = if self.linear_end {
+            self.lower_bound(fs, start.saturating_sub(7)).await?..self.count
+        } else {
+            self.bounds(fs, start, end).await?
+        };
+        let mut buffer = [0_u8; 64 * 24];
+        let mut previous = 0;
+        'records: for first in range.clone().step_by(64) {
+            let count = (range.end - first).min(64);
+            self.read(
+                fs,
+                self.offset + first as u64 * 24,
+                &mut buffer[..count * 24],
+            )
+            .await?;
+            for row in buffer[..count * 24].as_chunks::<24>().0 {
+                let entry: [u64; 3] = core::array::from_fn(|i| {
+                    u64::from_le_bytes(row[i * 8..i * 8 + 8].try_into().unwrap())
+                });
+                self.validate(entry)?;
+                if entry[0] < previous {
+                    return Err(ErrorKind::InvalidInput.into());
+                }
+                previous = entry[0];
+                if entry[0] >= end {
+                    break 'records;
+                }
+                Self::store(bytes, start, entry[0], entry[2]);
+            }
+        }
+        for &target in &self.consumed {
+            if target != 0 {
+                Self::store(bytes, start, target, 0);
+            }
+        }
+        Ok(())
+    }
+
+    fn store(bytes: &mut [u8], start: u64, target: u64, value: u64) {
+        let from = target.max(start);
+        let to = (target + 8).min(start + bytes.len() as u64);
+        if from >= to {
+            return;
+        }
+        bytes[(from - start) as usize..(to - start) as usize].copy_from_slice(
+            &value.to_le_bytes()[(from - target) as usize..(to - target) as usize],
+        );
+    }
+}
````

## Appendix B: warm prototype patches (2026-10-01)

Apply in order to the same base commit.

### 01-prepared-image.patch

````diff
diff --git a/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs b/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs
new file mode 100644
index 0000000..613e4f8
--- /dev/null
+++ b/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs
@@ -0,0 +1,106 @@
+//! Experiment only: one prepared image in the spawning process.
+//! Metadata checks are not an immutable filesystem snapshot protocol.
+use super::*;
+use moto_sys::{SysHandle, SysMem, sys_mem::PAGE_SIZE_SMALL};
+
+struct Segment {
+    remote: u64,
+    local: u64,
+    pages: u64,
+    flags: u32,
+}
+
+struct Image {
+    identity: (u128, u128, u64),
+    entry: u64,
+    segments: Vec<Segment>,
+}
+
+impl Drop for Image {
+    fn drop(&mut self) {
+        for seg in &self.segments {
+            SysMem::free(seg.local).unwrap();
+        }
+    }
+}
+
+static IMAGE: moto_rt::mutex::Mutex<Option<Image>> = moto_rt::mutex::Mutex::new(None);
+
+pub(super) fn load(fd: RtFd, size: u64, child: SysHandle) -> Result<u64, ErrorCode> {
+    let attr = moto_rt::fs::get_file_attr(fd)?;
+    let identity = (attr.entry_id, attr.modified, size);
+    let mut cache = IMAGE.lock();
+    if cache
+        .as_ref()
+        .is_none_or(|image| image.identity != identity)
+    {
+        *cache = None;
+        let addr = SysMem::alloc(PAGE_SIZE_SMALL, size.div_ceil(PAGE_SIZE_SMALL))?;
+        crate::util::scopeguard::defer! { SysMem::free(addr).unwrap(); }
+        let bytes = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, size as usize) };
+        read_all(fd, bytes)?;
+        let elf = elfloader::ElfBinary::new(bytes).map_err(|_| moto_rt::E_INVALID_ARGUMENT)?;
+        let space = moto_sys::syscalls::RaiiHandle::from(moto_sys::SysObj::create(
+            SysHandle::NONE,
+            0,
+            "address_space:debug_name=prototype-template",
+        )?);
+        let mut loader = Loader {
+            address_space: space.syshandle(),
+            relocated: false,
+            mapped_regions: BTreeMap::new(),
+            map_error: None,
+            retain: false,
+            region_flags: BTreeMap::new(),
+        };
+        elf.load(&mut loader)
+            .map_err(|_| loader.map_error.unwrap_or(moto_rt::E_INVALID_ARGUMENT))?;
+        let mut segments = Vec::new();
+        for (&remote, &(local, pages)) in &loader.mapped_regions {
+            let flags = loader.region_flags[&remote];
+            segments.push(Segment {
+                remote,
+                local,
+                pages,
+                flags,
+            });
+        }
+        loader.retain = true;
+        *cache = Some(Image {
+            identity,
+            entry: elf.entry_point(),
+            segments,
+        });
+    }
+    let image = cache.as_ref().unwrap();
+    for seg in &image.segments {
+        if seg.flags & SysMem::F_WRITABLE == 0 {
+            SysMem::map(
+                child,
+                seg.flags,
+                seg.local,
+                seg.remote,
+                PAGE_SIZE_SMALL,
+                seg.pages,
+            )?;
+        } else {
+            let (_, local) = SysMem::map2(
+                child,
+                seg.flags,
+                u64::MAX,
+                seg.remote,
+                PAGE_SIZE_SMALL,
+                seg.pages,
+            )?;
+            unsafe {
+                core::ptr::copy_nonoverlapping(
+                    seg.local as *const u8,
+                    local as *mut u8,
+                    (seg.pages * PAGE_SIZE_SMALL) as usize,
+                );
+            }
+            SysMem::free(local).unwrap();
+        }
+    }
+    Ok(image.entry)
+}
diff --git a/src/sys/lib/rt.vdso/src/rt_process.rs b/src/sys/lib/rt.vdso/src/rt_process.rs
index 4263a8f..6ffb396 100644
--- a/src/sys/lib/rt.vdso/src/rt_process.rs
+++ b/src/sys/lib/rt.vdso/src/rt_process.rs
@@ -5,6 +5,8 @@ use alloc::vec::Vec;
 use moto_rt::ErrorCode;
 use moto_rt::RtFd;
 
+mod spawn_cache;
+
 pub unsafe extern "C" fn args() -> u64 {
     let args: Vec<String> = unsafe {
         ProcessData::get()
@@ -280,6 +282,8 @@ struct Loader {
     // Why the kernel refused to map a segment. elfloader can only report
     // OutOfMemory, which would call a bad segment address a lack of memory.
     map_error: Option<ErrorCode>,
+    retain: bool,
+    region_flags: BTreeMap<u64, u32>,
 }
 
 impl Loader {
@@ -317,6 +321,9 @@ impl Loader {
 
 impl Drop for Loader {
     fn drop(&mut self) {
+        if self.retain {
+            return;
+        }
         for (addr, _) in self.mapped_regions.values() {
             moto_sys::SysMem::unmap(moto_sys::SysHandle::SELF, 0, u64::MAX, *addr).unwrap();
         }
@@ -371,6 +378,7 @@ impl elfloader::ElfLoader for Loader {
 
             assert_eq!(remote, vaddr_start);
             self.mapped_regions.insert(vaddr_start, (local, num_pages));
+            self.region_flags.insert(vaddr_start, flags);
         }
         Ok(())
     }
@@ -457,6 +465,8 @@ fn load_binary(bytes: &[u8], address_space: moto_sys::SysHandle) -> Result<u64,
         relocated: false,
         mapped_regions: BTreeMap::default(),
         map_error: None,
+        retain: false,
+        region_flags: BTreeMap::new(),
     };
     match elf_binary.load(&mut elf_loader) {
         // A refused mapping keeps the kernel's reason, so running out of
@@ -597,6 +607,12 @@ fn run_elf(
     stdio: &mut crate::stdio::PreparedChildStdio,
     result_rt: &mut moto_rt::process::SpawnResult,
 ) -> Result<(), ErrorCode> {
+    let launch_env = unsafe { ProcessData::deserialize_vec(args_rt.env) };
+    let prototype = (0..launch_env.len() / 2)
+        .find(|&i| launch_env[i] == b"MOTOR_SPAWN_PROTO")
+        .map(|i| launch_env[i + launch_env.len() / 2])
+        .unwrap_or(b"eager");
+    let cached = prototype.starts_with(b"cache");
     // TODO: currently the binary is first fully loaded into RAM, and then
     //       the bytes are copied again as part of ELF loading. There should
     //       be a way to avoid the extra copying. Or even do lazy loading,
@@ -611,15 +627,26 @@ fn run_elf(
                 >> moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2,
         )
     };
-    let buf_addr = moto_sys::SysMem::alloc(page_size, num_pages)?;
-    let buf: &mut [u8] =
-        unsafe { core::slice::from_raw_parts_mut(buf_addr as usize as *mut u8, file_sz as usize) };
+    let buf_addr = if cached {
+        0
+    } else {
+        moto_sys::SysMem::alloc(page_size, num_pages)?
+    };
+    let buf: &mut [u8] = if cached {
+        &mut []
+    } else {
+        unsafe { core::slice::from_raw_parts_mut(buf_addr as usize as *mut u8, file_sz as usize) }
+    };
     crate::util::scopeguard::defer! {
         // Free the allocated buffer.
-        moto_sys::SysMem::free(buf_addr).unwrap();
+        if buf_addr != 0 { moto_sys::SysMem::free(buf_addr).unwrap(); }
     }
 
-    let sz = read_all(fd, buf)?;
+    let sz = if cached {
+        file_sz as usize
+    } else {
+        read_all(fd, buf)?
+    };
     if sz != file_sz as usize {
         log::warn!("Unexpected EOF reading exe '{exe}'");
         return Err(moto_rt::E_UNEXPECTED_EOF);
@@ -645,7 +672,12 @@ fn run_elf(
         0,
         &full_url,
     )?);
-    let load_result = load_binary(buf, address_space.syshandle()).inspect_err(|err| {
+    let load_result = if cached {
+        spawn_cache::load(fd, file_sz, address_space.syshandle())
+    } else {
+        load_binary(buf, address_space.syshandle())
+    }
+    .inspect_err(|err| {
         let hash = moto_rt::fnv1a_hash_64(buf);
         log::warn!(
             "\n\tError loading ELF for '{exe}': {err:?}; buf len: {} hash: 0x{hash:x}.",
@@ -681,7 +713,9 @@ fn run_elf(
     let mut no_terminal = false;
     // Find the capability, detached, and stdio launch-only env vars.
     for (k, v) in &mut env {
-        if *k == moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY.as_bytes() {
+        if *k == b"MOTOR_SPAWN_PROTO" {
+            *k = b"";
+        } else if *k == moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY.as_bytes() {
             *k = "".as_bytes(); // Clear the key: see env::create_remote_env().
             let v = core::str::from_utf8(v).map_err(|_| moto_rt::E_INVALID_ARGUMENT)?;
             caps = u64::from_str_radix(v.trim_start_matches("0x"), 16).map_err(|_| {
````

### 02-sparse-mappings.patch

````diff
diff --git a/src/sys/kernel/src/mm/mod.rs b/src/sys/kernel/src/mm/mod.rs
index b501112..b51682a 100644
--- a/src/sys/kernel/src/mm/mod.rs
+++ b/src/sys/kernel/src/mm/mod.rs
@@ -286,6 +286,7 @@ bitflags! {
         // A segment's creation policy, never a per-page hardware option:
         // 2 MiB-aligned placement and huge candidates for its mapping.
         const HUGE_ELIGIBLE   = 512;
+        const IMAGE_SPARSE    = 1024; // Scratch prepared-image experiment.
     }
 }
 
diff --git a/src/sys/kernel/src/mm/user.rs b/src/sys/kernel/src/mm/user.rs
index 506cf82..e286fca 100644
--- a/src/sys/kernel/src/mm/user.rs
+++ b/src/sys/kernel/src/mm/user.rs
@@ -464,6 +464,22 @@ impl UserAddressSpace {
         num_pages: u64,
         mapping_options: super::MappingOptions,
     ) -> Result<(), ErrorCode> {
+        if mapping_options.contains(MappingOptions::IMAGE_SPARSE) {
+            self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;
+            if let Err(err) = self
+                .inner
+                .vmem_allocate_user_fixed(vaddr, num_pages, mapping_options)
+            {
+                self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
+                return Err(err);
+            }
+            return source
+                .inner
+                .share_with(source_addr, &self.inner, vaddr, mapping_options)
+                .inspect_err(|_| {
+                    let _ = self.unmap(vaddr);
+                });
+        }
         self.fill_fixed(vaddr, num_pages, |inner| {
             source
                 .inner
diff --git a/src/sys/kernel/src/mm/virt_intrusive.rs b/src/sys/kernel/src/mm/virt_intrusive.rs
index 6501b29..cf2119c 100644
--- a/src/sys/kernel/src/mm/virt_intrusive.rs
+++ b/src/sys/kernel/src/mm/virt_intrusive.rs
@@ -2,6 +2,7 @@
 // utilize intrusive collections: using normal vectors/maps is not right, as
 // they involve heap allocations, and we don't want to do heap allocations
 // while allocating virtual memory, as it results in nasty recursion.
+use alloc::{sync::Arc, vec::Vec};
 use core::mem::MaybeUninit;
 
 use intrusive_collections::{intrusive_adapter, Bound, UnsafeRef};
@@ -260,6 +261,8 @@ pub(super) struct VmemSegment {
     pages: RBTree<PageTreeAdapter>,
     owner: crate::util::UnsafeRef<super::virt::VmemRegion>,
     mapping_options: MappingOptions,
+    image: SpinLock<Option<Arc<Vec<SlabArc<Frame>>>>>,
+    image_offset: usize,
 }
 
 impl Drop for VmemSegment {
@@ -279,6 +282,8 @@ impl VmemSegment {
             owner: crate::util::UnsafeRef::from(owner),
             mapping_options,
             pages: RBTree::new(PageTreeAdapter::new()),
+            image: SpinLock::new(None),
+            image_offset: 0,
         }
     }
 
@@ -310,6 +315,16 @@ impl VmemSegment {
     pub(super) fn vaddr_map_status(&self, vmem_addr: u64) -> VaddrMapStatus {
         assert!(self.segment.contains(vmem_addr));
 
+        if self.mapping_options.contains(MappingOptions::IMAGE_SPARSE)
+            && self.find_page(vmem_addr).is_none()
+        {
+            return self
+                .image_page(vmem_addr)
+                .map_or(VaddrMapStatus::Unmapped, |(f, offset)| {
+                    VaddrMapStatus::Shared(f.get().unwrap().start() + offset)
+                });
+        }
+
         let page = self.find_page(vmem_addr).unwrap();
 
         if let Some(frame) = page.frame.get() {
@@ -330,6 +345,9 @@ impl VmemSegment {
     }
 
     pub(super) fn pin_user_page(&self, vmem_addr: u64) -> Option<(SlabArc<Frame>, u64)> {
+        if self.mapping_options.contains(MappingOptions::IMAGE_SPARSE) {
+            return self.image_page(vmem_addr);
+        }
         let page = self.find_page(vmem_addr)?;
         let frame = page.frame.get()?;
         if frame.is_mmio() {
@@ -340,6 +358,15 @@ impl VmemSegment {
         Some((page.frame.clone(), vmem_addr - page.start))
     }
 
+    fn image_page(&self, addr: u64) -> Option<(SlabArc<Frame>, u64)> {
+        let index = ((addr - self.segment.start) / PAGE_SIZE_SMALL) as usize + self.image_offset;
+        let image = self.image.lock(line!());
+        Some((
+            image.as_ref()?.get(index)?.clone(),
+            addr & (PAGE_SIZE_SMALL - 1),
+        ))
+    }
+
     pub(super) fn unmap(mut self) -> u64 {
         // Note: it is important to unmap pages before freeing the segment
         // in the VMemRegion, otherwise a concurrent allocation may try
@@ -388,6 +415,11 @@ impl VmemSegment {
             self.address_space().page_allocator.free_page(page_ptr);
         }
 
+        if self.mapping_options.contains(MappingOptions::IMAGE_SPARSE) {
+            sz = self.segment.size;
+        }
+        self.image.lock(line!()).take();
+        self.image_offset = 0;
         self.segment = MemorySegment::empty_segment();
         self.owner.clear();
 
@@ -418,6 +450,9 @@ impl VmemSegment {
     pub(super) fn allocate_pages(&mut self) -> Result<(), ErrorCode> {
         assert!(self.segment.size > 0);
         assert!(self.pages.is_empty());
+        if self.mapping_options.contains(MappingOptions::IMAGE_SPARSE) {
+            return Ok(());
+        }
 
         let num_pages = self.segment.size >> PAGE_SIZE_SMALL_LOG2;
         let huge = self.huge_candidates();
@@ -557,6 +592,27 @@ impl VmemSegment {
     pub(super) fn fix_pagefault(&mut self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
         debug_assert!(self.segment.contains(pf_addr));
 
+        if self.mapping_options.contains(MappingOptions::IMAGE_SPARSE) {
+            if error_code & 3 != 0 {
+                return Err(moto_rt::E_INVALID_ARGUMENT);
+            }
+            let options = self
+                .mapping_options
+                .difference(MappingOptions::IMAGE_SPARSE)
+                | MappingOptions::DONT_ZERO;
+            let first = ((pf_addr - self.segment.start) / PAGE_SIZE_SMALL) & !15;
+            let end = (first + 16).min(self.segment.size / PAGE_SIZE_SMALL);
+            for index in first..end {
+                let addr = self.segment.start + index * PAGE_SIZE_SMALL;
+                if self.find_page(addr).is_some() {
+                    continue;
+                }
+                let (frame, _) = self.image_page(addr).ok_or(moto_rt::E_INVALID_ARGUMENT)?;
+                self.map_frame(addr, frame, options)?;
+            }
+            return Ok(());
+        }
+
         // Note: this is run under spinlock on self.
 
         if (((pf_addr & !(PAGE_SIZE_SMALL - 1)) == self.segment.start)
@@ -670,6 +726,29 @@ impl VmemSegment {
         if start + other.segment.size > self.segment.end() {
             return Err(moto_rt::E_INVALID_ARGUMENT);
         }
+        if other.mapping_options.contains(MappingOptions::IMAGE_SPARSE) {
+            let mut image = self.image.lock(line!());
+            if image.is_none() {
+                let mut frames = Vec::new();
+                frames
+                    .try_reserve_exact((self.segment.size / PAGE_SIZE_SMALL) as usize)
+                    .map_err(|_| moto_rt::E_OUT_OF_MEMORY)?;
+                for page in self.pages.iter() {
+                    let frame = page.frame.get().ok_or(moto_rt::E_INVALID_ARGUMENT)?;
+                    if frame.kind() != PageType::SmallPage || frame.is_mmio() {
+                        return Err(moto_rt::E_INVALID_ARGUMENT);
+                    }
+                    frames.push(page.frame.clone());
+                }
+                if frames.len() as u64 * PAGE_SIZE_SMALL != self.segment.size {
+                    return Err(moto_rt::E_INVALID_ARGUMENT);
+                }
+                *image = Some(Arc::new(frames));
+            }
+            *other.image.lock(line!()) = image.clone();
+            other.image_offset = self.image_offset + first_page as usize;
+            return Ok(());
+        }
         // Segment provenance decides, whatever the actual backing: a huge
         // page must never reach the small-page replacement loop below.
         if (self.mapping_options | other.mapping_options).contains(MappingOptions::HUGE_ELIGIBLE) {
@@ -758,11 +837,10 @@ impl SegmentNode {
 }
 
 const SEGMENT_NODE_SZ: usize = core::mem::size_of::<SegmentNode>();
-const _SEGMENT_NODE_SZ: () = assert!(core::mem::size_of::<SegmentNode>() == 72);
+// Scratch image backing extends the descriptor; packing follows its actual size.
 
 const SEGMENT_NODES_IN_SMALL_PAGE: usize =
     ((PAGE_SIZE_SMALL as usize) - STRUCT_PAGE_SZ) / SEGMENT_NODE_SZ; // == 55.
-const _SEGMENT_NODES_IN_SMALL_PAGE: () = assert!(SEGMENT_NODES_IN_SMALL_PAGE == 55);
 
 intrusive_adapter!(SegmentListAdapter = UnsafeRef<SegmentNode>: SegmentNode { free_list_link: SinglyLinkedListLink });
 intrusive_adapter!(pub(super) SegmentTreeAdapter = UnsafeRef<SegmentNode>: SegmentNode { tree_link: RBTreeLink });
diff --git a/src/sys/kernel/src/uspace/sys_mem.rs b/src/sys/kernel/src/uspace/sys_mem.rs
index 76e044e..2a4bbfc 100644
--- a/src/sys/kernel/src/uspace/sys_mem.rs
+++ b/src/sys/kernel/src/uspace/sys_mem.rs
@@ -238,6 +238,13 @@ fn sys_map(
         // (the vdso's text and read-only data).
         let mut flags = flags & !SysMem::F_SHARE_SELF;
         let mut opts = MappingOptions::USER_ACCESSIBLE;
+        if flags & 0x100 != 0 {
+            if phys_addr == u64::MAX {
+                return ResultBuilder::invalid_argument();
+            }
+            opts |= MappingOptions::IMAGE_SPARSE;
+            flags &= !0x100;
+        }
         if (flags & SysMem::F_READABLE) != 0 {
             opts |= MappingOptions::READABLE;
             flags &= !SysMem::F_READABLE;
diff --git a/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs b/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs
index 613e4f8..a931b80 100644
--- a/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs
+++ b/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs
@@ -26,7 +26,7 @@ impl Drop for Image {
 
 static IMAGE: moto_rt::mutex::Mutex<Option<Image>> = moto_rt::mutex::Mutex::new(None);
 
-pub(super) fn load(fd: RtFd, size: u64, child: SysHandle) -> Result<u64, ErrorCode> {
+pub(super) fn load(fd: RtFd, size: u64, child: SysHandle, sparse: bool) -> Result<u64, ErrorCode> {
     let attr = moto_rt::fs::get_file_attr(fd)?;
     let identity = (attr.entry_id, attr.modified, size);
     let mut cache = IMAGE.lock();
@@ -77,7 +77,7 @@ pub(super) fn load(fd: RtFd, size: u64, child: SysHandle) -> Result<u64, ErrorCo
         if seg.flags & SysMem::F_WRITABLE == 0 {
             SysMem::map(
                 child,
-                seg.flags,
+                seg.flags | if sparse { 0x100 } else { 0 },
                 seg.local,
                 seg.remote,
                 PAGE_SIZE_SMALL,
diff --git a/src/sys/lib/rt.vdso/src/rt_process.rs b/src/sys/lib/rt.vdso/src/rt_process.rs
index 6ffb396..6f1d05a 100644
--- a/src/sys/lib/rt.vdso/src/rt_process.rs
+++ b/src/sys/lib/rt.vdso/src/rt_process.rs
@@ -673,7 +673,12 @@ fn run_elf(
         &full_url,
     )?);
     let load_result = if cached {
-        spawn_cache::load(fd, file_sz, address_space.syshandle())
+        spawn_cache::load(
+            fd,
+            file_sz,
+            address_space.syshandle(),
+            prototype == b"cache-sparse",
+        )
     } else {
         load_binary(buf, address_space.syshandle())
     }
````

### 03-vdso-templates.patch

````diff
diff --git a/src/sys/kernel/src/mm/virt.rs b/src/sys/kernel/src/mm/virt.rs
index db4a949..b28ec85 100644
--- a/src/sys/kernel/src/mm/virt.rs
+++ b/src/sys/kernel/src/mm/virt.rs
@@ -1159,7 +1159,11 @@ impl UserAddressSpaceBase {
     }
 
     pub(super) fn fix_pagefault(&self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
-        self.normal_memory.fix_pagefault(pf_addr, error_code)
+        if self.custom_memory.segment.contains(pf_addr) {
+            self.custom_memory.fix_pagefault(pf_addr, error_code)
+        } else {
+            self.normal_memory.fix_pagefault(pf_addr, error_code)
+        }
     }
 
     /// Maps the kernel-static pages starting at `kernel_vaddr` into the
diff --git a/src/sys/lib/rt.vdso/src/load.rs b/src/sys/lib/rt.vdso/src/load.rs
index 7cba7a8..3d9f83e 100644
--- a/src/sys/lib/rt.vdso/src/load.rs
+++ b/src/sys/lib/rt.vdso/src/load.rs
@@ -12,13 +12,17 @@ pub fn load_vdso(address_space: u64) -> ErrorCode {
         Err(err) => return err,
     };
 
-    match init_remote_vdso(address_space, entry_point) {
+    match init_remote_vdso(address_space, entry_point, false) {
         Ok(()) => moto_rt::E_OK,
         Err(err) => err,
     }
 }
 
-fn init_remote_vdso(address_space: SysHandle, entry_point: u64) -> Result<(), ErrorCode> {
+fn init_remote_vdso(
+    address_space: SysHandle,
+    entry_point: u64,
+    sparse: bool,
+) -> Result<(), ErrorCode> {
     // The vdso bytes: a child needs them to load the vdso into its own
     // children, and every process holds the same bytes at the same address,
     // so share ours read-only instead of copying.
@@ -28,7 +32,7 @@ fn init_remote_vdso(address_space: SysHandle, entry_point: u64) -> Result<(), Er
     let num_pages = (vdso_bytes_sz + sys_mem::PAGE_SIZE_SMALL - 1) >> sys_mem::PAGE_SIZE_SMALL_LOG2;
     let remote = SysMem::map(
         address_space,
-        SysMem::F_SHARE_SELF | SysMem::F_READABLE,
+        SysMem::F_SHARE_SELF | SysMem::F_READABLE | if sparse { 0x100 } else { 0 },
         moto_rt::RT_VDSO_BYTES_ADDR,
         moto_rt::RT_VDSO_BYTES_ADDR,
         sys_mem::PAGE_SIZE_SMALL,
@@ -66,6 +70,10 @@ fn init_remote_vdso(address_space: SysHandle, entry_point: u64) -> Result<(), Er
 
 // On success, return the _vdso_entry.
 fn load_binary(address_space: SysHandle) -> Result<u64, ErrorCode> {
+    build_binary(address_space).map(|(entry, _)| entry)
+}
+
+fn build_binary(address_space: SysHandle) -> Result<(u64, RemoteLoader), ErrorCode> {
     let vdso_bytes = unsafe {
         core::slice::from_raw_parts(
             moto_rt::RT_VDSO_BYTES_ADDR as usize as *const u8,
@@ -95,13 +103,74 @@ fn load_binary(address_space: SysHandle) -> Result<u64, ErrorCode> {
         offset: moto_rt::RT_VDSO_START,
         mapped_regions: BTreeMap::default(),
         shared_regions: BTreeMap::default(),
+        shared_flags: BTreeMap::default(),
     };
 
     if elf_binary.load(&mut elf_loader).is_err() {
         return Err(moto_rt::E_INVALID_ARGUMENT);
     };
 
-    Ok(elf_binary.entry_point() + moto_rt::RT_VDSO_START)
+    Ok((
+        elf_binary.entry_point() + moto_rt::RT_VDSO_START,
+        elf_loader,
+    ))
+}
+
+// Scratch experiment: keep pristine, already-relocated writable data, never
+// copy the live runtime's mutable data into a child.
+static PREPARED: moto_rt::mutex::Mutex<Option<(u64, RemoteLoader)>> =
+    moto_rt::mutex::Mutex::new(None);
+
+pub fn load_vdso_prepared(address_space: u64, sparse: bool) -> ErrorCode {
+    let result = (|| {
+        let address_space = SysHandle::from_u64(address_space);
+        let mut prepared = PREPARED.lock();
+        if prepared.is_none() {
+            let space = moto_sys::syscalls::RaiiHandle::from(moto_sys::SysObj::create(
+                SysHandle::NONE,
+                0,
+                "address_space:debug_name=vdso-template",
+            )?);
+            *prepared = Some(build_binary(space.syshandle())?);
+        }
+        let (entry, image) = prepared.as_ref().unwrap();
+        for (&base, &pages) in &image.shared_regions {
+            let remote = base + image.offset;
+            SysMem::map(
+                address_space,
+                image.shared_flags[&base]
+                    | if sparse && image.shared_flags[&base] & SysMem::F_EXECUTABLE != 0 {
+                        0x100
+                    } else {
+                        0
+                    },
+                remote,
+                remote,
+                sys_mem::PAGE_SIZE_SMALL,
+                pages,
+            )?;
+        }
+        for (&base, &(source, pages)) in &image.mapped_regions {
+            let (_, local) = SysMem::map2(
+                address_space,
+                SysMem::F_SHARE_SELF | SysMem::F_READABLE | SysMem::F_WRITABLE,
+                u64::MAX,
+                base + image.offset,
+                sys_mem::PAGE_SIZE_SMALL,
+                pages,
+            )?;
+            unsafe {
+                core::ptr::copy_nonoverlapping(
+                    source as *const u8,
+                    local as *mut u8,
+                    (pages * sys_mem::PAGE_SIZE_SMALL) as usize,
+                );
+            }
+            SysMem::free(local).unwrap();
+        }
+        init_remote_vdso(address_space, *entry, sparse)
+    })();
+    result.err().unwrap_or(moto_rt::E_OK)
 }
 
 struct RemoteLoader {
@@ -114,6 +183,7 @@ struct RemoteLoader {
     // Segments mapped from this process's own vdso instead of copied:
     // unoffset vaddr -> num_pages. Nothing is ever written to these.
     shared_regions: BTreeMap<u64, u64>,
+    shared_flags: BTreeMap<u64, u32>,
 }
 
 impl RemoteLoader {
@@ -192,6 +262,7 @@ impl elfloader::ElfLoader for RemoteLoader {
                 .map_err(|_| elfloader::ElfLoaderErr::OutOfMemory)?;
                 assert_eq!(remote, remote_start);
                 self.shared_regions.insert(vaddr_start, num_pages);
+                self.shared_flags.insert(vaddr_start, flags);
                 continue;
             }
 
diff --git a/src/sys/lib/rt.vdso/src/rt_process.rs b/src/sys/lib/rt.vdso/src/rt_process.rs
index 6f1d05a..b75d3de 100644
--- a/src/sys/lib/rt.vdso/src/rt_process.rs
+++ b/src/sys/lib/rt.vdso/src/rt_process.rs
@@ -677,7 +677,7 @@ fn run_elf(
             fd,
             file_sz,
             address_space.syshandle(),
-            prototype == b"cache-sparse",
+            prototype.starts_with(b"cache-sparse"),
         )
     } else {
         load_binary(buf, address_space.syshandle())
@@ -689,7 +689,14 @@ fn run_elf(
             buf.len()
         )
     })?;
-    let res = crate::load::load_vdso(address_space.syshandle().as_u64());
+    let res = if prototype.ends_with(b"vdso") || prototype.ends_with(b"vdso-sparse") {
+        crate::load::load_vdso_prepared(
+            address_space.syshandle().as_u64(),
+            prototype.ends_with(b"vdso-sparse"),
+        )
+    } else {
+        crate::load::load_vdso(address_space.syshandle().as_u64())
+    };
     if res != moto_rt::E_OK {
         log::warn!("Spawn '{exe}': VDSO error: {res}.");
         return Err(res);
````

### 04-learned-pages.patch

````diff
diff --git a/src/sys/kernel/src/mm/mod.rs b/src/sys/kernel/src/mm/mod.rs
index b51682a..fb2df2f 100644
--- a/src/sys/kernel/src/mm/mod.rs
+++ b/src/sys/kernel/src/mm/mod.rs
@@ -287,6 +287,7 @@ bitflags! {
         // 2 MiB-aligned placement and huge candidates for its mapping.
         const HUGE_ELIGIBLE   = 512;
         const IMAGE_SPARSE    = 1024; // Scratch prepared-image experiment.
+        const IMAGE_WARM      = 2048;
     }
 }
 
diff --git a/src/sys/kernel/src/mm/virt_intrusive.rs b/src/sys/kernel/src/mm/virt_intrusive.rs
index cf2119c..093eed4 100644
--- a/src/sys/kernel/src/mm/virt_intrusive.rs
+++ b/src/sys/kernel/src/mm/virt_intrusive.rs
@@ -12,7 +12,7 @@ use moto_sys::ErrorCode;
 
 use crate::mm::{PageType, PAGE_SIZE_MID, PAGE_SIZE_SMALL_LOG2};
 use crate::util::SpinLock;
-use core::sync::atomic::Ordering;
+use core::sync::atomic::{AtomicU64, Ordering};
 
 use super::phys::Frame;
 use super::slab::SlabArc;
@@ -255,13 +255,18 @@ impl PageAllocator {
     }
 }
 
+struct ImageBacking {
+    frames: Vec<SlabArc<Frame>>,
+    hot: Vec<AtomicU64>, // One bit per 16-page window, learned on faults.
+}
+
 #[derive(Default)]
 pub(super) struct VmemSegment {
     segment: super::MemorySegment,
     pages: RBTree<PageTreeAdapter>,
     owner: crate::util::UnsafeRef<super::virt::VmemRegion>,
     mapping_options: MappingOptions,
-    image: SpinLock<Option<Arc<Vec<SlabArc<Frame>>>>>,
+    image: SpinLock<Option<Arc<ImageBacking>>>,
     image_offset: usize,
 }
 
@@ -362,11 +367,28 @@ impl VmemSegment {
         let index = ((addr - self.segment.start) / PAGE_SIZE_SMALL) as usize + self.image_offset;
         let image = self.image.lock(line!());
         Some((
-            image.as_ref()?.get(index)?.clone(),
+            image.as_ref()?.frames.get(index)?.clone(),
             addr & (PAGE_SIZE_SMALL - 1),
         ))
     }
 
+    fn map_image_window(&mut self, first: u64) -> Result<(), ErrorCode> {
+        let options = self
+            .mapping_options
+            .difference(MappingOptions::IMAGE_SPARSE | MappingOptions::IMAGE_WARM)
+            | MappingOptions::DONT_ZERO;
+        let end = (first + 16).min(self.segment.size / PAGE_SIZE_SMALL);
+        for index in first..end {
+            let addr = self.segment.start + index * PAGE_SIZE_SMALL;
+            if self.find_page(addr).is_some() {
+                continue;
+            }
+            let (frame, _) = self.image_page(addr).ok_or(moto_rt::E_INVALID_ARGUMENT)?;
+            self.map_frame(addr, frame, options)?;
+        }
+        Ok(())
+    }
+
     pub(super) fn unmap(mut self) -> u64 {
         // Note: it is important to unmap pages before freeing the segment
         // in the VMemRegion, otherwise a concurrent allocation may try
@@ -596,20 +618,11 @@ impl VmemSegment {
             if error_code & 3 != 0 {
                 return Err(moto_rt::E_INVALID_ARGUMENT);
             }
-            let options = self
-                .mapping_options
-                .difference(MappingOptions::IMAGE_SPARSE)
-                | MappingOptions::DONT_ZERO;
             let first = ((pf_addr - self.segment.start) / PAGE_SIZE_SMALL) & !15;
-            let end = (first + 16).min(self.segment.size / PAGE_SIZE_SMALL);
-            for index in first..end {
-                let addr = self.segment.start + index * PAGE_SIZE_SMALL;
-                if self.find_page(addr).is_some() {
-                    continue;
-                }
-                let (frame, _) = self.image_page(addr).ok_or(moto_rt::E_INVALID_ARGUMENT)?;
-                self.map_frame(addr, frame, options)?;
-            }
+            self.map_image_window(first)?;
+            let window = (self.image_offset as u64 + first) / 16;
+            self.image.lock(line!()).as_ref().unwrap().hot[(window / 64) as usize]
+                .fetch_or(1 << (window % 64), Ordering::Relaxed);
             return Ok(());
         }
 
@@ -743,10 +756,30 @@ impl VmemSegment {
                 if frames.len() as u64 * PAGE_SIZE_SMALL != self.segment.size {
                     return Err(moto_rt::E_INVALID_ARGUMENT);
                 }
-                *image = Some(Arc::new(frames));
+                let hot = (0..frames.len().div_ceil(1024))
+                    .map(|_| AtomicU64::new(0))
+                    .collect();
+                *image = Some(Arc::new(ImageBacking { frames, hot }));
             }
             *other.image.lock(line!()) = image.clone();
             other.image_offset = self.image_offset + first_page as usize;
+            if mapping_options.contains(MappingOptions::IMAGE_WARM) {
+                let backing = image.as_ref().unwrap().clone();
+                drop(image);
+                for (word, bits) in backing.hot.iter().enumerate() {
+                    let mut bits = bits.load(Ordering::Relaxed);
+                    while bits != 0 {
+                        let first = (word as u64 * 64 + bits.trailing_zeros() as u64) * 16;
+                        bits &= bits - 1;
+                        if first >= other.image_offset as u64
+                            && first
+                                < other.image_offset as u64 + other.segment.size / PAGE_SIZE_SMALL
+                        {
+                            other.map_image_window(first - other.image_offset as u64)?;
+                        }
+                    }
+                }
+            }
             return Ok(());
         }
         // Segment provenance decides, whatever the actual backing: a huge
diff --git a/src/sys/kernel/src/uspace/sys_mem.rs b/src/sys/kernel/src/uspace/sys_mem.rs
index 2a4bbfc..03e84a1 100644
--- a/src/sys/kernel/src/uspace/sys_mem.rs
+++ b/src/sys/kernel/src/uspace/sys_mem.rs
@@ -238,6 +238,13 @@ fn sys_map(
         // (the vdso's text and read-only data).
         let mut flags = flags & !SysMem::F_SHARE_SELF;
         let mut opts = MappingOptions::USER_ACCESSIBLE;
+        if flags & 0x200 != 0 {
+            if flags & 0x100 == 0 {
+                return ResultBuilder::invalid_argument();
+            }
+            opts |= MappingOptions::IMAGE_WARM;
+            flags &= !0x200;
+        }
         if flags & 0x100 != 0 {
             if phys_addr == u64::MAX {
                 return ResultBuilder::invalid_argument();
diff --git a/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs b/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs
index a931b80..d31450c 100644
--- a/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs
+++ b/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs
@@ -26,7 +26,13 @@ impl Drop for Image {
 
 static IMAGE: moto_rt::mutex::Mutex<Option<Image>> = moto_rt::mutex::Mutex::new(None);
 
-pub(super) fn load(fd: RtFd, size: u64, child: SysHandle, sparse: bool) -> Result<u64, ErrorCode> {
+pub(super) fn load(
+    fd: RtFd,
+    size: u64,
+    child: SysHandle,
+    sparse: bool,
+    hot: bool,
+) -> Result<u64, ErrorCode> {
     let attr = moto_rt::fs::get_file_attr(fd)?;
     let identity = (attr.entry_id, attr.modified, size);
     let mut cache = IMAGE.lock();
@@ -77,7 +83,7 @@ pub(super) fn load(fd: RtFd, size: u64, child: SysHandle, sparse: bool) -> Resul
         if seg.flags & SysMem::F_WRITABLE == 0 {
             SysMem::map(
                 child,
-                seg.flags | if sparse { 0x100 } else { 0 },
+                seg.flags | if sparse { 0x100 } else { 0 } | if hot { 0x200 } else { 0 },
                 seg.local,
                 seg.remote,
                 PAGE_SIZE_SMALL,
diff --git a/src/sys/lib/rt.vdso/src/rt_process.rs b/src/sys/lib/rt.vdso/src/rt_process.rs
index b75d3de..5cc6a17 100644
--- a/src/sys/lib/rt.vdso/src/rt_process.rs
+++ b/src/sys/lib/rt.vdso/src/rt_process.rs
@@ -678,6 +678,7 @@ fn run_elf(
             file_sz,
             address_space.syshandle(),
             prototype.starts_with(b"cache-sparse"),
+            prototype == b"cache-sparse-hot-vdso",
         )
     } else {
         load_binary(buf, address_space.syshandle())
````

### 05-batched-teardown.patch

````diff
diff --git a/src/sys/kernel/src/arch/x64/paging.rs b/src/sys/kernel/src/arch/x64/paging.rs
index ed3cf35..f733bd5 100644
--- a/src/sys/kernel/src/arch/x64/paging.rs
+++ b/src/sys/kernel/src/arch/x64/paging.rs
@@ -385,7 +385,14 @@ impl PageTableImpl {
 
     // With `flush: false` the caller must flush the TLB (e.g. via
     // `flush_pages`) before the unmapped physical frame is freed/reused.
-    fn unmap_page(&mut self, phys_addr: u64, virt_addr: u64, kind: PageType, flush: bool) {
+    fn unmap_page(
+        &mut self,
+        phys_addr: u64,
+        virt_addr: u64,
+        kind: PageType,
+        flush: bool,
+        prune: bool,
+    ) {
         assert_eq!(0, phys_addr & (kind.page_size() - 1));
         assert_eq!(0, virt_addr & (kind.page_size() - 1));
 
@@ -401,7 +408,7 @@ impl PageTableImpl {
         if kind == PageType::LargePage {
             assert!(pte_l3.is_huge_page());
             table_l3.set(idx_l3, PTE::empty());
-            if table_l3.is_empty() {
+            if prune && table_l3.is_empty() {
                 self.table_l4.set(idx_l4, PTE::empty());
                 phys_deallocate_frameless(table_l3.self_phys_addr(), PageType::SmallPage);
             }
@@ -420,7 +427,7 @@ impl PageTableImpl {
         if kind == PageType::MidPage {
             assert!(pte_l2.is_huge_page());
             table_l2.set(idx_l2, PTE::empty());
-            if table_l2.is_empty() {
+            if prune && table_l2.is_empty() {
                 table_l3.set(idx_l3, PTE::empty());
                 phys_deallocate_frameless(table_l2.self_phys_addr(), PageType::SmallPage);
                 if table_l3.is_empty() {
@@ -441,7 +448,7 @@ impl PageTableImpl {
         let idx_l1 = PageTableImpl::idx_l1(virt_addr);
         assert!(!table_l1.get(idx_l1).is_empty());
         table_l1.set(idx_l1, PTE::empty());
-        if table_l1.is_empty() {
+        if prune && table_l1.is_empty() {
             table_l2.set(idx_l2, PTE::empty());
             phys_deallocate_frameless(table_l1.self_phys_addr(), PageType::SmallPage);
             if table_l2.is_empty() {
@@ -458,6 +465,43 @@ impl PageTableImpl {
         }
     }
 
+    // Scratch batched teardown: inspect a leaf table once after all of the
+    // segment's PTEs have been removed, rather than after each 4 KiB page.
+    fn prune_range(&mut self, start: u64, end: u64) {
+        let mut addr = start & !(PAGE_SIZE_MID - 1);
+        while addr < end {
+            let l4 = Self::idx_l4(addr);
+            let l3 = Self::idx_l3(addr);
+            let l2 = Self::idx_l2(addr);
+            addr += PAGE_SIZE_MID;
+            let p4 = self.table_l4.get(l4);
+            if !p4.is_present() {
+                continue;
+            }
+            let t3 = HwPageTable::from_pte(p4);
+            let p3 = t3.get(l3);
+            if p3.is_present() && !p3.is_huge_page() {
+                let t2 = HwPageTable::from_pte(p3);
+                let p2 = t2.get(l2);
+                if p2.is_present() && !p2.is_huge_page() {
+                    let t1 = HwPageTable::from_pte(p2);
+                    if t1.is_empty() {
+                        t2.set(l2, PTE::empty());
+                        phys_deallocate_frameless(t1.self_phys_addr(), PageType::SmallPage);
+                    }
+                }
+                if t2.is_empty() {
+                    t3.set(l3, PTE::empty());
+                    phys_deallocate_frameless(t2.self_phys_addr(), PageType::SmallPage);
+                }
+            }
+            if t3.is_empty() {
+                self.table_l4.set(l4, PTE::empty());
+                phys_deallocate_frameless(t3.self_phys_addr(), PageType::SmallPage);
+            }
+        }
+    }
+
     fn is_readable(&self, virt_addr: u64) -> bool {
         let idx_l4 = PageTableImpl::idx_l4(virt_addr);
         let pte_l4 = self.table_l4.get(idx_l4);
@@ -847,7 +891,7 @@ impl PageTable {
             self.inst
                 .get()
                 .lock(4)
-                .unmap_page(phys_addr, virt_addr, kind, true);
+                .unmap_page(phys_addr, virt_addr, kind, true, true);
         }
     }
 
@@ -859,7 +903,13 @@ impl PageTable {
             self.inst
                 .get()
                 .lock(line!())
-                .unmap_page(phys_addr, virt_addr, kind, false);
+                .unmap_page(phys_addr, virt_addr, kind, false, false);
+        }
+    }
+
+    pub fn prune_unmapped_range(&self, start: u64, end: u64) {
+        unsafe {
+            self.inst.get().lock(line!()).prune_range(start, end);
         }
     }
 
diff --git a/src/sys/kernel/src/mm/virt_intrusive.rs b/src/sys/kernel/src/mm/virt_intrusive.rs
index 093eed4..3f690b2 100644
--- a/src/sys/kernel/src/mm/virt_intrusive.rs
+++ b/src/sys/kernel/src/mm/virt_intrusive.rs
@@ -415,6 +415,9 @@ impl VmemSegment {
             }
         }
         if mapped_pages > 0 {
+            self.address_space()
+                .page_table
+                .prune_unmapped_range(self.segment.start, self.segment.end());
             self.address_space().page_table.flush_pages(
                 self.segment.start,
                 self.segment.size >> PAGE_SIZE_SMALL_LOG2,
````

### 06-family-cache.patch

````diff
diff --git a/src/sys/kernel/src/uspace/sys_mem/image_cache.rs b/src/sys/kernel/src/uspace/sys_mem/image_cache.rs
new file mode 100644
index 0000000..4fccf63
--- /dev/null
+++ b/src/sys/kernel/src/uspace/sys_mem/image_cache.rs
@@ -0,0 +1,145 @@
+//! Scratch, one-image cache for an explicitly participating process family.
+//! Only its original publisher may replace it. Not a filesystem cache API.
+use super::*;
+use crate::util::SpinLock;
+use alloc::sync::{Arc, Weak};
+use alloc::vec::Vec;
+
+struct Image {
+    key: Vec<u8>,
+    source: Arc<UserAddressSpace>,
+    entry: u64,
+    segments: Vec<[u64; 3]>, // Address, pages, SysMem flags.
+}
+
+static CACHE: SpinLock<(Weak<super::super::process::Process>, Option<Arc<Image>>)> =
+    SpinLock::new((Weak::new(), None));
+
+pub(super) fn run(
+    thread: &super::super::process::Thread,
+    space: Arc<UserAddressSpace>,
+    args: &SyscallArgs,
+) -> SyscallResult {
+    match run_impl(thread, space, args) {
+        Ok(entry) => ResultBuilder::ok_1(entry),
+        Err(err) => ResultBuilder::result(err),
+    }
+}
+
+fn run_impl(
+    thread: &super::super::process::Thread,
+    space: Arc<UserAddressSpace>,
+    args: &SyscallArgs,
+) -> Result<u64, ErrorCode> {
+    let caller = thread.owner();
+    let key = caller.address_space().read_from_user(args.args[1], 40)?;
+    let mut cache = CACHE.lock(line!());
+    let owner = if let Some(owner) = cache.0.upgrade() {
+        owner
+    } else {
+        cache.0 = Arc::downgrade(&caller);
+        cache.1 = None;
+        caller.clone()
+    };
+    let mut ancestor = Some(thread.process_stats.clone());
+    let mut allowed = false;
+    while let Some(stats) = ancestor {
+        if stats.pid() == owner.pid() {
+            allowed = true;
+            break;
+        }
+        ancestor = stats.parent();
+    }
+    if !allowed
+        || moto_sys::caps::ProcessRole::from_caps(caller.capabilities())
+            != moto_sys::caps::ProcessRole::from_caps(owner.capabilities())
+    {
+        return Err(moto_rt::E_NOT_ALLOWED);
+    }
+    if args.flags == 1 {
+        if caller.pid() != owner.pid() || args.args[3] == 0 || args.args[3] > 16 {
+            return Err(moto_rt::E_NOT_ALLOWED);
+        }
+        let bytes = caller
+            .address_space()
+            .read_from_user(args.args[2], args.args[3] * 24)?;
+        let mut segments = Vec::new();
+        for record in bytes.as_chunks::<24>().0 {
+            let words = core::array::from_fn(|i| {
+                u64::from_le_bytes(record[i * 8..i * 8 + 8].try_into().unwrap())
+            });
+            let [start, pages, flags] = words;
+            if start & 4095 != 0
+                || pages == 0
+                || pages > 65536
+                || flags & !0x93 != 0
+                || flags & 1 == 0
+                || flags & 0x82 == 0x82
+            {
+                return Err(moto_rt::E_INVALID_ARGUMENT);
+            }
+            segments.push(words);
+        }
+        cache.1 = Some(Arc::new(Image {
+            key,
+            source: space,
+            entry: args.args[4],
+            segments,
+        }));
+        return Ok(args.args[4]);
+    }
+    if args.flags != 0 {
+        return Err(moto_rt::E_INVALID_ARGUMENT);
+    }
+    if core::ptr::eq(space.as_ref(), caller.address_space().as_ref()) {
+        return Err(moto_rt::E_NOT_ALLOWED);
+    }
+    let image = cache
+        .1
+        .as_ref()
+        .filter(|image| image.key == key)
+        .cloned()
+        .ok_or(moto_rt::E_NOT_FOUND)?;
+    drop(cache);
+
+    // Keep the existing mapping budget checks; the experiment only handles
+    // resident source bytes and makes no deferred OOM guarantee.
+    let pages: u64 = image.segments.iter().map(|s| s[1]).sum();
+    let _admission = crate::mm::admission::admit(
+        space.mem_class(),
+        crate::mm::admission::mapping_charge(pages, pages * 2),
+    )?;
+    for &[start, pages, flags] in &image.segments {
+        let mut options = MappingOptions::READABLE | MappingOptions::USER_ACCESSIBLE;
+        if flags & SysMem::F_WRITABLE as u64 == 0 {
+            options |= MappingOptions::IMAGE_SPARSE | MappingOptions::IMAGE_WARM;
+            if flags & SysMem::F_EXECUTABLE as u64 != 0 {
+                options |= MappingOptions::EXECUTABLE;
+            }
+            space.share_from(&image.source, start, start, pages, options)?;
+        } else {
+            options |= MappingOptions::WRITABLE;
+            let (_, local) =
+                space.alloc_user_shared(start, pages, options, caller.address_space())?;
+            let result = (|| {
+                for index in 0..pages {
+                    let src = image.source.get_user_page_as_kernel(start + index * 4096)?;
+                    let dst = caller
+                        .address_space()
+                        .get_user_page_as_kernel(local + index * 4096)?;
+                    unsafe {
+                        core::ptr::copy_nonoverlapping(
+                            src.kernel_addr() as *const u8,
+                            dst.kernel_addr() as *mut u8,
+                            4096,
+                        );
+                    }
+                }
+                Ok::<_, ErrorCode>(())
+            })();
+            caller.address_space().unmap(local)?;
+            result?;
+        }
+    }
+    Ok(image.entry)
+}
diff --git a/src/sys/kernel/src/uspace/sys_mem.rs b/src/sys/kernel/src/uspace/sys_mem.rs
index 03e84a1..2717613 100644
--- a/src/sys/kernel/src/uspace/sys_mem.rs
+++ b/src/sys/kernel/src/uspace/sys_mem.rs
@@ -6,6 +6,8 @@ use crate::mm::MappingOptions;
 
 use super::syscall::*;
 
+mod image_cache;
+
 fn sys_mmio_map(
     address_space: &UserAddressSpace,
     phys_addr: u64,
@@ -514,6 +516,7 @@ pub fn sys_mem_impl(thread: &super::process::Thread, args: &SyscallArgs) -> Sysc
     };
 
     match args.operation {
+        5 => image_cache::run(thread, address_space, args),
         SysMem::OP_MAP => {
             if args.args[5] != 0 {
                 return ResultBuilder::invalid_argument();
diff --git a/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs b/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs
index d31450c..9c7272f 100644
--- a/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs
+++ b/src/sys/lib/rt.vdso/src/rt_process/spawn_cache.rs
@@ -32,8 +32,23 @@ pub(super) fn load(
     child: SysHandle,
     sparse: bool,
     hot: bool,
+    family: bool,
 ) -> Result<u64, ErrorCode> {
     let attr = moto_rt::fs::get_file_attr(fd)?;
+    let key = [
+        attr.entry_id as u64,
+        (attr.entry_id >> 64) as u64,
+        attr.modified as u64,
+        (attr.modified >> 64) as u64,
+        size,
+    ];
+    if family {
+        match family_call(child, 0, &key, &[], 0) {
+            Ok(entry) => return Ok(entry),
+            Err(moto_rt::E_NOT_FOUND | moto_rt::E_NOT_ALLOWED) => {}
+            Err(err) => return Err(err),
+        }
+    }
     let identity = (attr.entry_id, attr.modified, size);
     let mut cache = IMAGE.lock();
     if cache
@@ -72,12 +87,31 @@ pub(super) fn load(
             });
         }
         loader.retain = true;
+        if family && size >= 50 * 1024 * 1024 {
+            let recipe: Vec<_> = segments
+                .iter()
+                .map(|s| [s.remote, s.pages, s.flags as u64])
+                .collect();
+            let published = family_call(space.syshandle(), 1, &key, &recipe, elf.entry_point());
+            match published {
+                Ok(_) => {}
+                Err(moto_rt::E_NOT_ALLOWED) => {}
+                Err(err) => return Err(err),
+            }
+        }
         *cache = Some(Image {
             identity,
             entry: elf.entry_point(),
             segments,
         });
     }
+    if family && size >= 50 * 1024 * 1024 {
+        match family_call(child, 0, &key, &[], 0) {
+            Ok(entry) => return Ok(entry),
+            Err(moto_rt::E_NOT_FOUND | moto_rt::E_NOT_ALLOWED) => {}
+            Err(err) => return Err(err),
+        }
+    }
     let image = cache.as_ref().unwrap();
     for seg in &image.segments {
         if seg.flags & SysMem::F_WRITABLE == 0 {
@@ -110,3 +144,27 @@ pub(super) fn load(
     }
     Ok(image.entry)
 }
+
+fn family_call(
+    space: SysHandle,
+    flags: u32,
+    key: &[u64; 5],
+    segments: &[[u64; 3]],
+    entry: u64,
+) -> Result<u64, ErrorCode> {
+    use moto_sys::syscalls::{SYS_MEM, do_syscall};
+    let result = do_syscall(
+        ((SYS_MEM as u64) << 56) | (5 << 48) | ((flags as u64) << 16),
+        space.as_u64(),
+        key.as_ptr() as u64,
+        segments.as_ptr() as u64,
+        segments.len() as u64,
+        entry,
+        0,
+    );
+    if result.is_ok() {
+        Ok(result.data[0])
+    } else {
+        Err(result.error_code())
+    }
+}
diff --git a/src/sys/lib/rt.vdso/src/rt_process.rs b/src/sys/lib/rt.vdso/src/rt_process.rs
index 5cc6a17..029e92f 100644
--- a/src/sys/lib/rt.vdso/src/rt_process.rs
+++ b/src/sys/lib/rt.vdso/src/rt_process.rs
@@ -679,6 +679,7 @@ fn run_elf(
             address_space.syshandle(),
             prototype.starts_with(b"cache-sparse"),
             prototype == b"cache-sparse-hot-vdso",
+            prototype == b"cache-family-vdso",
         )
     } else {
         load_binary(buf, address_space.syshandle())
@@ -726,7 +727,7 @@ fn run_elf(
     let mut no_terminal = false;
     // Find the capability, detached, and stdio launch-only env vars.
     for (k, v) in &mut env {
-        if *k == b"MOTOR_SPAWN_PROTO" {
+        if *k == b"MOTOR_SPAWN_PROTO" && *v != b"cache-family-vdso" {
             *k = b"";
         } else if *k == moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY.as_bytes() {
             *k = "".as_bytes(); // Clear the key: see env::create_remote_env().
````

## Appendix C: harness, drivers, and helpers

### bench.rs (cold harness; the 50-pair rustc variant lacked the final Clang line)

````rust
// Scratch benchmark, cross-built with the repository-selected Rust toolchain.
use std::process::{Command, Stdio};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rounds: usize = args.get(1).map_or(30, |s| s.parse().unwrap());
    let modes: Vec<&str> = args
        .get(2)
        .map_or("eager", String::as_str)
        .split(',')
        .collect();
    let program = args
        .get(3)
        .map_or("/devtools/rust/bin/rustc", String::as_str);
    let child_args: Vec<&str> = if args.len() > 4 {
        args[4..].iter().map(String::as_str).collect()
    } else {
        vec!["--version"]
    };
    assert_eq!(
        rounds, 1,
        "a cold sample must be the first command in a fresh VM"
    );
    assert_eq!(modes.len(), 1);
    assert!(std::env::var_os("SPAWN_BENCH_PREPARE").is_none());
    let mut expected = None;
    println!("mode,round,spawn_us,total_us");
    for round in 0..rounds {
        let order: Vec<_> = if round % 2 == 0 {
            modes.iter().copied().collect()
        } else {
            modes.iter().rev().copied().collect()
        };
        for mode in order {
            let mut command = Command::new(program);
            command.args(&child_args).env("MOTOR_SPAWN_PROTO", mode);
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let start = Instant::now();
            let child = command.spawn().unwrap();
            let spawn = start.elapsed();
            let output = child.wait_with_output().unwrap();
            let total = start.elapsed();
            let expected_output: &[u8] = match program {
                "/devtools/bin/rustc" => b"rustc 1.99.0-dev (b111eff31 2026-09-24) (1.99.0-beta-f47d5bb-motor.dev.2)\n",
                "/devtools/llvm/bin/llvm" => b"clang version 23.1.0-rc1 (https://github.com/moturus/llvm-project.git 7c2a7b21e3dc7be1f0c41d443bc420bcc774b1d4)\nTarget: x86_64-unknown-motor\nThread model: posix\nInstalledDir: /devtools/llvm/bin\nConfiguration file: /devtools/cfg/llvm/x86_64-unknown-motor.cfg\n",
                "/system/bin/rush" => b"",
                _ => panic!("unknown validation workload"),
            };
            assert_eq!(output.stdout, expected_output);
            assert!(output.status.success(), "{mode}: {:?}", output);
            assert!(output.stderr.is_empty(), "{mode}: {:?}", output);
            if let Some(ref bytes) = expected {
                assert_eq!(&output.stdout, bytes);
            } else {
                eprintln!("output: {}", String::from_utf8_lossy(&output.stdout).trim());
                expected = Some(output.stdout);
            }
            println!(
                "{mode},{round},{},{},",
                spawn.as_micros(),
                total.as_micros()
            );
        }
    }
}
````

### run-cold.sh (fresh-VM driver)

````sh
#!/usr/bin/env bash
# Host driver: one measured command per newly booted VM; no warmup/retries.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$repo"
artifacts=$1
mode=$2
label=$3
count=${4:-1}
case "${SPAWN_COLD_WORKLOAD:-rustc}" in
    rustc) child_command='/devtools/bin/rustc --version' ;;
    clang) child_command='/devtools/llvm/bin/llvm clang --version' ;;
    rush) child_command='/system/bin/rush -c exit' ;;
    *) exit 2 ;;
esac
vm=build/spawn-cold/vm
runtime=/tmp/motor-spawn-cold
cp "$artifacts/kloader" "$vm/kloader"
cp "$artifacts/initrd" "$vm/initrd"
vm_pid=
cleanup() {
    if [[ -n "$vm_pid" ]]; then
        curl --silent --show-error --unix-socket "$runtime/chv" -X PUT http://localhost/api/v1/vmm.shutdown
        wait "$vm_pid"
        vm_pid=
    fi
}
trap cleanup EXIT
for ((sample=1; sample<=count; sample++)); do
    prefix="build/spawn-cold/$label-$sample"
    MOTO_IMAGE=flat.qcow2 MOTO_MEMORY_MIB=8192 MOTO_CHV_RUNTIME_DIR="$runtime" \
        taskset -c 0,2,4,6 "$vm/run-chv.sh" > "$prefix-serial.log" 2>&1 &
    vm_pid=$!
    sleep 1
    perf_pid=
    if [[ "${SPAWN_COLD_PERF:-0}" == 1 ]]; then
        perf stat -p "$vm_pid" -e cycles:G,cycles:H,instructions:G,instructions:H,context-switches,page-faults \
            -o "$prefix-perf.txt" -- sleep 0.4 &
        perf_pid=$!
    fi
    if [[ "${SPAWN_COLD_CPU:-0}" == 1 ]]; then python3 docs/plans/spawn-cold-prototype/vm-cpu.py "$vm_pid" > "$prefix-cpu-before.json"; fi
    if [[ "${SPAWN_COLD_COUNTERS:-0}" == 1 ]]; then
        curl --silent --show-error --unix-socket "$runtime/chv" http://localhost/api/v1/vm.counters > "$prefix-counters-before.json"
    fi
    ssh -F /dev/null -p 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile=src/tests/test-known-hosts \
        -i vm_images/release/test.key motor@192.168.4.2 \
        "/user/${SPAWN_COLD_BENCH:-spawn-bench-family} 1 $mode $child_command" \
        > "$prefix.csv" 2> "$prefix.stderr"
    if [[ "${SPAWN_COLD_CPU:-0}" == 1 ]]; then python3 docs/plans/spawn-cold-prototype/vm-cpu.py "$vm_pid" > "$prefix-cpu-after.json"; fi
    if [[ "${SPAWN_COLD_COUNTERS:-0}" == 1 ]]; then
        curl --silent --show-error --unix-socket "$runtime/chv" http://localhost/api/v1/vm.counters > "$prefix-counters-after.json"
    fi
    if [[ -n "$perf_pid" ]]; then wait "$perf_pid"; fi
    # Optional post-measurement drain for asynchronous diagnostic logging.
    if [[ -n "${SPAWN_COLD_LOG_DRAIN:-}" ]]; then sleep "$SPAWN_COLD_LOG_DRAIN"; fi
    cleanup
    cat "$prefix.csv"
done
````

### run-pairs.sh (alternating pair driver)

````sh
#!/usr/bin/env bash
# Alternate order; every driver invocation boots a fresh VM.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$repo"
prototype=$1
mode=$2
label=$3
count=${4:-20}
for ((pair=1; pair<=count; pair++)); do
    printf -v tag '%02d' "$pair"
    if ((pair % 2)); then
        bash docs/plans/spawn-cold-prototype/run-cold.sh build/spawn-cold/baseline eager "$label-base-$tag" 1
        bash docs/plans/spawn-cold-prototype/run-cold.sh "$prototype" "$mode" "$label-proto-$tag" 1
    else
        bash docs/plans/spawn-cold-prototype/run-cold.sh "$prototype" "$mode" "$label-proto-$tag" 1
        bash docs/plans/spawn-cold-prototype/run-cold.sh build/spawn-cold/baseline eager "$label-base-$tag" 1
    fi
done
````

### install-bench.sh (installer)

````sh
#!/usr/bin/env bash
# Install only the benchmark into the isolated image, then shut down.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$repo"
artifacts=${1:?artifacts containing the fsync fix}
label=${2:-install-fixed}
vm=build/spawn-cold/vm
runtime=/tmp/motor-spawn-cold
cp "$artifacts/kloader" "$vm/kloader"
cp "$artifacts/initrd" "$vm/initrd"
vm_pid=
cleanup() {
    if [[ -n "$vm_pid" ]]; then
        curl --silent --show-error --unix-socket "$runtime/chv" -X PUT http://localhost/api/v1/vmm.shutdown
        wait "$vm_pid"
        vm_pid=
    fi
}
trap cleanup EXIT
MOTO_IMAGE=flat.qcow2 MOTO_MEMORY_MIB=8192 MOTO_CHV_RUNTIME_DIR="$runtime" \
    taskset -c 0,2,4,6 "$vm/run-chv.sh" > "build/spawn-cold/$label-serial.log" 2>&1 &
vm_pid=$!
sleep 1
if [[ "${3:-}" == --replace ]]; then
    # The previous install deliberately removed Interactive write permission.
    ssh -F /dev/null -p 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile=src/tests/test-known-hosts \
        -i vm_images/release/test.key motor@192.168.4.2 \
        '/system/bin/chmod rwxrwxr-x /user/spawn-bench-cold /user/spawn-flush-file'
fi
scp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=src/tests/test-known-hosts \
    -i vm_images/release/test.key build/spawn-cold/bench-cold motor@192.168.4.2:/user/spawn-bench-cold
scp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=src/tests/test-known-hosts \
    -i vm_images/release/test.key build/spawn-cold/flush-file motor@192.168.4.2:/user/spawn-flush-file
ssh -F /dev/null -p 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=src/tests/test-known-hosts \
    -i vm_images/release/test.key motor@192.168.4.2 \
    '/system/bin/chmod rwxr-xr-x /user/spawn-bench-cold /user/spawn-flush-file && /user/spawn-flush-file /user/spawn-bench-cold && /system/bin/ls -l /user/spawn-bench-cold'
````

### validate-flush.sh (three-boot durability check)

````sh
#!/usr/bin/env bash
# Verify persisted bytes in a new VM after each synchronization operation.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$repo"
artifacts=${1:?artifacts containing the fsync fix}
label=${2:-flush}
vm=build/spawn-cold/vm
runtime=/tmp/motor-spawn-cold
cp "$artifacts/kloader" "$vm/kloader"
cp "$artifacts/initrd" "$vm/initrd"
ssh_options=(-F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=src/tests/test-known-hosts
    -i vm_images/release/test.key)
vm_pid=
cleanup() {
    if [[ -n "$vm_pid" ]]; then
        curl --silent --show-error --unix-socket "$runtime/chv" -X PUT http://localhost/api/v1/vmm.shutdown
        wait "$vm_pid"
        vm_pid=
    fi
}
trap cleanup EXIT
start_vm() {
    MOTO_IMAGE=flat.qcow2 MOTO_MEMORY_MIB=8192 MOTO_CHV_RUNTIME_DIR="$runtime" \
        taskset -c 0,2,4,6 "$vm/run-chv.sh" > "build/spawn-cold/$label-$1-serial.log" 2>&1 &
    vm_pid=$!
    sleep 1
}
start_vm write-all
scp "${ssh_options[@]}" -P 2222 motor@192.168.4.2:/user/spawn-bench-cold build/spawn-cold/installed-bench-verified
cmp build/spawn-cold/bench-cold build/spawn-cold/installed-bench-verified
ssh "${ssh_options[@]}" -p 2222 motor@192.168.4.2 \
    "/system/bin/ls -l /user/spawn-bench-cold && /user/spawn-flush-file /user/spawn-$label-all write-all"
cleanup
start_vm write-data
ssh "${ssh_options[@]}" -p 2222 motor@192.168.4.2 \
    "/user/spawn-flush-file /user/spawn-$label-all verify && /user/spawn-flush-file /user/spawn-$label-data write-data"
cleanup
start_vm verify-data
ssh "${ssh_options[@]}" -p 2222 motor@192.168.4.2 \
    "/user/spawn-flush-file /user/spawn-$label-all verify && /user/spawn-flush-file /user/spawn-$label-data verify"
cleanup
printf '%s\n' 'PASS: installed benchmark bytes, sync_all bytes, and sync_data bytes survived fresh boots'
````

### flush-file.rs (flush helper)

````rust
// Installation helper only; never runs the target executable.
fn main() {
    let path = std::env::args().nth(1).expect("file to flush");
    let operation = std::env::args().nth(2).unwrap_or_else(|| "all".into());
    let bytes: Vec<u8> = (0..8193).map(|i| (i * 37 + 11) as u8).collect();
    match operation.as_str() {
        "all" => std::fs::File::open(path).unwrap().sync_all().unwrap(),
        "write-all" | "write-data" => {
            use std::io::Write;
            let mut file = std::fs::File::create(path).unwrap();
            file.write_all(&bytes).unwrap();
            if operation == "write-all" {
                file.sync_all().unwrap();
            } else {
                file.sync_data().unwrap();
            }
        }
        "verify" => assert_eq!(std::fs::read(path).unwrap(), bytes),
        _ => panic!("unknown flush operation"),
    }
}
````

### vm-cpu.py (hypervisor thread CPU accounting)

````python
#!/usr/bin/env python3
"""Read CPU accounting for threads of the benchmark's own hypervisor."""
import json
from pathlib import Path
import sys
rows = {}
for task in (Path('/proc') / sys.argv[1] / 'task').iterdir():
    line = (task / 'stat').read_text()
    name = line[line.index('(') + 1:line.rindex(')')]
    fields = line[line.rindex(')') + 2:].split()
    rows[task.name] = dict(name=name, user=int(fields[11]), system=int(fields[12]),
                           guest=int(fields[40]), minor_faults=int(fields[7]))
print(json.dumps(rows))
````

### run-trace.sh (strace variant of the driver; host denied ptrace)

````sh
#!/usr/bin/env bash
# Host driver: one measured command per newly booted VM; no warmup/retries.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$repo"
artifacts=$1
mode=$2
label=$3
count=${4:-1}
vm=build/spawn-cold/vm
runtime=/tmp/motor-spawn-cold
cp "$artifacts/kloader" "$vm/kloader"
cp "$artifacts/initrd" "$vm/initrd"
vm_pid=
cleanup() {
    if [[ -n "$vm_pid" ]]; then
        curl --silent --show-error --unix-socket "$runtime/chv" -X PUT http://localhost/api/v1/vmm.shutdown
        wait "$vm_pid"
        vm_pid=
    fi
}
trap cleanup EXIT
for ((sample=1; sample<=count; sample++)); do
    prefix="build/spawn-cold/$label-$sample"
    MOTO_IMAGE=flat.qcow2 MOTO_MEMORY_MIB=8192 MOTO_CHV_RUNTIME_DIR="$runtime" \
        taskset -c 0,2,4,6 "$vm/run-chv.sh" > "$prefix-serial.log" 2>&1 &
    vm_pid=$!
    sleep 1
    perf_pid=
    if [[ "${SPAWN_COLD_PERF:-0}" == 1 ]]; then
        perf stat -p "$vm_pid" -e cycles:G,cycles:H,instructions:G,instructions:H,context-switches,page-faults \
            -o "$prefix-perf.txt" -- sleep 0.4 &
        perf_pid=$!
    fi
    if [[ "${SPAWN_COLD_CPU:-0}" == 1 ]]; then python3 docs/plans/spawn-cold-prototype/vm-cpu.py "$vm_pid" > "$prefix-cpu-before.json"; fi
    strace -f -qq -s 0 -ttt -T -e trace=pread64,preadv,preadv2,readv,lseek,io_uring_enter \
        -o "$prefix-strace.txt" -p "$vm_pid" &
    trace_pid=$!
    sleep 0.1
    ssh -F /dev/null -p 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile=src/tests/test-known-hosts \
        -i vm_images/release/test.key motor@192.168.4.2 \
        "/user/spawn-bench-family 1 $mode /devtools/bin/rustc --version" \
        > "$prefix.csv" 2> "$prefix.stderr"
    if [[ "${SPAWN_COLD_CPU:-0}" == 1 ]]; then python3 docs/plans/spawn-cold-prototype/vm-cpu.py "$vm_pid" > "$prefix-cpu-after.json"; fi
    if [[ -n "$perf_pid" ]]; then wait "$perf_pid"; fi
    # Optional post-measurement drain for asynchronous diagnostic logging.
    if [[ -n "${SPAWN_COLD_LOG_DRAIN:-}" ]]; then sleep "$SPAWN_COLD_LOG_DRAIN"; fi
    cleanup
    wait "$trace_pid"
    cat "$prefix.csv"
done
````

### initrd.rs (initrd packer)

````rust
use std::fs;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let bins = std::path::Path::new(&args[1]);
    let kloader = fs::read(bins.join("kloader.bin")).unwrap();
    let kernel = fs::read(bins.join("kernel")).unwrap();
    let io = fs::read(bins.join("sys-io")).unwrap();
    let kstart = 512usize;
    let kend = kstart + kloader.len();
    let mstart = (kend + 511) & !511;
    let mend = mstart + kernel.len();
    let iostart = (mend + 4095) & !4095;
    let ioend = iostart + io.len();
    let mut bytes = vec![0; ioend];
    for (idx, value) in [0xf402_100f, kstart, kend, mstart, mend, iostart, ioend]
        .iter()
        .enumerate()
    {
        bytes[idx * 4..idx * 4 + 4].copy_from_slice(&(*value as u32).to_le_bytes());
    }
    bytes[kstart..kend].copy_from_slice(&kloader);
    bytes[mstart..mend].copy_from_slice(&kernel);
    bytes[iostart..ioend].copy_from_slice(&io);
    fs::write(&args[2], bytes).unwrap();
}
````

### summarize.rs (warm prototype summarizer, excludes round 0)

````rust
use std::collections::BTreeMap;

fn median(v: &[f64]) -> f64 {
    (v[(v.len() - 1) / 2] + v[v.len() / 2]) / 2.0
}

fn main() {
    for path in std::env::args().skip(1) {
        let log = std::fs::read_to_string(&path).unwrap();
        let mut modes: BTreeMap<String, (Vec<f64>, Vec<f64>)> = BTreeMap::new();
        println!("{path}");
        for line in log.lines().skip(1) {
            let cols: Vec<_> = line.split(',').collect();
            if cols.len() < 4 {
                continue;
            }
            if cols[1] == "0" {
                println!(
                    "  initial {}: spawn {} us; total {} us",
                    cols[0], cols[2], cols[3]
                );
                continue;
            }
            let row = modes.entry(cols[0].to_owned()).or_default();
            row.0.push(cols[2].parse::<f64>().unwrap() / 1000.0);
            row.1.push(cols[3].parse::<f64>().unwrap() / 1000.0);
        }
        for (mode, (mut spawn, mut total)) in modes {
            spawn.sort_by(f64::total_cmp);
            total.sort_by(f64::total_cmp);
            let mean = total.iter().sum::<f64>() / total.len() as f64;
            println!("  {mode}: n={} spawn median={:.3} ms; total mean={mean:.3}, median={:.3}, p95={:.3}, min={:.3}, max={:.3} ms",
                total.len(), median(&spawn), median(&total), total[(total.len() * 95).div_ceil(100) - 1], total[0], total[total.len()-1]);
        }
    }
}
````

### bench.rs (warm prototype harness, with SPAWN_BENCH_PREPARE)

````rust
// Scratch benchmark, cross-built with the repository-selected Rust toolchain.
use std::process::{Command, Stdio};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rounds: usize = args.get(1).map_or(30, |s| s.parse().unwrap());
    let modes: Vec<&str> = args
        .get(2)
        .map_or("eager", String::as_str)
        .split(',')
        .collect();
    let program = args
        .get(3)
        .map_or("/devtools/rust/bin/rustc", String::as_str);
    let child_args: Vec<&str> = if args.len() > 4 {
        args[4..].iter().map(String::as_str).collect()
    } else {
        vec!["--version"]
    };
    // Optional explicit first load, timed separately, for the family-cache
    // experiment. The measured commands can then use a fresh shell launcher.
    if let Ok(program) = std::env::var("SPAWN_BENCH_PREPARE") {
        let start = Instant::now();
        let output = Command::new(program)
            .arg("--version")
            .env("MOTOR_SPAWN_PROTO", "cache-family-vdso")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success() && output.stderr.is_empty());
        eprintln!("prepare_us={}", start.elapsed().as_micros());
    }
    let mut expected = None;
    println!("mode,round,spawn_us,total_us");
    for round in 0..rounds {
        let order: Vec<_> = if round % 2 == 0 {
            modes.iter().copied().collect()
        } else {
            modes.iter().rev().copied().collect()
        };
        for mode in order {
            let mut command = Command::new(program);
            command.args(&child_args).env("MOTOR_SPAWN_PROTO", mode);
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let start = Instant::now();
            let child = command.spawn().unwrap();
            let spawn = start.elapsed();
            let output = child.wait_with_output().unwrap();
            let total = start.elapsed();
            assert!(output.status.success(), "{mode}: {:?}", output);
            assert!(output.stderr.is_empty(), "{mode}: {:?}", output);
            if let Some(ref bytes) = expected {
                assert_eq!(&output.stdout, bytes);
            } else {
                eprintln!("output: {}", String::from_utf8_lossy(&output.stdout).trim());
                expected = Some(output.stdout);
            }
            println!(
                "{mode},{round},{},{},",
                spawn.as_micros(),
                total.as_micros()
            );
        }
    }
}
````

## Appendix D: superseded implementation plan (2026-10-03)

Archived on 2026-10-04 when the user chose sys-io loading. The previous
main document is preserved below, with only heading levels adjusted.
Its recommendations, alternatives, open questions, and stale tree notes
are historical; they do not override the current main plan or section 9.
This retains the mechanism inventory, tuning values, detailed validation
procedure, and the user's recorded decisions without lengthening the
active plan.

### Cold spawn optimization: implementation plan

Status (2026-10-03): the prototype is archived and its validation is
complete; production work has not started. The plan was reviewed on
2026-10-03 and the review questions are in section 10. Two of them are
decided: Q1 (there is no numeric acceptance gate) and Q2a (the runtime
handoff is done in Motor's mlibc, option (d), described in section 9).
Each remaining question blocks the step it names. The prototype itself is
recorded in [spawn-optimization-prototype.md](spawn-optimization-prototype.md).

#### 1. Goal, evidence, and scope

The goal is to make a cold launch of a large executable much faster. The
reference workload is `/devtools/bin/rustc --version` on a freshly booted
Motor OS VM, including its shell wrapper. Startup should read, allocate,
relocate, and map only the pages the program actually touches, instead of
doing that work for the whole file. The prototype reached a tenfold
improvement; per the Q1 ruling there is no numeric acceptance threshold.
Acceptance rests on the correctness gates in section 7, and the measured
ratio is reported next to the prototype's result.

The frozen prototype produced these release results:

| Workload | Alternating pairs | Baseline mean | Prototype mean | Ratio of means |
|---|---:|---:|---:|---:|
| `rustc --version`, normal wrapper | 50 | 374.542 ms | 37.109 ms | **10.09x** |
| LLVM/Clang `--version` | 10 | 328.431 ms | 41.738 ms | **7.87x** |
| Rush `-c exit` | 10 | 6.935 ms | 5.264 ms | **1.32x** |

Each sample ran in a fresh VM and was accepted only with the exact expected
stdout, an empty stderr, and a successful exit. Host storage caches were
not flushed between samples, so "cold" means a cold guest, not a cold host.
Rush is already running by the time the VM has booted, so its row is a
small-program sanity check, not a cold-executable result. The rustc ELF
that was measured is 119,030,776 bytes. The result belongs to the prototype
as a whole; the individual optimizations were not measured on their own.
See the archive's [results](spawn-optimization-prototype.md#1-results)
and [experiment ledger](spawn-optimization-prototype.md#4-experiment-ledger-2026-10-02).

In scope: the executable loader and the child's vDSO setup in `rt.vdso`,
kernel memory management and fault delivery, filesystem paging in sys-io,
the native libraries those paths use, and one toolchain change: Motor's
mlibc stops walking the executable's relocation table at startup (section
8, decision 2b), after which the mlibc-linked binaries in the developer
image are relinked. **The kernel ELF loader that loads sys-io is out of
scope.** Rust std, moto-rt, and the Rust toolchain stay unchanged; any
proposal that needs them needs a separate discussion. Do not add boot-time
preparation, a learned access profile, a per-executable address list, or a
persistent executable index.

The `fsync`/`datasync` fix is a prerequisite. Q3 decides how it is
committed; do not reapply it from the candidate patch. Both calls were
validated across fresh boots, including after the prototype was removed.

#### 2. Mechanisms at a glance

Every mechanism the plan carries, with a rough estimate of what it
contributed to the `rustc --version` result. The estimates come from the
prototype's experiment ledger (archive section 4), where each change was
measured on top of
the previous ones against a moving baseline, usually from one to three
samples. They are not independent measurements and they do not add up to
the 337 ms between 374.5 ms and 37.1 ms; read them as orders of magnitude.
"n/s" means the ledger could not separate the effect from noise.

- **Header-only loading with demand paging of file segments (Steps 3–7):**
  the loader reads a few KiB of metadata and reserves sparse ranges;
  sys-io fills pages on fault. About 285 ms (375 to about 90).
- **Sparse reservations without per-page descriptors (Step 3):** about
  3 ms.
- **Page-local relocation of touched writable pages (Steps 8a, 8b):**
  zero, copy, relocate, publish, with a table lookup instead of a full
  walk. About 25 ms (79 to 55).
- **Runtime handoff, option (d) (Step 8c):** the C runtime no longer walks
  the table, so writable input fell from 2.9 MB to 0.11 MB. About 15 ms,
  measured through the prototype's tag rewrite.
- **Zero-copy sharing of clean read-only pages (Step 9):** block-cache
  frames mapped straight into the child. n/s in the ledger.
- **Sparse resident vDSO mapping (Step 10):** about 10 to 15 ms (60.6 to
  45.0, single samples).
- **Lazy allocator slabs for the child and the launcher (Step 11):** about
  3 ms.
- **Constructor prefetch and code-reference guesses (Steps 12b, 12c):**
  about 8 ms.
- **Adaptive demand window and first-fault read-ahead (Steps 12a, 12c):**
  about 2 ms.
- **Zeroed contiguous DMA pool and descriptor coalescing (Step 13):** the
  pool alone n/s; coalescing about 2 ms.
- **Batched kicks, bounded completion polling, and the shared pending
  counter (Step 14):** about 3 ms combined (counter about 2, polling
  budget about 1).
- **Interpolation probes in the relocation lookup (Step 15a):** about
  1 ms; disappears under Q2 option (c).
- **Batched user-frame allocation (Step 15b):** about 4 ms (45.4 to 41.5,
  one diagnostic sample).
- **Bulk zeroing loop and batched page-table teardown (Step 15c):** about
  1 ms combined; the zeroing loop alone n/s.
- **Eligibility policy (Step 16a):** decides which executables use paging;
  no contribution to rustc, protects small programs.
- **fsync/datasync fix (prerequisite):** correctness only; no timing
  contribution.

#### 3. Read the reference implementation first

The prototype is recorded in
[spawn-optimization-prototype.md](spawn-optimization-prototype.md): its
design in section 3, its experiment ledger in section 4, and the complete
patch in Appendix A. The base commit is
`6ef7737b4a5db34744827694e5c99c0b751ded44`; the measured snapshot is
**s100** in mode **`cold-131072`**. To browse the code as files, extract
Appendix A and apply it to a scratch checkout of that commit:

```sh
awk '/^````diff/{f=1;next} /^````$/{if(f)exit} f' \
    docs/plans/spawn-optimization-prototype.md > build/candidate.patch
git worktree add build/spawn-reference 6ef7737b4a5db34744827694e5c99c0b751ded44
git -C build/spawn-reference apply "$PWD/build/candidate.patch"
```

Paths below that start with `kernel/`, `lib/`, or `sys-io/` are relative to
`src/sys/` in that checkout; the same paths name the hunks in Appendix A.
**Do not apply the whole patch as an implementation step.** It contains
experiments, incomplete error handling, and shortcuts that the steps below
replace.

| Ref | Prototype file(s) | What to study |
|---|---|---|
| P1 | `lib/rt.vdso/src/rt_process.rs`, `lib/rt.vdso/src/rt_process/cold.rs` | `run_elf`, `load`, `read_at`, `Segment`: how metadata is read, how segments are registered, the entry point, and wrapper selection. |
| P2 | `kernel/src/mm/user.rs`, `kernel/src/mm/virt.rs`, `kernel/src/mm/virt_intrusive.rs` | `reserve_file`, `fill_file`, `mark_file_zero`, `VmemSegment`, `image_page`, `fix_pagefault`: sparse descriptors, private and shared pages, local zero fill. |
| P3 | `kernel/src/uspace/cold_pager.rs`, `kernel/src/uspace/process.rs`, `kernel/src/uspace/sys_mem.rs` | `Mapping`, `run_impl`, `enqueue`, `retire`, `resume_file_fault`: reserve, bind, dequeue, and fill, plus thread suspension and resumption. |
| P4 | `lib/moto-io/src/fs.rs`, `lib/rt.vdso/src/rt_fs.rs`, `sys-io/src/runtime/fs.rs`, `sys-io/src/runtime/fs/cold_pager.rs` | `register_cold`, `read_cold`, `register`, `serve`, `read_range`: the filesystem IPC and the fault service in sys-io. |
| P5 | `lib/motor-fs/src/fs.rs`, `sys-io/src/runtime/fs/cold_pager/prefault.rs` | `cold_page`, `LaunchPins`, `fetch_map`: retained `CheckpointedBlock` backing for clean read-only pages. |
| P6 | `sys-io/src/runtime/fs/cold_pager/relocations.rs` | `Relocations::{entry,validate,lower_bound,prefetch_tree,apply,store}`: page-local relocation lookup and split writes. |
| P7 | `sys-io/src/runtime/fs/cold_pager/prefault.rs`, `sys-io/src/runtime/fs/cold_pager.rs` | `start`, `references`, `fetch_map`, `serve`: constructor, reference, first-fault, and consecutive-access read-ahead. |
| P8 | `lib/rt.vdso/src/load.rs`, `kernel/src/mm/virt_intrusive.rs`, `kernel/src/uspace/sys_mem.rs` | `load_vdso_sparse`, `init_remote_vdso`, `RemoteLoader`, `image_page`: resident vDSO backing shared through sparse mappings. |
| P9 | `lib/rt.vdso/src/rt_alloc.rs`, `kernel/src/mm/user.rs`, `kernel/src/uspace/sys_mem.rs` | `BackEndAllocator::alloc`, `alloc_cold_heap`, `sys_map`: lazy allocator backing with eager backing for IPC and privileged users. |
| P10 | `lib/fittings/src/iobuf.rs`, `lib/moto-tooling/src/iobuf.rs`, `lib/async-fs/src/block_cache.rs`, `lib/virtio-async/src/virtio_blk.rs` | `from_raw`, `ColdPages`, `ColdIoGuard`, `cold_read_buffers`, `pop_free_block`, `try_request`: zeroed contiguous buffers and descriptor coalescing. |
| P11 | `lib/moto-async/src/local_runtime.rs`, `lib/virtio-async/src/virtio_blk.rs`, `lib/virtio-async/src/virtio_queue.rs`, `sys-io/src/runtime/fs/block_io.rs`, `sys-io/src/runtime/fs/cold_pager.rs` | `SpinSource`, `park_spin_sources`, `cold_poll`, `cold_watch`, `kick_deferred`, `InFlight`, `poll_done`, `ReadyRequest`: batching, bounded polling, and wakeup handling. |
| P12 | `kernel/src/mm/mod.rs`, `kernel/src/mm/virt_intrusive.rs`, `kernel/src/arch/x64/paging.rs` | `zero_page`, `allocate_pages`, `unmap_page`, `prune_range`, `prune_unmapped_range`: frame allocation, zeroing, and page-table teardown. |

Do not port `hints.rs` or `lookahead.rs`; they are unused leftovers. The
same goes for `ANON_SPARSE` mode 2, parent-serviced paging, the diagnostic
syscalls, and the numeric experiment modes.

#### 4. How to work through this plan

Follow the steps in order. Each numbered step is a milestone made of
several lettered patches. A patch should normally be **100–300 changed
lines including tests**; split it further if it grows beyond that. After
each patch, record here which files changed, which checks ran, and what
comes next. Leave unrelated edits alone and do not commit unless asked.
Use standard Rust and native Motor APIs, format with the repository's
`cargo fmt`, and add no compiler or clippy warnings.

The prototype worked under a review and test exemption. Production work
follows [AGENTS.md](../../AGENTS.md) as it stands at the time.

Resolve the [design decisions](#9-design-decisions) and the
[review questions](#10-review-questions-2026-10-03) before implementing
the mechanisms they affect.

Keep these invariants throughout:

- A launch reads headers, dynamic data, relocations, and faulted pages from
  one approved version of the file. A path lookup alone does not identify
  that version.
- The kernel ties a mapping to its address space and to the pager that is
  authorized to fill it. sys-io separately checks that the authenticated
  caller may read and execute the file.
- Only initialized pages become present. Writable pages, relocated pages,
  and pages at file edges are private to the child; complete, clean,
  read-only pages may share retained backing.
- A page is published after it has been initialized and relocated, and
  before any waiting thread resumes. A failed or retired mapping cannot
  install further pages.
- Source frames stay owned while a child mapping or a DMA operation uses
  them. Closing the launcher or evicting a cache entry must not free them.
- An unsupported format may fall back to the eager loader before the child
  runs, after complete cleanup. Permission, I/O, corruption, and allocation
  failures are reported, never hidden by a fallback. Every format the eager
  loader supports today keeps working.

#### 5. Implementation steps

##### Step 0 — Establish the baseline

**References:** the archive's
[measurement method](spawn-optimization-prototype.md#2-measurement-method)
and the harness, drivers, installer, and durability check in its
[Appendix C](spawn-optimization-prototype.md#appendix-c-harness-drivers-and-helpers).

- [ ] 0a. Inspect the tree and reconcile it with the archived base. Confirm
  the sync fix is present (Q3) and delete the leftover
  `src/sys/kernel/src/mm/virt_intrusive.rs.orig`. Record source and
  toolchain hashes and keep the baseline build artifacts separately; never
  overwrite the archive.
- [ ] 0b. Copy the benchmark drivers into implementation tooling with
  explicit baseline, candidate, image, and output paths. The archived
  scripts hard-code `build/spawn-cold/baseline` and their output
  locations; a future build must not be compared against that historical
  baseline by accident.
- [ ] 0c. Record fresh-VM baseline timings and boot and memory observations
  before changing any behavior. Install and flush helpers outside the timed
  samples. Fix the target binaries, VM resources, host affinity, and
  measurement boundaries. Freeze the baseline OS build (kernel, sys-io,
  vDSO) here: the final comparison in section 7 runs it against the
  relinked binaries from Step 8c, on both sides.

**Done when:** the baseline is repeatable, its source and build hashes are
recorded, and stdout and exit status are checked. Source timestamps or
stale embedded vDSO artifacts must not be able to make the measured build
differ from the intended source.

##### Step 1 — Specify the native contracts and test fixtures

**References:** P1–P6; current `lib/moto-sys/src/sys_mem.rs` and
`lib/moto-sys-io/src/api_fs.rs`.

- [ ] 1a. Resolve the decisions in section 9 and the questions in section
  9. Write down who owns a session, which permission checks apply, the
  lock order, the cancellation sequence, the error codes, and what each
  operation is charged to. Keep ownership of immutable backing separate
  from page presence.
- [ ] 1b. Define typed request and response layouts for opening and binding
  a session, reserving a segment, dequeuing faults, supplying or failing
  pages, and retiring mappings. Describe version negotiation and what
  happens on an unsupported operation.
- [ ] 1c. Define small hermetic ELF fixtures and their expected behavior for
  file edges, BSS, relocations, unsupported layouts, and permission
  failures. Add a `cold_spawn` module to `src/sys/tests/systest/src/` and
  register its checks and subcommands in `main.rs`. Generate the fixtures
  in Rust.

**Done when:** the contracts can be reviewed and every decision has an
answer. Another engineer should be able to tell which component owns each
object and which error each failure path returns. This step authorizes no
toolchain or moto-rt change beyond the mlibc change in section 9.

##### Step 2 — Add named native APIs and checked codecs

**References:** P3/P4. Production API additions belong in moto-sys and
moto-sys-io, not in moto-rt.

- [ ] 2a. Add named syscall operations and flags with checked wrappers in
  `lib/moto-sys/src/sys_mem.rs`, and update kernel dispatch and flag
  validation. Replace the prototype's operation 6 and its raw `0x100` and
  `0x200` flags with the approved API. Review memory charging for every
  new flag.
- [ ] 2b. Add named filesystem messages and codecs in
  `lib/moto-sys-io/src/api_fs.rs`, replacing scratch command `0x7f00` and
  the overloaded write-message payload. Update `known_cmd`,
  `is_read_command`, capability gating, donated-page cleanup, and
  channel-budget handling.
- [ ] 2c. Add checked wrappers in moto-io and rt.vdso. The server validates
  lengths, counts, arithmetic, flags, handles, and ownership on its own and
  never trusts ELF metadata supplied by the client. Reject unknown versions
  cleanly.

**Done when:** codec and dispatch tests reject malformed and unauthorized
requests without leaks and without terminating the service. Execution
session requests count as read operations for clients without filesystem
write capability. Handlers that are not implemented yet return
"unsupported"; end-to-end execution arrives in Step 7.

##### Step 3 — Implement sparse file reservations and page installation

**References:** P2; `kernel/src/mm/{user,virt,virt_intrusive}.rs`.

- [ ] 3a. Add a file-backed reservation kind. Reserve the virtual range with
  metadata proportional to the populated pages rather than one descriptor
  per possible page. Keep admission accounting and the user-address,
  overlap, and alignment checks.
- [ ] 3b. Implement installation of fully initialized private pages.
  Validate range and protection on every call; keep executable permissions
  and the existing W+X rejection. When a batch fails part way, report
  which pages were installed so the fault layer can fail the rest without
  reporting them present and without losing ownership of the installed
  ones.
- [ ] 3c. Teach lookup, pinning, mapping status, full and partial unmap, and
  the drop paths about missing descriptors. Release frames and charges
  exactly once. Shared backing and local BSS filling come in later steps.

**Done when:** a sparse reservation uses bounded metadata, installed pages
can be read, holes fault, protection violations fail, and unmap returns the
accounting to its starting value. The existing oversized-ELF OOM test in
systest keeps its error semantics.

##### Step 4 — Implement fault delivery, completion, and cancellation

**References:** P3; a new kernel pager module plus `process.rs` and
`sys_mem.rs`.

- [ ] 4a. Implement mapping ownership and the page states: missing, queued,
  in flight, and present, with failed and retired as terminal states.
  Coalesce simultaneous faults on one page, including faults that arrive
  after a dequeue. Allocate state only for outstanding requests and
  populated pages, within the limits from Step 1.
- [ ] 4b. Implement bind, dequeue, supply, and fail, and thread suspension.
  Keep the lock order: publish the initialized mapping before resuming
  waiters, and drop the registry lock before taking a waiter's status
  lock. Re-check a fill that races with waiter registration so that no
  wakeup is lost.
- [ ] 4c. Implement explicit retirement on unmap, failed launch, process
  exit, and pager disconnect. Reject stale completion tokens after a
  virtual address is reused; release pending notifications and wake or
  fail every waiter.

If Q4 selects option (b), add 4d here: a populate operation that enqueues
demand requests for a range of one file-backed mapping and waits for them,
returning errors instead of terminating the child.

**Done when:** deterministic interleavings of fault, fill, unmap, and exit
finish without duplicate publication, lost wakeups, deadlock, or
use-after-free. An ordinary client cannot fill another process's mapping
by guessing an identifier. The prototype's diagnostic operations are gone
from this API.

##### Step 5 — Implement filesystem execution sessions

**References:** P4/P5; `sys-io/src/runtime/fs.rs`, the new pager module,
`lib/motor-fs/src/fs.rs`, and the mutation paths in motor-fs.

- [ ] 5a. Implement the file-lifetime mechanism chosen in decision 1 (an
  execution lease, unless the decision says otherwise). Acquire it before
  reading any metadata and hold it until the last mapping is gone. Cover
  every mutation path listed in Step 1, including handles that were
  already open for writing. Copying an `EntryId` or holding individual
  cache pages is not enough.
- [ ] 5b. Bind the session to the authenticated IPC client and to the
  kernel mapping. Check the file kind, read and execute permission,
  limits, and segment ranges. Make multi-segment registration
  transactional, with rollback.
- [ ] 5c. Implement demand service in sys-io using a zeroed temporary page
  and private-page installation first. Keep sys-io's own memory and I/O
  paths resident so that serving a fault can never depend on the faulting
  child. Report read, EOF, and OOM errors through the fail operation;
  never `panic!`.

**Done when:** session tests exercise the chosen mutation semantics, every
read sees the same version, ownership survives the client closing its
handle while a mapping remains, and teardown frees all session state.
Children that outlive their launcher are checked in Step 7. No global
filesystem lock is held while waiting for the child's next fault.

##### Step 6 — Add checked ELF metadata loading and eager fallback

**References:** P1; `lib/rt.vdso/src/rt_process.rs` and a new loader
module.

- [ ] 6a. Implement checked positional reads of the metadata and parse the
  ELF and program headers into an owned layout. Read the program headers
  separately when needed; the prototype's assumption of at most 32 headers
  inside the first 4 KiB is not a general contract. Validate architecture
  and type, arithmetic, alignment, file and memory bounds, overlap, the
  entry point, dynamic tags, and the existing load-bias behavior.
- [ ] 6b. Keep the normal path and wrapper resolution, capability handling,
  arguments, environment, stack layout, and child startup. Read the
  metadata through the Step 5 session; do not reopen the path, which could
  select a different file.
- [ ] 6c. Classify every input as supported, valid but not supported by the
  pager, or malformed. Valid inputs the pager does not support, such as
  layouts outside the first implementation's coverage, go to the eager
  loader. Malformed inputs fail before either loader runs, so the known
  elfloader panics (Q5) cannot be reached. Roll back reservations and
  sessions before falling back; never restart a running child.

**Done when:** every input that worked before still works or reports the
same error class as before. Malformed, truncated, and W+X fixtures fail
safely; unsupported TLS, interpreter, and relocation forms are not
misloaded. The new loader never reads the whole file just to get the
headers.

##### Step 7 — Integrate a correct demand loader before lazy relocations

**References:** P1/P4/P6 and the eager loader's relocation rules.

- [ ] 7a. Wire the metadata parser, the sparse reservations, and the sys-io
  service together behind a development-only selector (Q7). The normal
  path stays eager until Step 16. The selector grants no extra authority.
- [ ] 7b. For now, validate and apply all supported relocations up front and
  eagerly prepare the writable pages they touch. Demand-fill only the
  read-only segments, with private initialized pages at the edges and the
  existing startup semantics. This is the correctness reference for Step
  8.
- [ ] 7c. Exercise ordinary execution beyond printing a version: a small
  Rust compile and run, constructors, globals, BSS, arguments and
  environment, and piped output. Add child, parent, and sibling isolation
  checks and launch-failure cleanup checks to the default systest run.

**Done when:** the first complete pager path is correct, with no
speculative I/O and no assumption about relocation order. Record its
timings and bytes read; this intermediate milestone has no performance
target.

##### Step 8 — Apply relocations only to touched writable pages

**References:** P6, P1's dynamic-tag handling, and section 9, decision 2.

- [ ] 8a. Validate the relocation table under the policy chosen in Q2.
  Check types, symbol fields, destinations, load bias and addends,
  duplicate and overlap rules, and table boundaries. Keep the eager
  fallback for tables the policy does not cover.
- [ ] 8b. For a faulted writable page: zero it, copy the file bytes that
  intersect it, find every relocation that overlaps it, including one that
  starts up to seven bytes before the page, apply only the bytes that land
  in this page, and publish the page only after all of its writes are
  done. Compare the result with the eager reference, including a
  relocation that crosses a page boundary.
- [ ] 8c. Toolchain: make Motor's mlibc skip the executable's relocation
  walks at startup, as described in section 9, decision 2b. This changes
  `../toolchain-src/mlibc` and must be called out as an external change in
  every conversation and commit message. Rebuild the mlibc sysroot, relink
  the mlibc-linked binaries in the developer image, record their hashes,
  and confirm with the fault counters that `rustc --version` no longer
  faults its whole writable data. The pager does not rewrite dynamic tags;
  drop the prototype's `consumed` logic. Binaries linked before this
  change keep working; they are only slower under the pager because they
  still walk the table.
- [ ] 8d. Add local zero filling for whole BSS tail pages, but only after
  proving they contain neither file bytes nor relocation or dynamic-tag
  writes. Page edges and relocated BSS keep using the pager's initialized
  private path.

**Done when:** constructors, globals, read-only file integrity, sibling
isolation, cross-page relocations, and BSS match the eager reference, and
a relinked C program and the relinked rustc start correctly under both
loaders. Record separately the cost of table validation and of the
page-local work.

##### Step 9 — Share clean filesystem pages without copying

**References:** P2/P5; `CheckpointedBlock` and `cold_page`.

- [ ] 9a. Add an explicit motor-fs API that hands out retained, clean,
  whole-page backing for the Step 5 version. Keep its owner alive across
  cache eviction and copy-on-write; never pass off a temporary borrowed
  pointer as ownership.
- [ ] 9b. Add privileged shared-page installation to the kernel. Only
  complete read-only segment pages qualify. Keep frame references in the
  child and reject writable sharing. Keep the private-copy fallback for
  dirty, sparse, partial, huge-backed, or otherwise unshareable pages.
- [ ] 9c. Release sys-io, cache, and kernel ownership in the agreed order on
  unmap, cancellation, and child exit. Integrate memory-pressure limits.

**Done when:** sharing survives cache eviction and launcher exit, writable
children stay isolated, and no neighboring file bytes or stale page data
appear at segment edges. Measure read-only installation time and retained
memory. An executable prepared in an earlier VM does not count as a cold
run.

##### Step 10 — Make the per-child resident vDSO mapping sparse

**References:** P8. This is separate from file demand paging.

- [ ] 10a. Add a typed owner for resident-image backing with sparse
  destination page descriptors. Capture the already-resident source frames
  once and share ownership with descendants; later children must not
  enumerate or copy a full per-page descriptor tree. Support faults,
  pinning, and partial unmap.
- [ ] 10b. Use it for both the raw vDSO object at `RT_VDSO_BYTES_ADDR` and
  the read-only loaded vDSO segments. The current loader already shares
  these bytes; the prototype saves the mapping and descriptor work on top
  of that.
- [ ] 10c. Keep writable vDSO data freshly copied from the pristine object,
  relocated, and private to each child, including the vtable and runtime
  state. Populate small runs of resident PTEs on a fault, starting with
  the prototype's 16-page bound. Validate protections and backing
  lifetime.

**Done when:** a parent and two generations of children can independently
allocate, use filesystem and stdio state, and spawn after their ancestors
have exited. Verify that a child never inherits a parent's mutable runtime
state. Record the vDSO setup cost separately; change no kernel sys-io ELF
loading code.

##### Step 11 — Make allocator slabs lazy without changing IPC contracts

**References:** P9; `rt_alloc.rs`, `mm/user.rs`, and `uspace/sys_mem.rs`.

- [ ] 11a. Add a named backing hint for the allocator. Unprivileged slab
  allocations receive zeroed physical pages when first touched; privileged
  sys-io allocations and direct IPC or shared allocations stay eagerly
  backed. Keep reservation and admission accounting and the allocation
  error behavior as they are.
- [ ] 11b. Apply the hint to the unprivileged launcher as well as to its
  children: the measured result includes the launcher's first runtime
  setup. Exercise first touch, zero initialization, realloc and free, and
  reclamation.

**Done when:** IPC buffers are resident whenever their API requires it,
paging has no allocator recursion or deadlock, and memory limits still
hold. Do not port the dormant `ANON_SPARSE` heap and stack mode 2. Measure
the launcher, small programs, and boot behavior before enabling the hint
generally.

##### Step 12 — Add bounded read-ahead derived from the current launch

**References:** P7. Implement each predictor in a separate patch.

- [ ] 12a. Add demand read-ahead: start at one page, double only after a
  consecutive access, cap at 32 pages, and reset on a non-consecutive
  access.
- [ ] 12b. Prefetch validated constructor targets from `DT_INIT_ARRAY` and
  from relocations, initially two pages each. Batch 64 predicted pages,
  combine nearby file runs of up to 16 pages, and bridge at most one
  unrequested page.
- [ ] 12c. Add bounded guesses from constructor code references and
  background read-ahead after the first executable fault, using the table
  in section 6. The demanded page must never wait for the speculative
  range to finish.
- [ ] 12d. Share deduplication, cancellation, ownership, and quotas with
  demand requests. Stop speculating under memory pressure. A failed
  prediction leaves demand loading available; I/O and session failures
  follow the agreed error contract. Unrecognized instruction bytes simply
  yield no hint.

**Done when:** disabling every predictor preserves correctness, random or
sparse access does not create unbounded I/O, and cancellation frees
speculative resources. Record the extra bytes read and the latency saved.
No saved trace addresses, command-name matching, or boot-time preparation
may feed the predictions.

##### Step 13 — Batch zeroed DMA allocation and virtio descriptors

**References:** P10. These changes also affect I/O unrelated to spawn.

- [ ] 13a. Add an owned batch of 16 zeroed, physically contiguous 4-KiB DMA
  buffers with a single physical-address lookup. Hand buffers out in
  ascending physical order. Keep the mapping owner alive through cache
  ownership and DMA completion; fall back to ordinary allocation when no
  contiguous batch is available.
- [ ] 13b. Coalesce physically adjacent buffers into data descriptors. Keep
  the request, page, and queue bounds, the negotiated device segment
  limits, descriptor length limits, ordering, and completion-byte
  accounting.
- [ ] 13c. Verify mixed contiguous and non-contiguous requests,
  cancellation, cache retention, device errors, writes, and flush
  ordering. Keep zero initialization; the rejected uninitialized-buffer
  experiment is not needed for the measured result.

**Done when:** ordinary I/O and the durability paths still work, and no
buffer can be freed or reused during DMA or while it is mapped into a
child. Measure the descriptor count and the allocation and lookup cost,
then the completed spawn time.

##### Step 14 — Reduce notification and completion overhead

**References:** P11; the block worker, the virtqueue, and the local
runtime.

- [ ] 14a. Batch read submissions and defer kicks, issuing a kick before
  sleeping or before waiting for a completion. Port the flat
  `Vec<InFlight>` polling layout as a separate patch; keep backpressure
  and write and flush ordering.
- [ ] 14b. Add bounded completion polling for active paging I/O. Start with
  a 200-microsecond idle budget, fall back to normal notifications, and
  keep runtime fairness and device error propagation.
- [ ] 14c. Add a pinned atomic pending-request counter and pure readiness
  checks that persist around park and rearm. The reference's one-second
  watcher lifetime is not a one-second busy-spin budget. Give retired
  sessions an explicit terminal state and remove their watchers.

**Done when:** arrivals before, during, and after park, interrupt
rearming, queue saturation, concurrent readers and writers, and pager
teardown all complete without lost wakeups. Idle processes do not spin
indefinitely. Record CPU time as well as wall time, including a one-vCPU
configuration and a run with unrelated I/O.

##### Step 15 — Port bounded relocation and memory-management tuning

**References:** P6/P12. Keep these independently reviewable.

- [ ] 15a. Once relocation correctness is established, prefetch six binary
  search levels, allow up to four interpolation probes inside the
  resulting bracket, and keep the binary-search progress afterwards. Use
  one lower bound and a forward scan of 64 records per read, stopping at
  the page end.
- [ ] 15b. Batch eligible eager user-frame allocations up to 64 pages with
  an ordinary-allocation fallback. Keep the options at segment edges, the
  charges, partial-failure cleanup, and zero initialization.
- [ ] 15c. Port the standard-Rust zero-store loop (eight `u64` writes per
  cache line) and, separately, batch page-table pruning by 2-MiB windows.
  Keep the TLB invalidation order: a mapping must stop being usable before
  its backing or page-table frames can be reused on any CPU.

**Done when:** results match the untuned algorithms for boundary,
duplicate, and error cases, teardown works across page-table boundaries
and CPUs, and the memory and CPU measurements show no regression that
outweighs the spawn benefit. A small exploratory win is not by itself
proof that a tuning change is worth keeping.

##### Step 16 — Select the default path and finish production validation

**References:** P1's selection logic and all preceding milestones.

- [ ] 16a. Evaluate the measured eligibility policy (paging for executables
  of at least 256 KiB; below 1 MiB, prepopulate complete read-only pages)
  against small and large programs. Keep valid unsupported formats on the
  eager path. Choose and document the default after the correctness and
  memory gates pass.
- [ ] 16b. Remove scratch numeric modes, diagnostic output, unused branches,
  and any assumption that a caller sets `MOTOR_SPAWN_PROTO`. A comparison
  selector may stay only if it has a clear testing purpose and bypasses no
  check. Benchmark the actual default path.
- [ ] 16c. Run the acceptance procedure in section 7 on a frozen
  implementation. Update this plan with the real source hashes, results,
  remaining limitations, and completed checkboxes. Do not call the work
  complete if it matches the prototype's numbers only by leaving out
  production checks.

**Done when:** the production default passes the correctness and
regression gates and the cold rustc comparison is recorded next to the
prototype's 10.09x. There is no numeric threshold (Q1). If the ratio falls
clearly short of the prototype's, explain where the time went and discuss
the next change; do not weaken validation to close the gap.

#### 6. Measured tuning values to start from

These values come from snapshot s100. They are starting points for the
steps above, not protocol constants and not promises of portable
performance. Port each one only in the step that names it.

| Mechanism | Selected value or behavior | Reference |
|---|---|---|
| Demand window | 1 page, doubles on consecutive access, maximum 32 | P4/P7 |
| Constructor read width | 2 pages per target | P7 |
| Constructor reference guesses | Up to 128 bytes; E8/E9 and RIP-relative LEA/MOV patterns; stop at paired INT3 padding after byte 16 | P7 |
| First executable-fault range | Fault page plus up to 127 following pages, read in the background and clipped to the segment | P4 |
| Speculative batching | 64 pages, at most 16 pages per file run, gap at most 1 page | P5/P7 |
| Relocation lookup | 6 prefetched binary levels, up to 4 local interpolation probes, binary fallback | P6 |
| Relocation application | One lower bound; forward reads of 64 records | P6 |
| DMA pool | 16 zeroed physically contiguous pages; ascending allocation order | P10 |
| Completion polling | 200,000 ns idle budget with notification fallback | P11 |
| Pending-request watcher | May persist across parks for 1 second; pure readiness check | P4/P11 |
| Resident vDSO fault fill | Up to 16 pages already backed by resident frames | P8 |
| Eager user-frame batch | Up to 64 pages, ordinary-allocation fallback | P12 |
| File paging selection | At least 256 KiB; below 1 MiB, prepopulate complete read-only pages | P1/P4 |

#### 7. Validation and acceptance procedure

##### Correctness and regression gates

Add tests together with the implementation patches, not after all the
optimizations. Use `src/sys/tests/systest/src/cold_spawn.rs`, registered
in the default run, for VM behavior; extend the motor-fs tests for
version, copy-on-write, and mutation behavior. Wire any new host-side
protocol or state-machine test into `src/tests/full-test.sh`. A subcommand
that the default suite never invokes does not count.

| Area | Required observable checks |
|---|---|
| Loader compatibility | Valid eager and paged outputs agree; malformed headers, overflow, overlap, W+X, an invalid entry point, and unsupported formats produce the right outcome. |
| Relocations and data | Constructors, globals, BSS, a nonzero load bias where supported, duplicates and order, cross-page writes, and dynamic metadata handling agree with the eager reference. |
| Access control | Execute and read denial, role and capability restrictions, invalid peer, handle, or token, and concurrent permission changes follow the reviewed contract. |
| File version | Write, truncate, unlink, replace, and preexisting writers follow the selected session contract without mixing file versions. |
| Ownership | Parent exit, grandchild launch, cache eviction, file copy-on-write, partial unmap, and cancellation retain or release the right frames and buffers. |
| Scheduling and errors | Same-page concurrent faults, completion races, I/O errors, OOM, pager disconnect, and child exit leave no stuck waiters and no service panic. |
| Shared facilities | IPC resident backing, allocator zeroing, virtio read, write, and flush ordering, memory admission, and TLB teardown keep their contracts. |
| Resources | One-vCPU and small-memory cases, concurrent launches, sustained ordinary I/O, and repeated exits stay within limits without an accumulating leak. |

Run the relevant targeted checks after each patch. Before committing a
core patch, follow AGENTS.md: at least three successful debug and three
successful release build-and-run cycles of `src/tests/full-test.sh`,
subject to the granularity chosen in Q6. Diagnose failures rather than
adding retries, longer timeouts, or ignored assertions. Run
`src/tests/full-test-dev.sh --release` as the developer-image gate; its
debug variant is not required for this non-Lorry work. Keep new tests
hermetic and respect the repository's network-test rules. The prototype
ran VM validation only, not these suites.

##### Final cold performance comparison

1. Freeze the implementation and the baseline OS build from Step 0, both
   with the sync fix. Keep the historical prototype comparison separate.
   Build release artifacts with the selected toolchain; record source and
   artifact hashes, the kernel, initrd, and vDSO composition, and the
   hashes of the target ELFs. Both sides run the same relinked binaries
   from Step 8c.
2. Use an independent copy of the developer image. Install and flush the
   benchmark and validate its persisted bytes before timing. Do not run
   rustc or Clang during installation. Keep builds, compression, and other
   benchmarks outside the timed VM batches; respect the VM lock and the
   existing host settings.
3. Match the reference environment when comparing with its numbers: Cloud
   Hypervisor 52.0, four vCPUs, 8 GiB RAM, host affinity `0,2,4,6` on the
   recorded i9-13900H. Report any difference. Host storage caches stay
   unflushed; state that boundary explicitly. No added boot work is
   allowed.
4. Run **50 alternating baseline/candidate pairs** of the normal
   `/devtools/bin/rustc --version` wrapper, one measured invocation per
   fresh VM. The harness's expected version string must match the
   installed rustc. The relinked rustc prints the same version but has a
   new hash; record it. A future version change needs an explicit fixture
   update on both sides, not a relaxed assertion. Keep failed runs as
   failures.
5. Measure from spawn through exit, wait, and output collection using
   `total_us`. Include round zero. Require a successful status, exact
   stdout, and empty stderr. `spawn_us` alone misses the rustc execution
   inside its wrapper. Keep every completed sample and every outlier; do
   not substitute minima.
6. Report the mean, median, nearest-rank p95, range, and the ratio of the
   baseline mean to the candidate mean, with production validation,
   ownership, and quotas enabled and the normal path selected. There is no
   numeric acceptance threshold (Q1); report the ratio next to the
   prototype's 10.09x and explain any clear shortfall.
7. Run 10 pairs each for LLVM/Clang and for Rush. Also validate a normal
   local compile and run, concurrent launches, memory use, and boot
   behavior. Require correct output and investigate regressions. Note that
   Rush is already resident from boot, so its numbers are not a cold-start
   result.
8. Archive the final source and configuration, build hashes, raw output,
   failures, and summary. Stop after reporting the result. Any larger
   redesign, boot-time work, or external or runtime ABI change beyond the
   mlibc change in section 9 needs a discussion first.

#### 8. Background and deferred work

The approach follows Linux's
[file-backed ELF mappings](https://github.com/torvalds/linux/blob/v6.18/fs/binfmt_elf.c)
and [read-ahead](https://docs.kernel.org/core-api/mm-api.html#readahead),
with filesystem I/O in sys-io and the mapping and protection mechanics in
the kernel.

The earlier prepared-image prototype reached **20.0x** after an explicit
preparation step. Its design, patches, and results are kept in the
archive's [section 5](spawn-optimization-prototype.md#5-the-earlier-warm-prototype-2026-10-01)
and Appendix B for later work on repeated launches. That warm-cache
result is not an implementation step here and does not substitute for
the cold-spawn goal.

#### 9. Design decisions

Decisions 1, 2a, and 3 are still open; recommendations follow, and the
matching review questions in section 10 refine them. Decision 2b is
settled. The Linux references use v6.18 and x86-64 glibc 2.42. A
recommendation here separates what Linux does from what is proposed for
Motor; none of it is a validated implementation result.

##### 1. Executable file lifetime (open; refined by Q8)

**Recommendation: keep the file object alive and exclude conflicting
writes with an execution lease.** Do not introduce general filesystem
versioning for this work.

Linux precedent: `execve` denies write access before it reads the image.
The inode's write and execution counts reject conflicting writers with
`ETXTBSY`, and the process keeps a reference to its executable. See
[exec opening][linux-exec], [write exclusion][linux-write], and
[executable ownership][linux-exe-owner]. Removing or replacing the name is
separate: [unlink][linux-unlink] keeps an open file alive, and
[rename][linux-rename] leaves existing open references attached to the
original object.

Proposed Motor contract: acquire the lease together with the file
authorization, before the first ELF read. Fail with a busy error if a
writable handle or a conflicting mutation already exists. While the lease
is held, reject new writable opens and every byte or size mutation,
including truncation and writes through any alias. No filesystem-wide
lock is needed.

Allow unlink and rename or replacement under the normal namespace rules.
Running children keep the old object; new launches resolve the new name.
Reclaim storage and reuse the identity only after the last reference is
gone. Tie the lease to the child's mapping and session, not to the
launcher's descriptor, and retire it only when no mapping and no
outstanding read needs the backing any more.

Capture read and execute authorization when the session is created. A
later chmod affects future opens and launches, not a mapping that is
already authorized. Page faults run under the session's authority; they
do not reopen the path and do not re-authorize each page. This adopts
Linux's open-file and mapping model for Motor's own role system; it does
not copy Linux's permission bits or its optional filesystem cases.

Acceptance checks: a writer blocks exec; exec blocks a later writer;
rename, unlink, and launcher exit leave a running child intact; a later
launch sees the replacement bytes; chmod blocks later unauthorized
launches; the final retirement releases the lease and any unlinked
storage.

##### 2a. Relocation ordering (open; decided by Q2)

Linux precedent: the kernel [maps ELF segments][linux-elf]. In the normal
glibc path, user space processes relative relocations at startup, and a
static PIE [relocates itself][glibc-static-pie]. glibc's
[relocation loop][glibc-relocations] walks the relative prefix of the
table without requiring the targets to be sorted. Lazy PLT binding is a
different mechanism from deferring relative data relocations to page
faults. Linux therefore gives no justification for assuming sorted
targets.

If Q2 selects packed relocations, the ordering question disappears and
the rules below apply to the in-memory `DT_RELR` table. Whichever option
Q2 selects, these rules hold. The pager publishes a
destination page only after every relocation that overlaps it has been
applied, including one that starts up to seven bytes before the page. It
never modifies the file. It bounds every destination to the child's
writable segments. Tables outside the supported form take the eager path.
Do not infer order from `DT_RELACOUNT`, do not sample a few records as a
proof of order, and do not require a linker change. Validation, whatever
its extent, runs inside the cold timing; it is not an offline preparation
step.

Acceptance checks: eager and paged images produce the same values,
including boundary-crossing relocations and constructors; unsupported
layouts take the eager path; the validation cost is recorded.

##### 2b. Runtime handoff (decided 2026-10-03: option (d))

**Decision: Motor's mlibc no longer walks the executable's relocation
table at startup, because Motor's loaders always apply relative
relocations before the program's first instruction runs.** The binaries
in the developer image are relinked against the changed mlibc. The pager
does not rewrite dynamic tags.

###### The problem

Every Motor loader applies an executable's relative relocations before
the program starts. The kernel loader does it for sys-io, `load.rs` in
rt.vdso does it for the vDSO it installs in each child, and
`rt_process.rs` in rt.vdso does it for executables. After this plan, the
pager does it for each writable page before publishing that page. The
eager loader rejects every relocation type other than `R_X86_64_RELATIVE`
and `R_X86_64_NONE`, and the pager accepts only tables whose
`DT_RELACOUNT` equals the entry count, so the loaders own the complete
relocation of a Motor executable. The load bias is 0.

mlibc does not know this. A program linked through the Motor Clang driver
gets mlibc's `crt1.o`, whose strong `motor_start` replaces the weak one in
Rust std. It enters `__mlibc_entry` and then `__dlapi_enter` in mlibc's
static rtld, which registers the executable as an object and links it.
`Loader::linkObjects` in `options/rtld/generic/linker.cpp` then walks the
executable's relocation table twice:

- `_processStaticRelocations` reads every record of `DT_RELA` /
  `DT_RELASZ` and stores base plus addend for each relative entry.
- `processLateRelocations` reads every record again and acts only on copy
  and IFUNC entries, of which a Motor binary has none.

The `relocateSelf` function in `main.cpp` is not involved: only the
`_start` of the dynamic-linker DSO calls it, and Motor binaries enter at
`motor_start` (`-e motor_start` in the rustc target spec). mlibc ignores
`DT_RELACOUNT`. Programs linked only against Rust std never enter mlibc
and do no relocation work of their own.

With the load bias at 0, the repeated stores write the values the loader
already wrote, so they are harmless. They are not free. Both walks read
the whole table, 3.4 MiB with 146,639 records for rustc, and the stores
touch every page that holds a relocation, which is every page of the
RELRO region. Under demand paging that pulled about 2.9 MB of writable
data through the pager before `main` ran; with the walks suppressed, a
`rustc --version` run touched 0.11 MB and 31 of roughly 859 writable
pages. In the profiled run, all pager relocation work took about 3.2 ms
of 43 ms, against 16.8 ms of text faults. The prototype suppressed the
walks by storing zero into `DT_RELASZ` and `DT_RELACOUNT` in the child's
private copy of the dynamic section, which mlibc reads as an empty table.

###### The change

The knowledge that the loader has already relocated the executable moves
into Motor's mlibc, where it is a fact about the platform rather than a
per-launch message. Two forms exist; Q2b chooses between them.

Form A, a guarded skip (recommended). The generic rtld already includes
the sysdeps header through `mlibc/all-sysdeps.hpp`, so
`sysdeps/motor/include/mlibc/sysdeps.hpp` can define
`MLIBC_LOADER_RELOCATES_EXECUTABLE`. In `Loader::linkObjects`, the calls
to `_processStaticRelocations` and `processLateRelocations` are skipped
when that macro is defined and `object->isMainObject` is set.
`_processLazyRelocations` is left alone: a Motor static PIE has no
`DT_JMPREL` table, and a binary that had one would already be rejected by
the loaders. Any other object is still linked as before. The divergence
from upstream is one define in a Motor-only header and two guarded calls
in one generic file.

Form B, a tag rewrite in `crt1.c` (fallback with no generic divergence).
Before calling `__mlibc_entry`, `motor_start` finds `DT_RELASZ` and
`DT_RELACOUNT` in `_DYNAMIC` and stores zero into them; mlibc then sees
an empty table exactly as it did with the prototype. The section is
writable at that point because nothing has applied RELRO protection yet.
This is the prototype's rewrite moved into the binary, and the running
process's dynamic section misreports its table.

###### Why it is correct

The correctness of a Motor binary never depended on mlibc's walks: they
only repeated stores the loader had already made. Removing them changes no
byte of the process image. A binary linked before the change keeps its
walks and stays correct; under the pager it reads the whole table and
faults every relocated page, so it starts more slowly until it is
relinked. Rust-only binaries have no walk and are unaffected either way.
Because the change lives in the sysroot, every program linked against the
new mlibc gets it, and no component of the OS needs to know anything
about any particular binary.

###### What it means for the rest of the plan

- The pager never rewrites dynamic tags. Step 8c drops the prototype's
  `consumed` logic and the validation of its two tag addresses. The
  child's in-memory dynamic section stays identical to the file's.
- The guarantee "Motor loaders apply every relative relocation before
  entry" becomes a documented part of the Motor ABI. Record it in `docs/`
  together with the mlibc change, so that a future loader change, for
  example a nonzero load bias with runtime relocation, is known to require
  relinking every mlibc-linked binary.
- The benchmark target changes. Section 7 runs the relinked rustc on both
  sides of the final comparison and records its new hash.
- The change is in `../toolchain-src/mlibc`, an external repository. Say
  so explicitly in every conversation, design note, and commit message
  that touches it.

###### Rollout and verification (Step 8c)

Change mlibc, rebuild the sysroot, relink every binary in the developer
image that links mlibc (rustc, LLVM and Clang, and whatever else the image
builds against mlibc), and record the hashes. Verify three things: a C
program compiled with the in-image Clang runs under both the eager and
the paged loader; the writable-fault count for `rustc --version` is close
to the prototype's 31 rather than the roughly 859 writable pages; and
`readelf -d` on the installed binaries shows the on-disk tags unchanged.

###### Alternatives considered

- (p) The prototype's OS-side tag rewrite. It works for binaries that
  have not been relinked, but it makes the pager validate and patch two
  words in the child's dynamic section and leaves the process
  misreporting its table. Rejected because relinking is in scope and (d)
  needs no OS-side work at all.
- (c) A runtime signal: the loader records "already relocated" at a fixed
  address and mlibc checks it. This needs a new moto-rt ABI field, loader
  support on both paths, and the same mlibc change plus a check. The OS
  never makes a different decision, so the signal would carry a constant.
  Rejected.
- (e) A minimal loader pass followed by self-relocation in the child. A
  runtime walk is eager by nature: it must store into every target before
  `main`, which under demand paging means every writable page and the
  whole table, the 2.9 MB the handoff removes. The child cannot relocate
  lazily, because Motor delivers faults to the pager, not to the faulting
  process, and giving user code its own fault handling would be a far
  larger kernel, moto-rt, and toolchain feature that would still read the
  same bytes. Rejected.

###### Risks

A binary that is not relinked keeps the old behavior: correct, but slower
under the pager. A future loader that stops relocating before entry would
need every mlibc-linked binary relinked; the documented guarantee exists
to make that visible. The fork divergence is small but must be carried
across upstream merges of mlibc.

##### 3. Limits and failure behavior (open)

**Recommendation: reuse Motor's admission and service budgets, bound the
new pager state, and contain a fatal demand fault to the affected child.**
Keep physical allocation lazy without promising that every future fault
will succeed.

Linux precedent: [virtual-address limits][linux-mmap] and
[mapping-count limits][linux-vm] are separate from resident memory. Its
[overcommit accounting][linux-overcommit] treats read-only file mappings
differently from private writable commitments, and actual memory use can
be limited with [memory cgroups][linux-cgroup]. These are configurable
policies, not a set of numbers to copy into Motor.

Proposed accounting: keep the existing address-range, oversized-image, and
admission checks. Charge mapping and request metadata when they are
created and physical growth when a fault needs backing. Attribute pager
work caused by a client to that client's admission class, even though
sys-io performs it. Count shared physical backing once globally while
accounting each process's mapping metadata and private pages. Charge
retained cache and DMA ownership as well; pinning must not hide memory
from pressure accounting.

Reuse `kernel/src/mm/admission.rs` and sys-io's channel budgets. Keep
their current user and service reserve floors. Do not allocate the full
executable up front and do not add Linux-style overcommit or OOM
configuration in this series. The existing eager and oversized-image
error behavior remains the compatibility constraint for reservation
admission.

Proposed initial work bounds: one coalesced demand request per missing
page, at most one fault waiter per blocked thread, and one speculative
batch of at most 64 pages in flight per session. Keep the measured
32-page demand window and the 16-page file-run bound. These are Motor
starting policies, not Linux constants and not measured results for this
revised policy. Enforce aggregate session, request, and pin admission as
well; batch limits alone do not bound the memory retained by long-lived
or concurrent children.

Under pressure, stop admitting speculation and release speculative
ownership that is no longer needed. Do not free DMA buffers that are
still in flight or frames that are still mapped into children. Keep
retire, cancel, and completion operations available under pressure so
that cleanup cannot deadlock behind admission.

Linux distinguishes fault causes: a [file-backed fault][linux-filemap] can
return `VM_FAULT_SIGBUS`, and the [x86 fault handler][linux-fault]
delivers a signal or invokes OOM handling. Linux does not always select
the faulting process as the OOM victim.

Proposed Motor failure policy: before the child runs, roll back and return
the real spawn error. After it runs, a fatal demand read error, an
unexpected EOF, or a refused demand allocation terminates that child with
an observable failure reason, wakes or fails its waiters, and retires its
sessions. Do not panic sys-io, do not kill unrelated processes to satisfy
the fault, and do not leave the child blocked forever. This is
deliberately simpler than Linux's general OOM policy. A refused
speculative allocation only drops the prediction; demand loading still
decides whether the program can continue.

Acceptance checks: exhausted budgets fail without leaking, cancellation
works under pressure, same-page faults coalesce, unrelated processes and
sys-io stay usable after a child fails, and every resource charge returns
after teardown. Measure CPU time, retained memory, and the cold speedup
with these limits enabled before choosing the final numeric quotas.

#### 10. Review questions (2026-10-03)

These came out of the 2026-10-03 readiness review of this plan against
the tree at `6ef7737b` and the archived prototype. Each entry records
what was verified, the options, and a recommendation. Write the ruling
after **Decision** and fold it into the affected step before that step
starts. Q3 and Q5 block Step 0; Q2 and Q2b block Step 8; Q4 blocks Step
4; Q6 blocks the first commit; Q7 blocks Step 7; Q8 refines decision 1
for Step 1a. Q1 and Q2a are decided.

##### Q1. Is 10x a hard acceptance gate or a target?

Context: the prototype mean is 37.109 ms against a 374.542 ms baseline. A
ratio of 10.0 allows 37.454 ms, so the margin is 0.345 ms: under 1% of the
run and far smaller than the prototype's own spread (32.725–42.848 ms).
Production adds work the prototype skipped: relocation validation (Q2),
the execution lease, admission charges, and quota checks.

Options:

- (a) Hard gate at 10.0 with every production check enabled; a shortfall
  means more optimization before acceptance.
- (b) 10x stays the target; a lower hard floor (for example 8.0, near the
  measured Clang ratio) is the gate, with the rule that no production
  check may be removed to reach either number.
- (c) No numeric gate; accept on correctness and report the ratio.

Recommendation: (b). The margin makes (a) likely to fail at Step 8 for
reasons unrelated to implementation quality.

**Decision:** C - no numeric gate.

##### Q2. Relocation ordering policy (refines decision 2a)

Context: the pager finds a page's relocations by binary search over the
on-disk table, which is correct only when the table is sorted by
destination. rustc's table has 146,639 records in 3.4 MiB; reading all of
it inside the launch costs several milliseconds of cold I/O on a 37 ms
run. Option (c) removes the search instead of validating it. The
runtime handoff is a separate mechanism, settled in Q2a.

Memory safety does not depend on table order: the pager bounds-checks
each destination against the child's writable segments, fills only its
own session's pages, and never modifies the file. An unsorted or
malicious table can at most cause missed writes inside the launched
process, which is that process's own memory. lld sorts relative
relocations by offset (`computeRels` in `SyntheticSections.cpp`); GNU ld
does the same under the default `-z combreloc`. That is linker behavior,
not an ELF guarantee. The prototype already requires `DT_RELAENT == 24`,
`DT_RELACOUNT == DT_RELASZ / 24`, the table inside one segment, and no
`DT_REL`, `DT_JMPREL`, or `DT_RELR`; each search probe must stay inside
the bracket set by earlier probes, and each forward run must be monotone.

Options:

- (a) Read and validate the whole table once per launch. Complete
  fidelity with the eager loader for every input; costs the cold read and
  the walk on every launch.
- (b) Keep the prototype's checks: bounds-check every record read, verify
  monotonicity across every record and every probe touched, fail the
  child on the first violation, and take the eager path for anything the
  tag checks reject. Fidelity holds for every table a Motor linker
  produces; a hand-built unsorted table yields a wrong but contained
  child instead of an eager-equivalent one.

- (c) Packed relative relocations. Link user binaries with
  `-z pack-relative-relocs`, so the table is a `DT_RELR` bitmap instead of
  24-byte records. Measured on the actual rustc ELF: `.rela.dyn` is
  3,519,336 bytes with 146,639 records; the same relocations encoded as
  `DT_RELR` come to about 45 KB. The pager reads the whole table at launch
  in one small I/O, keeps it in memory, and scans it on every writable
  fault; 31 faults over 45 KB is well under a millisecond of memory
  scanning, and the result is correct for any record order. The binary
  search, bracket checks, prefetch tree, and interpolation probes go
  away, which removes most of P6 and all of Step 15a. `DT_RELR` is in the
  generic ABI; lld emits it, glibc 2.36 and later consume it, and mlibc's
  walks already understand it (and are skipped under decision 2b). Costs:
  a link flag for user binaries, either in the Motor Clang driver or as
  one line in the rustc target spec; RELR support in the Step 6 loader for
  both its paged and its eager mode, because the forked elfloader does not
  know RELR; a per-crate flag that keeps sys-io and rt.vdso on `.rela.dyn`
  so the kernel loader and the vDSO loaders stay untouched; and a relink,
  which Step 8c performs anyway. Binaries that still carry a RELA table
  take the eager path, correct and at today's speed, so a compliant
  binary never fails and no ordering contract exists anywhere.

Recommendation: (c). It is the only option with both a fast happy path
and correct loading of every standard-compliant binary, and it makes the
pager simpler. If the toolchain-side changes are not wanted, (b) as a
documented Motor loader contract: ordered, relative-only tables are
supported; anything else is valid but not supported by the pager.

**Decision:**

##### Q2a. Runtime handoff mechanism (refines decision 2b)

Context: mlibc-linked programs walk their whole relocation table at
startup, which under demand paging faults every relocated page. The
options were (p) the prototype's OS-side tag rewrite, (c) a runtime
signal from the loader, and (d) a build-time change to Motor's mlibc.
Relinking existing binaries is in scope.

**Decision (2026-10-03): (d).** The full design is in section 9, decision
2b. Q2b chooses its form.

##### Q2b. Form of the mlibc change (refines Q2a)

Context: option (d) can be implemented in two ways, described in section
8, decision 2b. Both suppress the two table walks; they differ in where
the change lives and in what the running process's dynamic section
reports.

Options:

- (A) Guarded skip: a define in the Motor-only sysdeps header and two
  guarded calls in `options/rtld/generic/linker.cpp`. The dynamic section
  stays truthful. Divergence from upstream mlibc: a few lines in one
  generic file.
- (B) Tag rewrite in `sysdeps/motor/crt-src/crt1.c`: `motor_start` zeroes
  `DT_RELASZ` and `DT_RELACOUNT` in `_DYNAMIC` before entering mlibc. No
  generic file changes. The dynamic section misreports its table, as it
  did under the prototype.

Recommendation: (A). The divergence is small and explicit, and the
process keeps an honest view of itself.

**Decision:**

##### Q3. Disposition of the fsync/datasync fix and the baseline tree

Context: `src/sys/lib/rt.vdso/src/rt_fs.rs` in the working tree turns
`fsync` and `datasync` from no-ops into calls to `posix_flush`; it is
byte-identical to the archived `fsync-flush.patch`. It is uncommitted,
and the archive records that no test suite ran on it. It changes every
program that calls `sync_all` or `sync_data`, affects durability and
latency independently of spawn, and is a `src/sys` change that AGENTS.md
gates with three debug and three release full-test runs. The leftover
`src/sys/kernel/src/mm/virt_intrusive.rs.orig` is a prototype copy (it
contains `IMAGE_SPARSE`), not HEAD.

Options:

- (a) Commit the fix first as its own patch with a systest check (write,
  sync, read back through a fresh handle; the reboot durability check
  stays manual), gated per AGENTS.md. Delete the `.orig` file. Step 0 then
  baselines HEAD.
- (b) Carry it uncommitted and build it into both sides of the Step 0
  baseline.
- (c) Revert it and treat durability as separate work.

Recommendation: (a). Step 0 and the final comparison both assume the fix
is present on both sides, and a committed, gated fix is the only form of
that assumption that survives a second machine.

**Decision:**

##### Q4. The eager populate operation

Context: the 2026-10-01 request included a SysMem operation that loads
lazy pages eagerly, and the earlier design listed an "explicit
pressure/populate contract". This rewrite has no such operation: the only
eager fills are the Step 16a policy (complete read-only pages below
1 MiB) and the resident-vDSO run fill in Step 10c. Under decision 3 a
fatal demand failure kills the child, so a process has no way to take
that risk up front for a critical region.

Options:

- (a) Drop it.
- (b) Add it as Step 4d: a kernel pager operation that enqueues demand
  requests for a range of one file-backed mapping and waits, returning
  errors instead of terminating the child; exposed through moto-sys only,
  with no moto-rt change. Tests gain a deterministic way to drive the
  pager.
- (c) Defer it to a follow-up plan after Step 16.

Recommendation: (b). Step 4 builds everything it needs, the patch is
small, and the test value arrives while the pager is new.

**Decision:**

##### Q5. When to fix the malformed-ELF spawner panic

Context: reproduced on 2026-10-01 and still present. An `e_phoff` beyond
the end of the file panics in elfloader's program-header slice
(`src/third_party/elfloader/src/elf_impl/program.rs`); a relocation
outside every segment hits the assert at `rt_process.rs:304`. The panic
is in the launcher's vDSO, so the launching process dies (exit
`0xbadc0de`); for a shell, that is the shell. Step 6 removes it on the
paged path and must guard the eager fallback, but the eager loader stays
reachable until Step 6 lands, and elfloader is forked third-party code.

Options:

- (a) A standalone pre-check patch now in `rt_process.rs` (header,
  program-header, and relocation-destination bounds before elfloader
  runs) with systest fixtures, gated and committed before Step 0. The
  fixtures become Step 1c's first cases.
- (b) Fix it only inside Step 6.
- (c) Fix elfloader itself (a fork change; must be called out
  explicitly).

Recommendation: (a). It is small, removes a shell-killing bug now, and
Step 6 inherits the tests.

**Decision:**

##### Q6. Commit and gate granularity

Context: sixteen steps of about three lettered patches each is roughly 45
patches of 100–300 lines, nearly all under `src/sys`. AGENTS.md requires
three debug and three release full-test runs before each commit, plus the
release developer-image run. Section 4 says not to commit unless asked.

Options:

- (a) Gate and commit each lettered patch (about 45 gated commits).
- (b) Review lettered patches individually; gate and commit once per step
  (about 16 larger commits).
- (c) Keep one commit per lettered patch but run the gate once per step on
  the step's final state. Intermediate commits build and pass targeted
  tests but are not individually full-gated. This is an explicit override
  of the AGENTS.md per-commit rule and needs your authorization.

Recommendation: (c). It keeps commits small and bisectable while cutting
gate runs to one set per milestone; regressions are still caught at step
granularity before anything lands.

**Decision:**

##### Q7. Development selector mechanism (Step 7a)

Context: the prototype's launcher vDSO reads `MOTOR_SPAWN_PROTO` from the
child's environment list and selects the mode and window from it. Step
7a wants a development-only selector that grants no authority, and Step
16b removes scratch modes. An environment key is visible to the child and
inherited by its descendants. A spawn flag would need a moto-rt change,
which section 1 excludes. A build-time `cfg` needs two images for an A/B
comparison, which Step 16 wants to run in one image.

Options:

- (a) One documented environment key, read by the launcher only, honored
  only for path selection (eager versus paged), never for limits or
  checks.
- (b) A build-time `cfg` feature; comparison requires two images.
- (c) A moto-rt spawn flag; out of scope under section 1.

Recommendation: (a), with Step 16b deciding whether it survives.

**Decision:**

##### Q8. In-place overwrite of a running executable (refines decision 1)

Context: the recommended lease rejects writable opens and byte or size
mutations while any mapping of the file exists, like Linux `ETXTBSY`.
Consequences: a tool that truncates a running binary in place (for
example `fs::copy` onto it) fails with busy; a tool that writes a
temporary file and renames succeeds; a process merely holding a writable
handle open on the file blocks exec until it closes. The existing lock
machinery (`CMD_FILE_LOCK`, `on_cmd_file_lock` in
`sys-io/src/runtime/fs.rs`) is advisory and does not stop writes through
other handles, so the lease needs its own mandatory check on the write,
truncate, and open-for-write paths, keyed by `EntryId`.

Options:

- (a) Any writable open handle blocks exec, and exec blocks any later
  writable open (Linux semantics; the simplest state).
- (b) Only an in-progress write or truncate blocks exec; existing writable
  handles stay open and receive busy on their next mutation (friendlier
  to copy-then-run sequences; handle state transitions add complexity).

Recommendation: (a).

**Decision:**

[linux-exec]:
  https://github.com/torvalds/linux/blob/v6.18/fs/exec.c
[linux-write]:
  https://github.com/torvalds/linux/blob/v6.18/include/linux/fs.h
[linux-exe-owner]:
  https://github.com/torvalds/linux/blob/v6.18/kernel/fork.c
[linux-unlink]:
  https://man7.org/linux/man-pages/man2/unlink.2.html
[linux-rename]:
  https://man7.org/linux/man-pages/man2/rename.2.html
[linux-elf]:
  https://github.com/torvalds/linux/blob/v6.18/fs/binfmt_elf.c
[glibc-static-pie]:
  https://github.com/bminor/glibc/blob/glibc-2.42/elf/dl-reloc-static-pie.c
[glibc-relocations]:
  https://github.com/bminor/glibc/blob/glibc-2.42/elf/do-rel.h
[linux-mmap]:
  https://github.com/torvalds/linux/blob/v6.18/mm/mmap.c
[linux-vm]:
  https://docs.kernel.org/admin-guide/sysctl/vm.html#max-map-count
[linux-overcommit]:
  https://docs.kernel.org/mm/overcommit-accounting.html
[linux-cgroup]:
  https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files
[linux-filemap]:
  https://github.com/torvalds/linux/blob/v6.18/mm/filemap.c
[linux-fault]:
  https://github.com/torvalds/linux/blob/v6.18/arch/x86/mm/fault.c
