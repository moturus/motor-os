# Boot time

2026-09-01. Findings, a plan, and suggested launcher changes. The trace
method and the raw numbers are in `docs/boot-trace-2026-09-01.md`.

Scope: the release image on cloud-hypervisor (the user's launcher),
Firecracker, and QEMU, from the first guest instruction to sys-tty's
"most services up" line, plus the VMM's own time before the first guest
instruction, which the kernel's "kernel up at" stamp silently includes.

Provenance. Measured on the host used for all Motor OS work here, which is
itself a KVM guest with nested virtualization (24 vCPUs reporting an
i7-14700). A port I/O or MMIO exit costs ~14 us, the first guest access to
a page ~10 us if the VMM wrote it earlier (the initrd) and ~15 us for a
fresh page. On bare metal both are several times cheaper, so the absolute
savings shrink, but the ranking of the items should hold.

## What is committed (same day)

| step | commit | effect on cloud-hypervisor |
|---|---|---|
| PCI scan: bus 0 plus bridges instead of 256 buses | 60a4997e | userspace phase 297-329 -> 67-69 ms |
| vdso shared into children instead of copied | fcfbec98 | 67 -> 55 ms; 11 MB less guest RAM |
| sys-io text and rodata mapped from the kernel's copy, not copied | feea1c12 | 55 -> 48 ms |
| 2 MB MMIO page not zeroed by the kernel | 78953342 | runtime::init 5-6 ms -> 0 |
| sys-tty spawned before strobe; immediate retries | 0ef1e2a5 | console line 43-49 -> 37-40 ms |
| sys-io mapped from the initrd instead of copied (kernel item 1) | 78e8042b | kernel 19-21 -> 5-7 ms; see below |
| hugepage backing in the launcher scripts | 16d65919 | pool used when present; see the hugepage section |
| the VMM places the kernel (kernel item 2) | uncommitted, 63 lines | kloader 9-14 -> 2.5-6 ms on cloud-hypervisor, 7-7.6 -> 2.4-3.2 on Firecracker |

The userspace phase ("kernel up" to the console line) is now 35-37 ms on
cloud-hypervisor and Firecracker. What remains there is in the plan below
(items 10-12).

## Kernel item 1 done: sys-io is mapped from the initrd (same day, later)

`copy_sys_io` is replaced by `place_sys_io` (`src/sys/kernel/src/init.rs`).
When the initrd lies above the kernel and therefore stays reserved in the
physical allocator (cloud-hypervisor, Firecracker, QEMU `-kernel`), the
591 initrd pages holding sys-io are adopted as frames of a read-only
kernel-static segment (`phys::adopt_frame`,
`VmemRegion::map_reserved_pages`), and the ELF loader's existing in-place
path maps text and rodata from it; only the 12-page RW segment is copied.
Below the kernel (the BIOS path frees the initrd at stage 2) the old copy
runs. Nothing is read or zeroed up front: the mapping costs 0.03-0.5 ms.

Same-sitting A/B, copy path forced against the mapping, console stamps
("kernel up at" and "most services up at", both from TSC zero); the first
boot after each rebuild is excluded:

| launcher | variant | kernel | "kernel up" | console line | userspace phase |
|---|---|---|---|---|---|
| cloud-hypervisor (3 runs) | copy | 18.6-20.8 | 43-50 | 81-88 | 36-38 |
| cloud-hypervisor (3 runs) | map | 5.2-7.0 | 28-39 | 72-86 | 42-47 |
| Firecracker | copy | 19.0-22.5 | 30-40 | 72-100 | 42-60 |
| Firecracker | map | 4.7-6.8 | 18-26 | 71-76 | 50-53 |
| QEMU `-kernel` | copy | 71.8 | 185 | 243 | 58 |
| QEMU `-kernel` | map | 15.4 | 106 | 213 | 107 |

The kernel phase loses 13-15 ms on cloud-hypervisor and Firecracker (and
56 ms on QEMU, where the copy's scattered frames were hugepage faults),
but 6-11 ms of it comes back in the userspace phase: sys-io now takes the
first-access fault on each initrd page as it executes it, instead of the
kernel taking all 591 up front, and at boot it touches most of them. Net,
the console line moves 5-8 ms earlier on cloud-hypervisor (guest side,
64 -> 57-59 ms) and 0-6 ms on Firecracker; on QEMU the faults cost far
more in userspace than the kernel saved (QEMU is the launcher the item
matters least for, and its first-touch cost on this host is a hugepage
artifact, see item 7). On bare metal a first access costs a microsecond
rather than ten, so the shift shrinks with the saving.

Follow-up if the shift matters: have an idle AP read through the sys-io
pages while the BSP finishes its init (the APs spin in `sched::start`
waiting for the BSP from ~0.3 ms after memory init), so the faults are
taken off the critical path instead of moved along it. About 15 lines.

Validation: `full-test.sh --release` twice, 668 legs each, all passed.
Over ssh the services list and `/user` read back as before.

## Kernel item 2 done: the VMM places the kernel (2026-09-02)

The kloader ELF now carries the kernel ELF as its own PT_LOAD segment at
physical 34 MB (`src/boot/x64.kloader/layout.ld`, `.kernel_image`; the
bytes come from `include_bytes!` of the built kernel, so `make kloader`
depends on `kernel`). Every PVH loader (cloud-hypervisor, Firecracker,
QEMU `-kernel`) writes the segment there while loading the kloader, at
host speed. The kloader checks for the ELF magic at 34 MB: present, it
parses the headers in place and its `load` callback skips the copy when
source and destination coincide (the kernel's single segment has file
offset 0 at virtual address 0, so the file layout is the memory layout);
absent, as on the BIOS path where `kloader.bin` runs and the RAM is
untouched, it copies from the initrd as before. Relocations are applied
in place either way.

`kloader.bin` (the flat image inside the initrd) is made from the ELF's
allocated sections except `.kernel_image`; a removed section's segment
would otherwise pad the flat image out to 34 MB. Two details in
`layout.ld` keep the sizes right: the `.eh_frame*` and `.got` sections
are placed explicitly, before `.data`, so nothing is placed after the kernel
image and no read-only section sits right before it (lld would put both
in one segment and write the 33 MB gap into the file). `build.sh` fails
if either file grows past that.

Same-sitting A/B, copy path forced against in place, TSC cycles from the
kloader's entry to the jump into the kernel, at 2112 MHz:

| launcher | copy | in place |
|---|---|---|
| cloud-hypervisor (4 runs) | 8.9-13.8 ms | 2.5-6.2 ms |
| Firecracker (2 runs) | 7.1-7.6 ms | 2.4-3.2 ms |

What is left in the kloader is the AP start (item 3) and the ACPI parse.
The kloader ELF is 520 KB instead of 77 KB; the initrd is unchanged (the
BIOS path still needs the kernel in it). All four boot paths were booted
to the console after the change: cloud-hypervisor, Firecracker, QEMU
`-kernel`, and QEMU through the BIOS and MBR loader from the disk image.

Validation: `full-test.sh --release` twice, 668 legs each, all passed.

## Where the time goes now

Guest time is split at the kloader's Rust entry (`bsp_start`) and at the
kernel's entry (`_start`). "Pre-guest" is from TSC zero (vCPU creation) to
the kloader entry: the VMM's own work, opening the disk image, loading the
initrd, building ACPI tables. "Wall" is from `exec` of the VMM to the
"kernel up" line appearing on the host.

| launcher | pre-guest | kloader | kernel | user | wall to "kernel up" |
|---|---|---|---|---|---|
| cloud-hypervisor, qcow2, warm page cache (4 runs) | 13.5-20.8 | 5.2-9.7 | 18.9-20.4 | 34.6-36.5 | 49-59 |
| cloud-hypervisor, qcow2, first boot after rebuild | 43 | 8.5 | 20.5 | 33 | 86 |
| cloud-hypervisor, qcow2, page cache dropped | 22.9 | 13.8 | 21.9 | 36.8 | 71 |
| cloud-hypervisor, raw image (2 runs) | 4.8-9.1 | 5.5-12.2 | 19.6-21.3 | 35.6-36.3 | 37-54 |
| cloud-hypervisor, qcow2, 8 GB RAM | 21.3 | 12.2 | 23.4 | 46.6 | 73 |
| Firecracker, raw image (2 runs) | 6.6-7.0 | 11.5-12.2 | 20.6-21.0 | 31.7-66.8 | 45-46 |
| QEMU, BIOS + MBR loader | 332.7 | 1.8 | 68.7 | 52.1 | 436 |
| QEMU, `-kernel kloader -initrd initrd` (4 runs) | 91-99 | 1.9-2.3 | 69-72 | 52-54 | 203 |

All in milliseconds. The "kernel up at NNN ms" line counts from TSC zero,
so it is pre-guest plus kloader plus kernel: the VMM's disk-image open and
initrd load are inside it. On cloud-hypervisor with a qcow2 image the
pre-guest part is 14-21 ms warm and 43 ms right after the image is
rewritten (the qcow2 open with the io_uring backend alone took 32 ms in
that run); a raw image cuts it to 5-9 ms. This is why the stamp varied by
80 ms between runs earlier today.

Kloader plus kernel is 25-33 ms on cloud-hypervisor and Firecracker, against
32-37 ms of userspace: about half, as suspected. Of those 25-33 ms, about
25 are addressable.

### Kloader (cloud-hypervisor / Firecracker, one run each)

| ms | phase |
|---|---|
| 0.1 / 0.3 | cpuid checks |
| 0.1 / 0.2 | PVH info, 1 GB direct map, bump heap |
| 0.3 / 0.8 | ACPI: find and parse the MADT for the CPU count |
| 1.7 / 4.4 | start 3 APs, one at a time: INIT, a 10000-iteration spin, SIPI, wait for ready (0.3 / 0.9 ms per AP in the spin alone, 0.1-0.6 ms from SIPI to ready) |
| 0.1 / 0.2 | parse the kernel ELF |
| 3.0-6.5 / 6.3-6.5 | copy the kernel's segments from the initrd to 34 MB (138 pages: a fresh destination page plus an initrd source page per 4 KB) |
| 0.0 | relocations, jump |

### Kernel to "kernel up" (cloud-hypervisor / Firecracker)

| ms | phase |
|---|---|
| 0.1 | KVM clock, boot info, wait for the APs (already there) |
| 0.5 / 0.7-1.0 | `phys::init`: one 64-page descriptor per 256 KB of RAM (4096 at 1 GB; 3.0 ms at 8 GB) |
| 0.0 | `virt::init` |
| 0.6-0.7 / 0.8-1.0 | first `vmem_allocate_pages` (the GS page): slab and page-table pages, each first-touched |
| 0.3 / 0.4 | IDT, GDT, serial console object, x2APIC attach |
| 1.2-1.4 / 1.5-1.7 | `lapic_init` + `ioapic_init`: two MMIO mappings and a loop that writes both halves of all 24 redirection entries (96 MMIO exits) |
| 0.2 | syscall MSRs, serial port setup |
| 5.2-6.3 / 6.1-6.2 | `copy_sys_io`: first read of the 591 initrd pages holding sys-io |
| 9.2-9.3 / 8.6-8.9 | `copy_sys_io`: allocate, map and zero 591 kernel-static pages |
| 0.3 | `copy_sys_io`: the memcpy itself |
| 0.1 | stage 2: unmap the low 1 GB, global bits, stats, uspace init |
| 0.2 | the "MOTOR OS ..." prefix on the serial port |
| 0.1 | scheduler start, the init job |
| 0.9 | the "kernel up at" line on the serial port (66 bytes at ~14 us each) |

The three APs are done with their own init 0.3 ms after the BSP and then
idle in the scheduler loop for the whole `copy_sys_io`.

### QEMU is a different story

On QEMU the kernel takes 69-72 ms, of which 57-60 ms is the sys-io
destination allocation and 5.3-5.7 ms the first vmem allocation, with the
initrd reads at 0.0-0.2 ms. QEMU's guest RAM is hugepage-backed on this
host (`transparent_hugepage/enabled = madvise`, and QEMU asks), so the
first touch of a 2 MB region costs one host fault that allocates and zeroes
2 MB. The physical frame allocator picks a random 256 KB segment for every
allocation (`MemoryArea::do_allocate_frame`, three random tries before a
linear scan): the 591 frames for the sys-io copy were spread over 347
distinct 2 MB regions (`k: sys-io dst frames span 347 distinct 2M regions`
in the trace), so the copy triggered ~350 hugepage faults of ~170 us. The
host counters confirm it: `thp_fault_alloc` rose by 510 during one boot
with no fallbacks and no compaction stalls. On cloud-hypervisor and
Firecracker the RAM is 4 KB-backed here, so the scatter costs nothing
today, but it would cost exactly this once hugepages are enabled for them
(see the hugepage section): every fresh 4 KB frame would fault in 2 MB.

QEMU's pre-guest time is the firmware: 333 ms through the BIOS and the MBR
loader (which reads the 3 MB initrd through BIOS calls), 91-99 ms with
`-kernel kloader -initrd initrd` (SeaBIOS still runs, but the PVH ELF
loads directly). `run-qemu.sh` uses the disk path.

## Why

1. The kernel copies sys-io (2.4 MB) out of the initrd into kernel-static
   memory before starting it, because "initrd bytes are not held on to".
   The copy is 15 ms: 591 initrd pages read for the first time, 591 fresh
   pages allocated, mapped and zeroed, then the memcpy. The initrd pages
   are never released anyway (`phys::init` marks them in use and nothing
   marks them unused), so the copy buys nothing.

2. The kloader copies the kernel (441 KB, 564 KB in the trace build) from
   the initrd to 34 MB: both sides pay a first-touch per page, 22-47 us per
   4 KB. The relocations are free.

3. The APs are started one at a time with a fixed spin between INIT and
   SIPI, and the BSP waits for each before starting the next. The kernel
   later waits for them again, at a point where they have long been ready.
   On Firecracker the spin loop itself costs 0.9 ms per AP: PAUSE exits
   there.

4. `ioapic_init` masks all 24 redirection entries with two MMIO writes
   each; the entries are masked at reset on every VMM.

5. `phys::init` builds a descriptor per 64 pages, so its cost scales with
   RAM: 0.5 ms at 1 GB, 3 ms at 8 GB.

6. Serial output on the critical path: 1.1 ms of port exits for the logo
   prefix and the "kernel up" line.

7. The frame allocator's random placement defeats hugepage backing
   (QEMU today, cloud-hypervisor and Firecracker once enabled).

8. The "kernel up" stamp counts from vCPU creation, so VMM work is
   attributed to the kernel and the number moves with the host's page
   cache. `KernelBootupInfo.start_tsc` (the kloader's entry time) is
   passed to the kernel and unused.

## Plan, ordered by payoff

Kernel and kloader:

1. Done: sys-io mapped from the initrd (section above). Open: the AP
   pre-read of its pages, if the 6-11 ms shift into userspace on nested
   hosts is worth 15 lines.

2. Done: the VMM places the kernel (section above).

3. Start the APs in parallel and off the critical path (1.7-4.4 ms).
   Give each AP its own stack up front and let the trampoline read its
   CPU number from the APIC id, then send INIT to all, one wait, SIPI to
   all, and do not wait: the kernel's existing `AP_STARTED` wait in
   `start_bsp` is the join point, and by then the APs are up. Replace the
   iteration-count spin with a TSC-based delay so it costs the same on
   every VMM.

4. Program only the IOAPIC entries in use (1.2-1.7 ms): the serial IRQ
   and whatever `ioapic_enable_irq` is asked for later. If the reset state
   is not trusted, read the entries (48 exits) instead of writing them
   (96).

5. Cheaper `phys::init` (0.4 ms at 1 GB, 2.5 ms at 8 GB): bigger
   descriptors (a 512-page segment with an 8-word bitmap), or build the
   descriptor vector from the memory map arithmetically instead of one
   push per 64 pages through two passes.

6. Move the serial output off the path (1.1 ms): print the logo and the
   "kernel up" line after sys-io has been started, or from the scheduler
   loop; print less.

7. Sequential frame placement (prerequisite for hugepages anywhere; ~55 ms
   in the kernel alone on QEMU today). Keep a cursor to the last segment
   with free pages and advance it; if the random pick exists for lock
   spreading, use per-CPU cursors instead of a random segment per
   allocation. This also makes the userspace first-touch items shrink
   under hugepages, which the earlier QEMU numbers already showed.

8. Report boot time from the kloader entry (no speedup, correct
   attribution): use `KernelBootupInfo.start_tsc` for the "kernel up"
   line, or print both numbers.

9. Look inside the first `vmem_allocate_pages` (0.6-1.0 ms): how many
   slab and page-table pages it touches, and whether the slab can start
   smaller.

Userspace (unchanged from the morning plan):

10. Batch the demand-path block reads (~5 ms here, ~100 ms for russhd's
    4 MB load after the prompt). A 48 KB read becomes 12 sequential
    single-block round trips; the readahead path already issues
    scatter-gather reads of up to 16 blocks per request, so
    `on_cmd_read_multi` and motor-fs open should do the same.

11. Cheaper first filesystem use per process (~4 ms). Lazily populated
    io_channel pages, or a smaller channel, so a fresh connection does not
    first-touch 128 pages.

12. Trim the virtio capability walk (~3.5 ms). Read 32-bit words, cache
    the header, stop re-reading the vendor ID.

13. sys-io's own vdso self-load (4.9 ms) has no parent to share from; the
    kernel could map the vdso's read-only segments for the first process
    the same way item 1 maps sys-io.

| item | expected saving (cloud-hypervisor / Firecracker) |
|---|---|
| 1 sys-io mapped from the initrd | done: 13-15 ms in the kernel, 5-8 net |
| 2 kernel placed by the VMM | done: 5-8 ms |
| 3 APs in parallel, not waited for | 1.7-4.4 ms |
| 4 IOAPIC entries in use only | 1.2-1.7 ms |
| 5 phys::init | 0.4 ms (2.5 at 8 GB) |
| 6 serial off the path | 1.1 ms |
| 7 sequential placement | 0 today; 55+ ms on QEMU; enables hugepages |
| 10-13 userspace | 15-17 ms |

Items 3-6 take kloader plus kernel from the current 8-13 ms to roughly
5-8 ms.

## Launcher notes

cloud-hypervisor: a raw image saves 5-10 ms warm and ~35 ms on a first
boot (the qcow2 open with io_uring was 32 ms cold). The first boot after
`make` rewrites the image is always the slowest run; do not compare it
with the others. `vm_images/release` has raw images already
(`motor-os-base.img`); a raw `motor-os.img` could be kept next to the
qcow2.

QEMU: `-kernel vm_images/release/kloader -initrd vm_images/release/initrd`
boots through PVH and skips the MBR loader, 333 -> 91-99 ms before the
first guest instruction. The kernel-side QEMU cost is item 7.

Firecracker: `--enable-pci` is required (the base image's sys-io only
knows virtio-pci); `run-fc.sh` passes it.

## Hugepage backing: host settings and launcher changes

Do item 7 first. With random placement, hugepage backing turns every
fresh 4 KB frame into a 2 MB host fault, and the kernel's own boot gets
slower, not faster (QEMU: 69-72 ms). With sequential placement the
expected effect is what QEMU's userspace numbers showed this morning: the
first-touch items (~30 ms of the kloader+kernel+user path) drop to a few
ms, because one fault covers 512 pages.

What each launcher's guest RAM looks like on this host, from
`/proc/<pid>/smaps`:

| launcher | RAM mapping | hugepage hint (`hg`) | THP eligible | AnonHugePages |
|---|---|---|---|---|
| cloud-hypervisor v52, `thp=on` | memfd (`/memfd:ch_ram`) | yes | no | 0 |
| QEMU 8.2 | anonymous | yes | yes | 1 GiB |
| Firecracker 1.15 | anonymous | no | no | 0 |

Host settings (all need root; persist through `/etc/sysctl.d` and a boot
script for the sysfs switches):

```
# Anonymous memory (QEMU always; Firecracker only with "always", it does not
# ask for THP). This host is on "madvise".
echo madvise > /sys/kernel/mm/transparent_hugepage/enabled

# cloud-hypervisor's RAM is a memfd, so shared-memory THP applies, which has
# its own switch. This host is on "never", which is why thp=on had no effect.
echo advise > /sys/kernel/mm/transparent_hugepage/shmem_enabled

# A hugetlbfs pool for hugepages=on (chv), memory-backend-file (QEMU), and
# huge_pages=2M (Firecracker): 2 MiB pages, 512 per GiB. run-dev.sh uses
# 8 GiB. /dev/hugepages is already mounted with pagesize=2M here.
sysctl vm.nr_hugepages=512
```

Launcher scripts (`src/vm_scripts/`, copied into `vm_images/`), changed
2026-09-01: `run-chv.sh` and `run-qemu.sh` use the hugetlbfs pool on their
own when `/proc/meminfo` shows enough free pages for the guest's RAM
(`HugePages_Free` against `MOTO_MEMORY_MIB`; QEMU also needs a hugetlbfs
mount, `/dev/hugepages` here). cloud-hypervisor gets
`hugepages=on,prefault=on`, QEMU `-mem-path <mount> -mem-prealloc`. Without
a pool, cloud-hypervisor gets `thp=on` (its default, spelled out because it
depends on `shmem_enabled`) and QEMU its default anonymous RAM. Each script
prints the choice on stderr. `MOTO_HUGEPAGES=0` skips the pool.
`run-dev.sh` inherits this; its 8192 MiB need 4096 pages of 2 MiB.
`run-fc.sh` is unchanged: Firecracker takes `"huge_pages": "2M"` in
`machine-config` and needs the same pool.

Prealloc matters: with the RAM allocated and zeroed at VM start, a first
guest access to a 2 MB region costs one second-level page-table entry and
nothing else, so the frame allocator's scatter (item 7) is bounded by the
number of 2 MB regions in the guest's RAM, 512 for 1 GB, instead of costing
a hugepage allocation per 4 KB frame as it did with transparent hugepages
on QEMU.

Nested hosts. The machine this work runs on is itself a QEMU guest, and a
Motor OS access goes through two second-level page tables: the development
VM's (for the Motor OS guest) and the physical host's (for the development
VM). Both must use 2 MB entries for the fault count to drop by 512; a pool
inside the development VM alone gives its KVM 2 MB entries while the
physical host still fills its table 4 KB at a time. So, on the physical
host, reserve a pool and start the development VM from it:

```
# physical host, once (48 GiB in 2 MiB pages; persist in /etc/sysctl.d)
sudo sysctl vm.nr_hugepages=24576
# then the development VM, with two options added:
qemu-system-x86_64 -enable-kvm -m 48G -smp 24 -cpu host \
  -mem-path /dev/hugepages -mem-prealloc \
  -drive file=ubuntu-server.qcow2,if=virtio \
  -device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::2202-:22 \
  -no-reboot -nographic
```

1 GiB pages are better still for a 48 GiB guest (kernel command line
`hugepagesz=1G hugepages=48` on the physical host, a hugetlbfs mount with
`pagesize=1G`, and that mount as `-mem-path`), and need a reboot to
reserve. Either way the reserved memory is taken from the physical host
for as long as the setting stands, and `-mem-prealloc` adds a few seconds
to the development VM's start.

Inside the development VM, once (persist both in `/etc/sysctl.d` and a
boot script):

```
sudo sysctl vm.nr_hugepages=4608      # 8 GiB run-dev.sh + 1 GiB test VM
echo advise | sudo tee /sys/kernel/mm/transparent_hugepage/shmem_enabled
```

The second line is only for runs without a pool (cloud-hypervisor's memfd
RAM ignores the hint otherwise). Whether it took effect:
`grep HugePages_Free /proc/meminfo` drops by the guest's size while a VM
runs (pool), or `grep AnonHugePages /proc/<vmm pid>/smaps_rollup` is
non-zero (transparent hugepages); on the physical host the same check on
the development VM's QEMU process. The kernel and kloader phase of the
boot trace, or simply the "kernel up at" stamp, shows the gain.

## Instrumentation

In `git stash` ("boot-trace instrumentation: kloader stamps + kernel
records"), not in the tree: a boot-trace ring in the kernel
(`src/sys/kernel/src/xray/boot_trace.rs`, 1024 entries); kloader TSC
stamps handed over in `KernelBootupInfo.stamps` and replayed into the
ring by `start_bsp`; kernel records through `init.rs`, `mm/mod.rs`,
`arch/x64/mod.rs` (GS), `arch/x64/irq.rs`, and `sched/scheduler.rs`; the
dump runs from the scheduler's idle path one second after sys-io starts.
The userspace probes (a `bt:` prefix on `SysRay::log`, probes in the vdso
spawn path, sys-io, sys-init, strobe, sys-tty, dns-resolver, russhd) were
removed after the userspace work; they are a few lines each to put back.
The stash is relative to the commit before kernel item 1, so popping it
after item 1 is committed conflicts in `init.rs` (around `place_sys_io`) and
`mm/mod.rs` (the reservation flag); both are a few lines to resolve.

The trace build's kernel is 564 KB against 441 KB clean (the ring), so
the kloader's kernel-copy figure above is ~30 pages high.

Firecracker boots the raw base image, so `make BUILD=release base.img` is
needed for its userspace probes; the kernel and kloader come from the
initrd either way.

Suggested disposition: keep the ring, the kloader stamps and the probes
(each probe is one syscall or one TSC read), make the dump opt-in, and
drop it from the default image.
