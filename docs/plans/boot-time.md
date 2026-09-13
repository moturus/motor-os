# Boot time

Open items, the hugepage backing recipe, and launcher notes. The trace that
produced the numbers, the landed items (PCI scan, vdso sharing, sys-io mapped
from the initrd, the VMM placing the kernel, the block allocator's
`phys::init` and sequential placement) and their A/B tables are in Git
history of this file.

Scope: the release image on cloud-hypervisor (the user's launcher),
Firecracker, and QEMU, from the first guest instruction to sys-tty's
"most services up" line.

Provenance. Measured on the host used for all Motor OS work here, which is
itself a KVM guest with nested virtualization (24 vCPUs reporting an
i7-14700). A port I/O or MMIO exit costs ~14 us, the first guest access to
a page ~10 us if the VMM wrote it earlier (the initrd) and ~15 us for a
fresh page. On bare metal both are several times cheaper, so the absolute
savings shrink, but the ranking of the items should hold.

After the landed work, kloader plus kernel is 8-13 ms on cloud-hypervisor
and Firecracker and the userspace phase ("kernel up" to the console line)
is 35-37 ms.

## Open items, ordered by payoff

Kernel and kloader:

1. AP pre-read of sys-io's pages. Mapping sys-io from the initrd moved
   6-11 ms of first-access faults from the kernel into sys-io's own boot
   on nested hosts. An idle AP could read through the sys-io pages while
   the BSP finishes its init (the APs spin in `sched::start` waiting for
   the BSP from ~0.3 ms after memory init), taking the faults off the
   critical path instead of moving them along it. About 15 lines. Only
   worth it if the shift matters; on bare metal a first access costs a
   microsecond rather than ten.

2. Start the APs in parallel and off the critical path (1.7-4.4 ms).
   Give each AP its own stack up front and let the trampoline read its
   CPU number from the APIC id, then send INIT to all, one wait, SIPI to
   all, and do not wait: the kernel's existing `AP_STARTED` wait in
   `start_bsp` is the join point, and by then the APs are up. Replace the
   iteration-count spin with a TSC-based delay so it costs the same on
   every VMM (on Firecracker the spin alone costs 0.9 ms per AP: PAUSE
   exits there).

3. Program only the IOAPIC entries in use (1.2-1.7 ms): the serial IRQ
   and whatever `ioapic_enable_irq` is asked for later. `ioapic_init`
   masks all 24 redirection entries with two MMIO writes each, and the
   entries are masked at reset on every VMM. If the reset state is not
   trusted, read the entries (48 exits) instead of writing them (96).

4. Move the serial output off the path (1.1 ms): print the logo and the
   "kernel up" line after sys-io has been started, or from the scheduler
   loop; print less. The "kernel up at" line alone is 66 bytes at ~14 us
   each.

5. Report boot time from the kloader entry (no speedup, correct
   attribution). The "kernel up at" stamp counts from vCPU creation, so
   the VMM's own work (opening the disk image, loading the initrd,
   building ACPI tables; 14-21 ms warm and 43 ms cold on cloud-hypervisor
   with a qcow2 image) is attributed to the kernel and the number moves
   with the host's page cache. `KernelBootupInfo.start_tsc` (the
   kloader's entry time) is passed to the kernel and unused: use it for
   the "kernel up" line, or print both numbers.

6. Look inside the first `vmem_allocate_pages` (0.6-1.0 ms): how many
   slab and page-table pages it touches, and whether the slab can start
   smaller.

7. `phys::init` compute cost. Measured 0.19-1.9 ms across launchers with
   the spread between boots exceeding the difference between 1 and 8 GB,
   consistent with first-touch faults dominating on this host; the
   compute cost has not been isolated and the 0.1 ms target is open.

Userspace:

8. Batch the demand-path block reads (~5 ms here, ~100 ms for russhd's
   4 MB load after the prompt). A 48 KB read becomes 12 sequential
   single-block round trips; the readahead path already issues
   scatter-gather reads of up to 16 blocks per request, so
   `on_cmd_read_multi` and motor-fs open should do the same.

9. Cheaper first filesystem use per process (~4 ms). Lazily populated
   io_channel pages, or a smaller channel, so a fresh connection does not
   first-touch 128 pages.

10. Trim the virtio capability walk (~3.5 ms). Read 32-bit words, cache
    the header, stop re-reading the vendor ID.

11. sys-io's own vdso self-load (4.9 ms) has no parent to share from; the
    kernel could map the vdso's read-only segments for the first process
    the same way it maps sys-io from the initrd.

| item | expected saving (cloud-hypervisor / Firecracker) |
|---|---|
| 2 APs in parallel, not waited for | 1.7-4.4 ms |
| 3 IOAPIC entries in use only | 1.2-1.7 ms |
| 4 serial off the path | 1.1 ms |
| 8-11 userspace | 15-17 ms |

Items 2-4 take kloader plus kernel from the current 8-13 ms to roughly
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
first guest instruction. `run-qemu.sh` uses the disk path.

Firecracker: `--enable-pci` is required (the base image's sys-io only
knows virtio-pci); `run-fc.sh` passes it.

## Hugepage backing: host settings and launcher changes

The block allocator places fresh pages sequentially (eight 1 MiB pieces
land in 6 to 10 distinct 2 MiB blocks), which is what hugepage backing
needs: one host fault covers 512 guest pages. With the old random
placement, hugepage backing turned every fresh 4 KB frame into a 2 MB
host fault and the kernel's boot got slower, not faster.

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

Launcher scripts (`src/vm_scripts/`, copied into `vm_images/`):
`run-chv.sh` and `run-qemu.sh` use the hugetlbfs pool on their own when
`/proc/meminfo` shows enough free pages for the guest's RAM
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
nothing else, so any remaining scatter is bounded by the number of 2 MB
regions in the guest's RAM, 512 for 1 GB, instead of costing a hugepage
allocation per 4 KB frame as it did with transparent hugepages on QEMU.

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
the development VM's QEMU process. The "kernel up at" stamp shows the gain.
