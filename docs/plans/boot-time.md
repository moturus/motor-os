# Boot time

Measure the release guest from kloader entry to sys-tty's “most services up”
line on Cloud Hypervisor, Firecracker and QEMU. Keep VMM startup, kernel
time and userspace time separate. Nested virtualization makes first-touch
faults and port or MMIO exits especially expensive.

## Kernel and kloader

1. Use `KernelBootupInfo.start_tsc` to report elapsed guest time. The
   “kernel up” timestamp currently includes work the VMM does before the
   first guest instruction. On Cloud Hypervisor, syncing a freshly copied
   qcow2 image can dominate the number.
2. Start application processors in parallel. Give each a stack and select
   its bootstrap state by APIC ID. The BSP can join at the kernel's
   `AP_STARTED` wait. Evaluate a TSC-based startup delay across VMMs.
3. Evaluate programming only the IOAPIC redirection entries that are used.
   Establish the reset state on each supported VMM before relying on it.
4. Measure how much early serial output, including the logo and “kernel
   up” message, can move past sys-io startup without losing early failure
   diagnostics.
5. On nested hosts, determine whether an idle AP can pre-read sys-io's
   initrd pages while the BSP finishes initialization. Measure the whole
   boot through service readiness to distinguish overlap from moving faults
   to another phase.
6. Separate first-touch faults from the compute cost of `phys::init`.
   Inspect the slab and page-table pages touched by the first
   `vmem_allocate_pages` before changing its initial slab size.

## Userspace

- Batch demand reads. `on_cmd_read_multi` reserves pages for the full
  response but awaits each block-sized filesystem read in turn. Consider
  scatter-gather reads for motor-fs open and cold executable loads.
- Reduce the cost of first filesystem use in each process. Compare a
  smaller io_channel with populating channel pages on demand.
- Reduce PCI config reads during the virtio capability walk by reading
  complete words and reusing the header and vendor ID.
- Evaluate mapping the read-only vDSO segments for sys-io from the kernel.
  As the first userspace process, sys-io has no parent mapping to share.

## Launcher comparisons

Compare QEMU's disk boot with a direct PVH boot using kloader and the
initrd. For Cloud Hypervisor compare raw and qcow2 images with equivalent
host writeback and page-cache state. For Firecracker evaluate explicit
2 MiB backing via its machine configuration.

Record the RAM backing for each comparison. QEMU and Cloud Hypervisor can
use a host hugetlbfs pool. Check `HugePages_Free` against the requested
guest size, and the pool mount for QEMU. `MOTO_HUGEPAGES=0` selects the
comparison without that pool. For transparent hugepages, check anonymous
backing on QEMU and the host's `shmem_enabled` policy for Cloud
Hypervisor's memfd. On a nested host, record the backing of the outer VM
as well. Count preallocation before guest entry as launcher time.
