# frusa

The Motor OS allocator: every process's heap through `rt.vdso`, and the
kernel heap through `mm/kheap.rs`. Power-of-two size classes up to 4 KiB
served from 64-slot blocks, bounded pointer lookup through an address-sorted
index, free lists sharded by CPU, per-thread (in the kernel, per-CPU)
private blocks, no lock held across a backend call, and reclaim on demand.
The design is in `docs/frusa.md`.
