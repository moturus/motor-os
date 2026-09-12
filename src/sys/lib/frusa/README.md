# frusa

The Motor OS allocator: every process's heap through `rt.vdso`, and the
kernel heap through `mm/kheap.rs`. Version 0.2 (developed as `frusa_v2`)
replaced the 0.1 series with the same interface and size classes, bounded
lookups, and a per-thread (in the kernel, per-CPU) fast path. Design,
measurements, and the implementation plan are in `docs/plans/frusa.md`.
