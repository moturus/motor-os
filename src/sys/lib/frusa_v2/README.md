# frusa_v2

The Motor OS allocator: every process's heap through `rt.vdso`, and the
kernel heap through `mm/kheap.rs`. Same interface and size classes as
`frusa`, which it replaced, with bounded lookups and a per-thread (in the
kernel, per-CPU) fast path. Design, measurements, and the implementation
plan are in `docs/plans/frusa.md`.
