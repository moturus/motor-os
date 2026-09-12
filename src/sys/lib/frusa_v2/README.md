# frusa_v2

The Motor OS userspace allocator (`rt.vdso`). Same interface and size
classes as `frusa`, which the kernel keeps, with bounded lookups and a
per-thread fast path. Design, measurements, and the implementation plan are
in `docs/plans/frusa.md`.
