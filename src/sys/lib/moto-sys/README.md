# Motor OS system crate

System calls, capabilities, statistics and shared kernel pages for
[Motor OS](https://github.com/moturus/motor-os). This crate supports `no_std`.

Version 0.4 requires the current kernel's free-page shared-memory layout.
`free_pages()` reports free physical memory in 4 KiB pages; `low_memory()`
checks the 4 MiB service admission threshold. These replace the old
`memory_pressure()` flag. The old admission reservation counters,
`stats::AdmissionStats` and `SysMem::query_admission_stats()` are removed.

