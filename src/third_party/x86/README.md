# x86 / amd64 library [![Crates.io](https://img.shields.io/crates/v/x86.svg)](https://crates.io/crates/x86) [![docs.rs/x86](https://docs.rs/x86/badge.svg)](https://docs.rs/crate/x86/) ![Standard checks](https://github.com/gz/rust-x86/actions/workflows/standard.yml/badge.svg)

Library to program x86 (amd64) hardware. Contains x86 specific data structure descriptions, data-tables, as well as convenience function to call assembly instructions typically not exposed in higher level languages.

Currently supports:

* I/O registers
* Control registers
* Debug registers
* MSR registers
* Segmentation
* Descriptor-tables (GDT, LDT, IDT)
* IA32-e page table layout
* Interrupts (with xAPIC and x2APIC, I/O APIC drivers)
* Task state
* Performance counter information
* Intel SGX: Software Guard Extensions
* Random numbers (rdrand, rdseed)
* Time (rdtsc, rdtscp)
* Querying CPUID (uses [raw_cpuid](https://github.com/gz/rust-cpuid) library)
* Transactional memory (Intel RTM and HLE)
* Virtualization (Intel VMX)

This library depends on libcore so it can be used in kernel level code.

## Testing

We use two forms of tests for the crate. Regular tests with `#[test]` that run in a ring 3 process
and `#[x86test]` tests that run in a VM (and therefore grant a privileged execution environment, see [x86test](https://github.com/gz/rust-x86/tree/master/x86test)).

```bash
# To execute x86tests run:
$ RUSTFLAGS="-C relocation-model=dynamic-no-pic -C code-model=kernel" RUST_BACKTRACE=1 cargo test --features vmtest

# To execute the regular tests, run:
$ cargo test --features utest
```

## Features

* performance-counter: Includes the performance counter information. Note this feature
  can increase compilation time significantly due to large, statically generated hash-tables
  that are included in the source. Therefore, it is disabled by default.

## Documentation

* [API Documentation](https://docs.rs/crate/x86/)
