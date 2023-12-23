# `volatile`

[![Build Status](https://github.com/rust-osdev/volatile/workflows/Build/badge.svg)](https://github.com/rust-osdev/volatile/actions?query=workflow%3ABuild) [![Docs.rs Badge](https://docs.rs/volatile/badge.svg)](https://docs.rs/volatile/)

Provides the wrapper type `Volatile`, which wraps a reference to any copy-able type and allows  for volatile memory access to wrapped value. Volatile memory accesses are never optimized away  by the compiler, and are useful in many low-level systems programming and concurrent contexts.

The wrapper types *do not* enforce any atomicity guarantees; to also get atomicity, consider looking at the `Atomic` wrapper types found in `libcore` or `libstd`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
