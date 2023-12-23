intrusive-collections
=====================

[![Build Status](https://travis-ci.org/Amanieu/intrusive-rs.svg?branch=master)](https://travis-ci.org/Amanieu/intrusive-rs) [![Coverage Status](https://coveralls.io/repos/github/Amanieu/intrusive-rs/badge.svg?branch=master)](https://coveralls.io/github/Amanieu/intrusive-rs?branch=master) [![Crates.io](https://img.shields.io/crates/v/intrusive-collections.svg)](https://crates.io/crates/intrusive-collections)

A Rust library for creating intrusive collections. Currently supports singly-linked and doubly-linked lists, as well as red-black trees.

## Features

- Compatible with `#[no_std]`.
- Intrusive collections don't require any dynamic memory allocation since they simply keep track of existing objects rather than allocating new ones.
- You can safely manipulate intrusive collections without any unsafe code.
- A single object can be a member of multiple intrusive collections simultaneously.
- Intrusive collections provide a `Cursor`-based interface, which allows safe mutation while iterating.

For examples and more information, see the documentation ([crates.io](https://docs.rs/intrusive-collections), [master](https://amanieu.github.io/intrusive-rs/intrusive_collections/index.html)).

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
intrusive-collections = "0.9"
```

This crate has two Cargo features:

- `nightly`: Enables nightly-only features: `const fn` constructors for collections (`Link` constructors are always `const fn`)
- `alloc` (enabled by default): Implements `IntrusivePointer` for `Box`, `Rc` and `Arc`.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
