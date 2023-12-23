# Unreleased

# 0.4.5 – 2022-04-24

- Remove the `const_generics` feature flag ([#25](https://github.com/rust-osdev/volatile/pull/25))

# 0.4.4 – 2021-03-09

- Replace feature "range_bounds_assert_len" with "slice_range" ([#21](https://github.com/rust-osdev/volatile/pull/21))
  - Fixes the `unstable` feature on the latest nightly.

# 0.4.3 – 2020-12-23

- Add methods to restrict access ([#19](https://github.com/rust-osdev/volatile/pull/19))

# 0.4.2 – 2020-10-31

- Change `slice::check_range` to `RangeBounds::assert_len` ([#16](https://github.com/rust-osdev/volatile/pull/16))
  - Fixes build on latest nightly.

# 0.4.1 – 2020-09-21

- Small documentation and metadata improvements

# 0.4.0 – 2020-09-21

- **Breaking:** Rewrite crate to operate on reference values ([#13](https://github.com/rust-osdev/volatile/pull/13))

# 0.3.0 – 2020-07-29

- **Breaking:** Remove `Debug` and `Clone` derives for `WriteOnly` ([#12](https://github.com/rust-osdev/volatile/pull/12))

# 0.2.7 – 2020-07-29

- Derive `Default` for `Volatile`, `WriteOnly` and `ReadOnly` ([#10](https://github.com/embed-rs/volatile/pull/10))
