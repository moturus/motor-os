# Patched crates for native rust-analyzer

The native analyzer builds against the selected installed standard library.
Its remaining source rewrites are limited to the published dependencies below.
Use the published crates.io archive, not a Git checkout. Preserve its licenses.
The preparation helper verifies the archive checksum before applying the patch
to a fresh source copy under `$MOTORH/patched-crates/` (normally `../`).

| Crate | Version | Published archive SHA-256 | Patch |
|---|---|---|---|
| url | 2.5.8 | `ff67a8a4397373c3ef660812acab3268222035010ab8680ec4215f38ba3d0eed` | `url-2.5.8-motor.patch` |
| inventory | 0.3.24 | `a4f0c30c76f2f4ccee3fe55a2435f691ca00c0e4bd87abe4f4a851b1d4dac39b` | `inventory-0.3.24-motor.patch` |

The developer-image gate runs the patched crate's relevant upstream unit tests
on the host and on Motor through `src/tests/test-rust-analyzer-crates.sh`. The
URL patch drops benchmark and wasm-only test dependencies that are outside this
gate. Toolchain provisioning fetches the remaining locked test graphs; the
tests themselves always pass `--locked --offline` and never fetch missing
archives or dependencies.

Native tests use the selected assembly's `motor-clang` with
`-C link-self-contained=no -C default-linker-libraries=yes`, as the planned
server build does. The inventory test requires two registrations from separate
modules to be visible, proving that mlibc startup executes their constructors.
