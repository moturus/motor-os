# Patched crates for native rust-analyzer

Use the published crates.io archive, not a Git checkout. Preserve its licenses.
The preparation helper verifies the archive checksum before applying the patch
to a fresh source copy under `$MOTORH/patched-crates/` (normally `../`).

| Crate | Version | Published archive SHA-256 | Patch |
|---|---|---|---|
| url | 2.5.8 | `ff67a8a4397373c3ef660812acab3268222035010ab8680ec4215f38ba3d0eed` | `url-2.5.8-motor.patch` |

Integration into source acquisition and host/native build identity is still
pending in `docs/plans/rust-analyzer.md`. Do not select these sources in a
production build without that identity and lockfile integration.

The developer-image gate runs the patched crate's upstream unit tests on the
host and on Motor through `src/tests/test-rust-analyzer-crates.sh`. Provision
the test dependencies separately with `cargo fetch --locked --manifest-path
<prepared-source>/Cargo.toml`; the tests use the published lock and always
pass `--locked --offline`. Source acquisition will be integrated in plan
step 20. The tests never fetch missing archives or dependencies themselves.
