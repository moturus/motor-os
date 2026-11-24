# Porting aws-lc-rs to Motor OS

Bring up the non-FIPS AWS-LC provider for rustls on
`x86_64-unknown-motor`. The first consumers are `httpd-axum` and `httpd`.
Adopting the provider for curl also requires a reproducible Lorry build.
The C changes belong in the external AWS-LC fork and its pinned submodule
in the aws-lc-rs fork.

## Cross-build and guest runtime

1. Select the `getentropy` implementation for `__motor__` in AWS-LC's
   `crypto/rand_extra/internal.h`. A fallback that opens `/dev/urandom`
   cannot supply entropy on Motor. Consider the separate no-fork
   classification in `crypto/ube/fork_ube_detect.c` to avoid redundant
   DRBG initialization.
2. Pin a matching aws-lc-rs/aws-lc-sys pair. The plan targets 1.17.3 and
   0.43.0 respectively. Use the target-independent crypto bindings and
   the x86-64 ELF assembly. Keep the feature selection narrow enough to
   avoid generating target bindings or building the C SSL library.
3. Supply the Motor target and mlibc sysroot explicitly to clang and link
   the consumer with the C runtime. Check the builder's target flags and
   thread support. Start with a guest fixture that obtains random bytes,
   checks a digest and performs a local rustls handshake.
4. Verify pthread operations from Rust-created threads, emulated TLS,
   allocator ownership across FFI and jitter entropy. Then exercise each
   HTTP server with its new provider. Measure executable and image size
   before extending the change to more consumers.

## Lorry and curl

Determine whether the pinned AWS-LC C builder can run with Lorry's
per-package tool grants, target compiler and archiver on both hosts.
Its `links` metadata can use Lorry's `DEP_<LINKS>_<KEY>` forwarding.
Check include paths, version-prefixed symbols and the selected dependency
features in the consuming build.

If building C during a native install is too expensive, stage the
version-matched static archive and headers in the external toolchain
sysroot. Record the compiler inputs and digest. Have the sys crate link
that archive and export the metadata its Rust consumer reads. Keep the
Rust layers source-built and check a curl HTTPS transfer against a local
fixture. Decide whether the resulting footprint and maintenance cost
justify switching curl or retiring ring.
