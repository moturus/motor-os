# Porting aws-lc-rs to Motor OS

2026-08-04. Plan only. No code changes accompany this document.

Scope: bringing `aws-lc-rs` (the Rust binding to AWS-LC, Amazon's BoringSSL
fork) to the `x86_64-unknown-motor` target, first for Linux-hosted cargo
cross-builds, then for lorry-driven builds (cross and native). FIPS
(`aws-lc-fips-sys`) is out of scope: it hard-requires CMake, Go (delocate),
and Perl, and has pregenerated bindings for only six linux/darwin targets.

Provenance. Findings were gathered against:

* `aws-lc-rs` checkout `5a5408bc487` at `../aws-lc-rs` — crate versions
  `aws-lc-rs` 1.17.3 / `aws-lc-sys` 0.43.0, the exact pair measured by the
  Round 27 provider evaluation (`src/bin/lorry/work-in-progress.md:2785-2910`,
  fixtures dated 2026-07-19). Note: both C submodules in that checkout are
  uninitialized; `make init-submodules` there is required before building
  from the tree. Crates.io archives are self-contained.
* Motor OS tree at `9cbe81fd` (moto-rt v17 era), toolchains under
  `/home/posk/motor-dev/` (`rust` @ `motor-os-rustc`, LLVM 23 fork, mlibc
  sysroot).

Verified vs. assumed: "compiles and links for Motor" is *measured* (Round 27
built unmodified `aws-lc-sys` 0.43.0 cross with the mlibc/LLVM toolchain,
tracing only the C compiler and archiver). **No AWS-LC code has ever
executed on Motor OS.** Everything runtime-related in this plan is
link-time-proven only and is called out in Risks.

## Summary and headline recommendation

**The port is small because the hard parts already exist.** Motor OS has a
full C cross toolchain (clang + mlibc sysroot), mlibc implements
`getentropy()` over `moto_rt_fill_random_bytes`, and the crates.io form of
`aws-lc-sys`, when consumed through `aws-lc-rs`, needs only a C compiler and
archiver — no CMake, bindgen/libclang, Perl, Go, or NASM. Exactly one C
source patch is unavoidable (entropy selection), plus build plumbing.

Recommended shape, in two independent phases:

1. **Phase 1 — cargo cross-builds (days).** Fork aws-lc with the one-line
   entropy patch, consume via `[patch.crates-io]` like ring today, switch
   `httpd` and `httpd-axum` to the rustls aws-lc provider, add the
   mlibc-aware link recipe. Validate at runtime in the VM. This is the
   entire "Linux => Motor OS" story.
2. **Phase 2 — lorry consumption via a prebuilt C archive (days, later).**
   Do NOT teach lorry `links`/`DEP_*` forwarding and do NOT prebuild rlibs
   (both analyzed below, both rejected). Instead: stage
   `libaws_lc_0_43_0_crypto.a` as a sysroot artifact and patch the two
   vendored build scripts down to Stage-2-allowed directives. Lorry then
   builds the pure-Rust layers from source, unmodified lorry, cross and
   native alike.

Phase 1 alone leaves the image carrying two C crypto stacks (curl stays on
ring under lorry); Phase 2 is what makes retiring ring possible. Whether to
retire ring is a separate decision, not made here.

## Background A: what aws-lc-rs needs to build

The build script is shared: `aws-lc-sys/builder` is a symlink to the repo's
`builder/` (`build = "builder/main.rs"`). Builder selection is
`builder/main.rs:653` (`get_builder`); with no `AWS_LC_SYS_*` overrides, no
FIPS, and bindgen not required, it picks the **cc builder**
(`builder/cc_builder.rs`), which compiles a hardcoded source list with the
`cc` crate. Key facts:

* **Bindings.** `aws-lc-rs` depends on `aws-lc-sys` with
  `default-features = false`, which disables `all-bindings`. In that mode an
  *arbitrary unknown target* gets the pregenerated, target-agnostic
  "universal" bindings (`aws-lc-sys/src/universal_crypto.rs`, selected via
  `cargo:rustc-cfg=universal`) — bindgen is never invoked
  (`builder/main.rs:791` `initialize`, `:886` `is_bindgen_required`).
  Guard: any crate enabling `aws-lc-sys/all-bindings` or the `ssl` feature
  re-arms bindgen for unknown targets via feature unification.
* **Sources.** `identify_sources()` (`builder/cc_builder.rs:49`) selects by
  vendor/OS/arch; a `motor` OS falls through to arch-only selection, i.e.
  `universal` + `linux_x86_64` — the correct ELF/SysV pregenerated assembly.
  No build-script change is needed for source selection.
* **Flags to watch.** For a non-linux/non-apple target the builder adds
  `-pthread` and `-D__EXTENSIONS__=1` (`builder/cc_builder.rs:287,295`);
  both must be confirmed harmless against mlibc headers.
  `AWS_LC_SYS_NO_ASM=1` exists as an escape hatch but asserts debug-profile
  (`cc_builder.rs:238`). Jitter entropy
  (`third_party/jitterentropy/...`) is compiled by default; its x86_64 timer
  is RDTSC (no OS call), but `AWS_LC_SYS_NO_JITTER_ENTROPY=1` is the
  first-bring-up fallback.
* **The `cc` crate maps unknown Motor to `x86_64-unknown-none-elf`**
  (Round 27, `work-in-progress.md:2810-2814`), so the C compiler must be
  given explicitly with `--target=x86_64-unknown-motor --sysroot=...` —
  unlike ring, AWS-LC's C is *not* freestanding: it includes `pthread.h`,
  `unistd.h`, stdio, and links against mlibc symbols.
* **`links` metadata.** `aws-lc-sys` declares `links` and emits
  `cargo:include`/`libcrypto`/`root`/`conf`; `aws-lc-rs/build.rs` *asserts*
  on the forwarded `DEP_AWS_LC_*_INCLUDE` (`aws-lc-rs/build.rs:110`) and
  re-emits the values. Cargo handles this natively; lorry Stage 2 rejects
  it by design (`src/bin/lorry/src/build_script.rs:469-540`). Lorry does
  accept the `links` *manifest key* itself (ring's is
  `ring_core_0_17_14_`; `build_script.rs:165` sets
  `CARGO_MANIFEST_LINKS`) — only the metadata directives are the problem.
* **Rust layer.** `aws-lc-rs/src/` has zero `cfg(target_os)`/`cfg(unix)`
  code; it requires `std` (which the Motor port satisfies) plus `zeroize`
  and optionally `untrusted`. No changes expected.
* Symbols are version-prefixed (`aws_lc_0_43_0_*`), the static library is
  `libaws_lc_0_43_0_crypto.a` — a stale archive against a newer sys crate
  fails loudly at link time.

## Background B: what Round 27 measured

`work-in-progress.md:2825-2869`, fixture pair aws-lc-rs 1.17.3 /
aws-lc-sys 0.43.0 vs ring 0.17.14, both under rustls 0.23.42:

| Measured property | AWS-LC | ring |
| --- | ---: | ---: |
| Non-root packages (Linux-musl/Motor union) | 19 | 15 |
| Extracted source | ~76 MiB | ~16 MiB |
| Provider source tree | 66.7 MB / 2,011 files | 7.8 MB / 392 files |
| Motor release fixture (unstripped) | 3,707,256 B | 1,975,464 B |
| Motor native objects / archives | 366 / ~13.7 MB | 45 / ~2.6 MB |
| Build-script captured output | ~286 KiB | ~7 KiB |

Round 27 chose ring for the lorry curl graph on size/review-surface grounds
and because AWS-LC's `links` metadata would expand lorry's Stage-2 directive
boundary. Nothing in that decision blocks this port; this plan deliberately
avoids reopening the Stage-2 boundary (see Phase 2 and Rejected options).

## The required C patches

1. **Entropy (unavoidable).** AWS-LC's platform gate
   (`include/openssl/target.h`) is happy with an unknown OS, but the
   entropy chain (`crypto/rand_extra/internal.h`) then falls through to
   `OPENSSL_RAND_URANDOM` → `open("/dev/urandom")` — absent on Motor →
   runtime failure. Fix: classify `defined(__motor__)` into the existing
   `OPENSSL_RAND_GETENTROPY` branch; mlibc declares `getentropy` in
   `unistd.h`, backed by `moto_rt_fill_random_bytes` (RDRAND with retries,
   hard panic on exhaustion — no silent weak fallback). This must be a
   source patch, not `-DOPENSSL_RAND_GETENTROPY`: the `#else` would still
   define `OPENSSL_RAND_URANDOM` and both `urandom.c` and `getentropy.c`
   would define `CRYPTO_sysrand` (duplicate symbol). Round 27 verified the
   one-liner compiles and links (`work-in-progress.md:2851-2856`).
   `clang --target=x86_64-unknown-motor -dM -E` defines `__motor__` and
   `__ELF__`, not `__linux__`/`__unix__`, so the classification is clean.
2. **Optional, upstreamable.** Following the existing
   `OPENSSL_NANOLIBC`/`CROS_EC`/`OPENSSL_WASM_WASI` template in
   `include/openssl/target.h`: add an `OPENSSL_MOTOR` block, and add it
   beside `OPENSSL_WINDOWS || OPENSSL_TRUSTY` in
   `crypto/ube/fork_ube_detect.c` (`AWSLC_PLATFORM_DOES_NOT_FORK`; Motor
   has no `fork`). Without this AWS-LC falls back to re-randomizing DRBG
   state per request — correct but slower. Can land after Phase 1
   validation; a genuine upstream-patch candidate.

Delivery vehicle: a `moturus/aws-lc-rs` fork (plus a fork of the `aws-lc`
submodule carrying the C patch), mirroring the moturus/ring arrangement.

## Consumer inventory (corrects an earlier assumption)

* **russhd** — *not* a consumer. Its lockfile contains no `ring`, `rustls`,
  or `aws-lc-*`; russh 0.52 brings its own RustCrypto-based stack. Nothing
  to do.
* **httpd** — cargo cross (`Makefile:163-166`, `DO_BUILD` at `Makefile:36`),
  rustls `features = ["ring", "std"]`, ring patched to moturus branch
  `motor-os_2025-09-20` (`src/bin/httpd/Cargo.toml:11-16`).
* **httpd-axum** — cargo cross, same shape, but ring branch
  `motor-os-0.17.14` (`src/bin/httpd-axum/Cargo.toml:15,25`). The two
  binaries currently track *different* ring forks; moving both to one
  aws-lc fork consolidates.
* **curl** — built by a Linux-hosted lorry, not cargo
  (`Makefile:198-213`); ring is a lorry-vendored path patch
  (`src/bin/curl/Cargo.toml:23`). curl is lorry's Stage-2 acceptance
  fixture and native lorry's vendoring fetch tool; it cannot "forget
  lorry". It stays on ring until Phase 2.

## Phase 1: cargo cross-builds (Linux => Motor)

Steps, each a small reviewable patch per AGENTS.md:

1. Create the moturus forks (aws-lc-rs repo + aws-lc submodule) with patch
   (1) above; tag/branch pinned to the 0.43.0-era submodule commit.
   (Out-of-repo work; in-repo changes reference it by branch, as ring does.)
2. `httpd-axum`: switch rustls provider feature from `ring` to the aws-lc
   provider, add `[patch.crates-io]` for `aws-lc-sys` → fork, drop the ring
   patch; Makefile target gains `CC_x86_64_unknown_motor` /
   `AR_x86_64_unknown_motor` (Motor clang with
   `--target=x86_64-unknown-motor --sysroot=...`, llvm-ar) and the
   mlibc-aware link recipe — precedent at `Makefile:106-116`
   (dns-resolver: `-C linker=<motor-clang> -C link-self-contained=no
   -C default-linker-libraries=yes`). First bring-up may set
   `AWS_LC_SYS_NO_JITTER_ENTROPY=1`; removing it is a follow-up decision.
3. Runtime validation before touching the second binary (see Validation).
4. `httpd`: same conversion.
5. Optional: patch (2) (`OPENSSL_MOTOR` / no-fork classification) in the
   fork; re-validate.

Explicitly not in Phase 1: russhd (nothing to change), curl (lorry-built),
any lorry changes, any attempt to make `--no-default-features` choices
beyond what rustls's provider features already express.

## Phase 2: lorry consumption via a prebuilt C archive

Goal: let lorry build aws-lc-rs consumers (curl being the motivating one)
cross *and* native, with **zero lorry feature work**. The insight: the only
part of the graph lorry cannot handle is the build-script machinery; the
four Rust crates (`aws-lc-rs`, `aws-lc-sys`, `zeroize`, `untrusted`) are
plain Rust that lorry compiles happily.

1. **Prebuild `libaws_lc_0_43_0_crypto.a` on Linux** with a pinned script
   (patched sources from the Phase 1 fork, Motor clang, `llvm-ar`,
   `-ffile-prefix-map` for reproducibility, recorded sha256) and stage it
   inside the motor-sysroot. Trust class: identical to `libc.a`,
   `libunwind.a`, `libmoto_rt_cabi.a` — prebuilt sysroot artifacts already
   consumed by every C-linking Motor binary. Staging inside the sysroot
   also rides lorry's existing read-only `--sysroot` sandbox allowance on
   Linux.
2. **Patched vendored `aws-lc-sys`** (ring-precedent path patch): replace
   the ~5k-line builder with a ~20-line `build.rs` emitting only
   Stage-2-allowed directives — `cargo:rustc-cfg=universal` (+
   `rustc-check-cfg`), `rustc-link-search=native=<staged dir>`,
   `rustc-link-lib=static=aws_lc_0_43_0_crypto`. The patched manifest drops
   the `cc`/`cmake`/`dunce`/`fs_extra`/`pkg-config`/`jobserver` build-deps
   entirely, shrinking the graph to roughly ring's size and dissolving the
   Round 27 `links` objection.
3. **Patched vendored `aws-lc-rs`**: delete `export_sys_vars()` from its
   `build.rs` (kills the `DEP_AWS_LC_*_INCLUDE` assert; the re-export only
   serves downstream FFI consumers, of which the curl graph has none). The
   rest of that build script already emits only allowed directives.
4. Seed entries + policy grants (`allow-build-script`, pinned
   `source-tree-sha256`) in the lorry bootstrap seeds, as ring has today.
5. Native variant (optional, later): rebuild the archive *on* Motor with a
   rush script driving `/bin/cc` + `llvm ar` over the ~366-file list
   (generated from a Linux cc-builder trace, not hand-written). Only needed
   for self-hosting completeness; the staged cross-built archive serves
   native lorry builds fine until then.

## Options analyzed and rejected

* **Teach lorry `links`/`DEP_*` forwarding.** Round 27 already scoped the
  bounded design and called it "tractable but genuine structural scope".
  Rejected here because Phase 2 achieves the same outcome with two small
  vendored patches and no Stage-2 boundary change; the forwarding feature
  can still be built later on its own merits.
* **Prebuild the Rust layers as rlibs with cargo on Linux.** Verified
  enabling fact: the cross stage-2 rustc reports exactly
  `rustc 1.99.0-dev, commit-hash: unknown` (dev channel, hash omitted), and
  the native Motor rustc is built from the same checkout/`src/version`, so
  rlibs are mutually loadable across Linux-cross and native-Motor
  compilers — the usual version-stamp barrier is absent. Rejected anyway:
  (a) lorry has no prebuilt-artifact input mechanism, and adding
  resolver-level substitution (+ `--extern` wiring + policy/schema) is at
  least the structural scope of the `links` feature with a worse audit
  story (opaque compiled artifacts); (b) an rlib is not self-contained —
  the whole slice (`aws_lc_sys`, `zeroize`, `untrusted`) must ship, and
  shared deps like `zeroize` (also used by rustls) must match lorry's own
  from-source units by SVH/`-C metadata` exactly, coupling the prebuild to
  the consumer lockfile knife-edge; (c) because the version stamp omits the
  git hash, a stale rlib set after any toolchain rebuild is accepted
  *silently* rather than rejected. The C `.a` boundary has none of these:
  C-ABI-stable across rustc rebuilds, no dependency entanglement,
  version-prefixed symbols fail loudly on mismatch.
* **`AWS_LC_SYS_NO_ASM`** as a simplification: debug-profile-only by
  assertion, and abandons the pregenerated-assembly performance; not viable.

## Risks and open questions

1. **Runtime is unproven.** Compile+link is measured; execution is not.
   Specific hazards, all in the C-runtime seam:
   * `getentropy` path end-to-end (mlibc → `moto_rt_fill_random_bytes` →
     RDRAND).
   * pthread mutexes taken from Rust-std-spawned threads: such threads have
     a zero `UTCB.libc_tcb`; mlibc's lazy-TCB patch
     (`__mlibc_motor_lazy_tcb`, `docs/build-rustc.md`) exists precisely for
     this, but AWS-LC is its biggest exercise yet.
   * mlibc `malloc` (AWS-LC's `OPENSSL_malloc`) coexisting with Rust's
     moto-rt allocator in one process — fine while neither frees the
     other's allocations.
   * `__thread` in AWS-LC C → emulated TLS via `__emutls_get_address`
     (provided by `libmoto_rt_cabi.a`).
   * jitter-entropy library behavior on Motor (disable first, enable
     deliberately).
2. **Flag interactions**: `-D__EXTENSIONS__=1` and `-pthread` against mlibc
   headers (expected harmless; verify in step 2 build logs).
3. **Feature unification**: nothing in a consumer graph may enable
   `aws-lc-sys/all-bindings` or `ssl` (Phase 1: re-arms bindgen; Phase 2:
   loud build error). Worth a comment in each consumer manifest.
4. **Footprint**: ~1.7 MB unstripped growth per converted binary (fixture
   ratio ~2.7×
   vs ring); acceptable for httpd/httpd-axum, but flag if anything on the
   boot path ever adopts aws-lc. Until Phase 2 retires ring from curl, the
   image carries two C crypto stacks and the repo maintains both fork
   families.
5. **Fork maintenance**: the aws-lc entropy patch must be rebased per
   `aws-lc-sys` version bump; the version-prefixed symbols make a missed
   rebuild a link error, not silent skew. Upstreaming patch (2) (and
   ideally patch (1)) would shrink the delta to zero over time.
6. **Provider guidance drift**: rustls recommends aws-lc for performance
   and feature set (incl. post-quantum); if rustls's default-provider
   posture changes across upgrades, the explicit feature selection in
   consumer manifests is what pins behavior.

## Validation

* **Bring-up fixture**: an out-of-tree test binary (aws-lc-rs rand +
  digest + a rustls-aws-lc TLS handshake against a local listener), built
  for `x86_64-unknown-motor`, sftp'd into the VM and ssh-run — the
  established experiment workflow. Gate Phase 1 step 3 on it.
* **In-tree tests**: httpd and httpd-axum are already exercised by the full
  test suite; per AGENTS.md, `src/tests/full-test.sh` must pass three times
  each in debug and release before any commit, and any new test must be
  reachable from it directly or transitively.
* **Phase 2**: lorry's existing gates apply (Linux unit/fixture tests,
  cross byte-identity vs Cargo where applicable,
  `src/bin/lorry/tests/test-native.sh` smoke + `--full` for the native curl
  closure once curl adopts the patched graph).

## Effort estimate

* Phase 1: a few days, dominated by VM runtime validation, not build work.
* Phase 2: a few additional days (prebuild script + two ~20-line vendored
  build.rs patches + seeds/policy + lorry gate runs). No lorry code
  changes.
