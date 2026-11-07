# Motor OS crates

Motor OS publishes three Rust libraries on crates.io:

- `moto-rt`: the runtime ABI. Rust's standard library for Motor OS depends on
  it.
- `moto-sys`: system calls and the shared kernel pages.
- `moto-sdk`: userspace services: IPC, the async runtime, the sys-io clients
  and wire formats, the filesystem traits, logging, and metrics.

`moto-rt-cabi`, the C ABI shim under the C library, lives in the mlibc fork at
`sysdeps/motor/moto-rt-cabi`. The toolchain builds it from the pinned mlibc
revision, using its lockfile and the published `moto-rt` and `moto-sys` crates.
The shim itself is not published to crates.io.

The other libraries in `src/sys/lib` are internal and not published:
`motor-fs`, `memfs`, `virtio-async`, `timeq`, `frusa`, `moto-dns` and
`rt.vdso`.

## Dependency rules

- Crates in `src/sys` use each other by path. When a published crate has a
  path dependency, it also names a version, for example
  `moto-rt = { version = "0.17.9", path = "../moto-rt" }`. The published
  package then takes that crate from crates.io.
- Every other crate takes Motor OS crates from crates.io only. That covers
  `src/bin`, `src/tests`, the forks and the toolchain. They use no path, Git
  source or `[patch]` for these crates. A path copy next to a crates.io copy
  links moto-rt twice, and the two copies' types do not match.
- A program that needs SDK services depends on `moto-sdk = "0.2"`. It uses
  `moto_sdk::rt` and `moto_sdk::sys` rather than its own moto-rt and moto-sys
  dependencies. A program that needs only moto-rt or moto-sys depends on them
  directly, as curl, gix and Lorry do. Do not add the SDK where it is not
  needed, and never to the toolchain.
- The one exception is the imager (`src/imager`). It takes `moto-sdk` and
  `motor-fs` by path, because it is build tooling inside the tree and
  motor-fs is not published. It links only in-tree copies, so it never mixes
  the two sources.

## SDK module map

The SDK combines eleven former crates. Paths below are relative to `moto_sdk`.

| Former crate | SDK module or type |
| --- | --- |
| `fittings` | `iobuf::IoBuf` |
| `moto-mpmc` | `mpmc` |
| `moto-async` | `async_runtime` |
| `moto-ipc` | `ipc` (`io_channel`, `sync`, `stdio_pipe`) |
| `moto-tooling` | `tooling::mode2048`; its DMA `IoBuf` becomes `iobuf::VirtioIoBuf` |
| `async-fs` | `async_fs` (block device and filesystem traits, block cache) |
| `moto-sys-io` | `sys_io` (`api_fs`, `api_net`, `api_vsock`, `icmp`, `stats`) |
| `moto-io-internal` | `io_internal` (hidden from generated API documentation) |
| `moto-io` | `io` (`fs`, `net`) |
| `moto-stats` | `stats` |
| `moto-log` | `log` |

## The SDK's features and targets

- `std`, on by default. On Motor OS it adds the `moto_sdk::rt` and
  `moto_sdk::sys` re-exports, the `log` module and other std-only parts.
  rt.vdso builds the SDK with `default-features = false`, on core and alloc.
- `test-support`, off by default: hooks for systest only. Production builds
  never enable it.
- On Unix, `iobuf::IoBuf` and `tooling::mode2048` are available with or without
  `std`; `async_fs` additionally requires `std`. The imager, motor-fs, memfs
  and russhd use these on the Linux host. Everything else is Motor OS-only.

## Versions and publishing

- Versions follow Cargo's semver rules. One version covers the whole SDK.
- Crates outside `src/sys` see an SDK change only after it is published.
  Publish, then raise their requirement where needed and re-resolve their
  lockfiles. That includes javy-smoke, wasmtime-smoke and the Lorry editor
  fixture, which are built with `--locked`.
- Publish moto-rt or moto-sys first when the SDK needs a newer one, and raise
  the SDK's floor for it.
- `src/tests/test-sdk-package.sh`, part of `full-test.sh`, builds the SDK the
  way crates.io would ship it, against crates.io only. Its lock pins each
  direct dependency at the lowest version the manifest allows. After a
  dependency change, `test-sdk-package.sh --update-lock` writes a new lock.
- Publish from `src/sys` after the gates pass, and from a pushed commit: the
  package records its commit, and crates.io links to it.
- Crates the SDK replaced, such as moto-ipc 0.2.4, stay on crates.io. New code
  does not use them.

### Published releases: moto-sys 0.4.0 and moto-sdk 0.2.0

Both versions are published. The version changes follow
[Cargo's semver rules](https://doc.rust-lang.org/cargo/reference/semver.html):
removing public APIs requires a new compatibility range, including through
the SDK's `sys` re-export.

- `moto-sys 0.4.0` exposes `free_pages()` and `low_memory()` for the current
  kernel's shared-page layout. It removes `memory_pressure()`, the old
  admission reservation fields, `stats::AdmissionStats`, and
  `SysMem::query_admission_stats()` and its query flag.
- `moto-sdk 0.2.0` requires `moto-sys 0.4.0`, re-exports those APIs on Motor
  OS with `std`, and includes IP-device support and TCP protocol-state stats
  for the matching sys-io service. The published runtime remains
  `moto-rt 0.17.9`.

`moto-sys 0.4.0` is published from commit `70da7181`, and `moto-sdk 0.2.0`
from `f8f22e77`. The SDK package-test
lock is refreshed with its final registry checksum, retaining all unrelated
dependency versions and the declared direct dependency floors. The standalone
SDK Motor OS publish dry run passes against the published system crate.

The required three debug and three release full-image gates pass on the
repaired OOM cancellation test and refreshed SDK package lock. The test now
covers recovery before cancellation and requires child resources to be
reclaimed before releasing pressure allocations or retained handles. The
original failure, diagnosis and complete validation results are recorded in
the git history of `docs/plans/russhd-forwarding.md`, removed after commit `85f39f3d`.

Russhd now uses both published versions. Applications that need the new API
use `moto-sdk = "0.2"` and update their registry lockfiles. Existing `0.1`
consumers keep their current requirement until they migrate. These releases
did not change runtime or kernel implementations.
