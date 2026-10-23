# Motor OS crates

Motor OS publishes three Rust libraries on crates.io:

- `moto-rt`: the runtime ABI. Rust's standard library for Motor OS depends on
  it.
- `moto-sys`: system calls and the shared kernel pages.
- `moto-sdk`: userspace services: IPC, the async runtime, the sys-io clients
  and wire formats, the filesystem traits, logging, and metrics.

`moto-rt-cabi`, the C ABI shim under the C library, is published separately.
The toolchain builds it from the tree.

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
- A program that needs SDK services depends on `moto-sdk = "0.1"`. It uses
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
  and russhd use these on the Linux host. Everything else is Motor-only.

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
