# moto-api: one published crate for Motor OS userspace services

Status: plan, 2026-10-20. No code changed yet. Owner rulings of 2026-10-20:
crates under `src/sys` reference each other by path; every other crate (in
`src/bin`, `src/tests`, the forks, the toolchain) takes Motor OS crates from
crates.io only; no external repository takes a Motor OS crate by git or path;
`motor-fs` stays unpublished.

## Why one crate

Programs outside `src/sys` need thin slices of the system libraries: rmux the
IPC channels, russhd the filesystem client with role permissions plus the
async runtime, the log facade and the terminal helpers, the benchmarks and
smoke suites the stats protocol. The forks need none of them since Wasmtime's
filesystem adapter became path-based (2026-10-20). Publishing the eleven
libraries that serve those slices as separate crates means eleven versions to
bump for every protocol change and a dependency graph that nobody outside the
tree uses. They are about 26k lines that only ever change together, so they
become one crate, `moto-api`, and the published Motor OS crates are exactly
three: `moto-rt` (runtime ABI, std's dependency), `moto-sys` (syscalls) and
`moto-api` (userspace services).

## Crates combined into moto-api

All eleven are merged as modules and their directories under `src/sys/lib`
are deleted. Module names mirror the crate names, so a call site changes only
its prefix (`moto_ipc::sync::Client` becomes `moto_api::ipc::sync::Client`).

| Crate (version) | Lines | Module | In-tree consumers today | Outside `src/sys` |
| --- | --- | --- | --- | --- |
| fittings (0.1.0) | 125 | `iobuf` | moto-tooling, async-fs, motor-fs | imager |
| moto-mpmc (0.1.0) | 4513 | `mpmc` (`select!`) | moto-async, moto-io, systest | — |
| moto-async (0.1.0) | 3412 | `runtime` (`async` is a keyword) | rt.vdso, sys-io, strobe, sysbox, virtio-async, systest, virtio-task-tests | russhd |
| moto-ipc (0.2.6; crates.io has 0.2.4) | 4203 | `ipc` (`io_channel`, `sync`, `stdio_pipe`) | rt.vdso, sys-io, strobe, sys-tty, dns-resolver, sysbox, moto-dns, systest | rmux |
| moto-tooling (0.1.0) | 348 | `tooling` (`mode2048`); its DMA buffer becomes `iobuf::VirtioIoBuf` | sys-io, virtio-async, async-fs, motor-fs | russhd |
| async-fs (0.1.0; name taken on crates.io) | 1715 | `async_fs` (block device and filesystem traits, block cache) | moto-io, moto-sys-io, motor-fs, virtio-async, sys-io | imager |
| moto-sys-io (0.2.4) | 2448 | `sys_io` (`api_fs`, `api_net`, `api_vsock`, `icmp`, `stats`) | rt.vdso, sys-io, sysbox, systest | — |
| moto-io-internal (0.1.0) | 641 | `io_internal` (`#[doc(hidden)]`) | rt.vdso, sys-io, moto-io | — |
| moto-io (0.1.0) | 7713 | `io` (`fs` client with role permissions, `net`) | rt.vdso, strobe, sysbox, systest | russhd |
| moto-stats (0.1.0) | 490 | `stats` | sys-io, strobe, sysbox, systest, tokio-tests | rnetbench, rust-analyzer-smoke, wasm-smoke-suite |
| moto-log (0.1.0) | 317 | `log` | strobe, sys-init, sys-tty, dns-resolver, systest | russhd |

Total: 58 source files, about 25.9k lines, 119 importing files elsewhere in
the tree.

## Stays outside

- `motor-fs` (10.7k lines): path dependency of sys-io and the imager, not
  published (owner ruling).
- `virtio-async`, `timeq`, `frusa`, `moto-dns`, `rt.vdso`: internal, path.
- `moto-rt`, `moto-sys`: published as today; inside `src/sys` they are
  `version` plus `path` dependencies.
- `moto-rt-cabi`: already published separately; the toolchain builds it from
  the tree into the sysroot.
- The imager (`src/imager`) is build tooling inside the tree and keeps path
  dependencies on `moto-api` and `motor-fs`; it links only in-tree copies, so
  it never mixes sources.

## Shape of the crate

- `#![no_std]` with `alloc` at the root, since rt.vdso uses it. Std-only parts
  (`log`, `stats`, `tooling::mode2048`, the file-backed block device and the
  std allocator path of `iobuf`) sit behind a `std` feature.
- Two Cargo features, `std` (default) and `test-support`; see below. rt.vdso
  builds the crate with `default-features = false`.
- Dependencies: `moto-rt = { version = "0.17", path = "../moto-rt" }`,
  `moto-sys = { version = "0.3.2", path = "../moto-sys" }`, and the external
  crates the eleven use today (crossbeam, crossbeam-utils, log, async-trait,
  lru, bytemuck; tokio and camino only for `cfg(not(target_os = "motor"))`,
  as in async-fs now).
- `iobuf` holds both buffer types: `IoBuf`, fittings' pinned buffer aligned to its
  own size, and `VirtioIoBuf`, moto-tooling's Motor-only wrapper around it that
  caches the physical addresses a virtio device needs (whole buffer and per 4 KiB
  page). The rename is part of the merge, so the two types stop sharing a name;
  the call sites in virtio-async, sys-io, async-fs and motor-fs change with it.
- moto-io's build script, which forbids blocking calls under `src/net`, moves
  with that module. moto-mpmc's and moto-async's integration tests move to
  `moto-api/tests`.
- Inside moved code, `crate::` paths gain the module prefix, and `select!`'s
  `$crate::` paths (59 uses) become `$crate::mpmc::`.
- `src/sys/Cargo.toml`: one member replaces eleven; its `[patch.crates-io]`
  loses the moto-ipc, moto-log and moto-sys-io entries.

## Cargo features

The nine flags spread over the eleven crates collapse to two.

- `std` (default). Everything that needs the standard library: the `log`
  module (moto-log is std-only); the `stats` module with its IPC client
  (moto-stats' `userspace` is folded in: nothing in the tree builds moto-stats
  without it, and the crate is std-only anyway); `sys_io::icmp` and
  `sys_io::stats`; the std implementation of `async_fs` (std collections and
  locks, `Result = std::io::Result`) and, off Motor, its file-backed block
  device. Enabled by every userspace consumer: sys-io, strobe, sys-init,
  sys-tty, dns-resolver, sysbox, systest, russhd, rmux, rnetbench, the smoke
  suites and the imager. Disabled only by rt.vdso, which is `no_std` and builds
  the crate with `default-features = false` in its own `cargo build
  -Zbuild-std` invocation (`src/sys/lib/rt.vdso/build.sh`), so workspace
  feature unification never turns `std` on for it. It absorbs fittings' and
  moto-tooling's `std`, which only chose `std::alloc` over the `alloc` crate
  (the merged crate uses `alloc` throughout), and async-fs' and moto-sys-io's
  `std`.
- `test-support`, off by default. Test-only hooks: moto-log's
  `test_set_tag_id` and `test_rpc_enabled`, which systest uses to check the
  log RPC path, and the gate of moto-async's host-only `fallible` integration
  test, the allocator-construction regression that `full-test-prepare.sh` runs
  on Linux under today's `host-construction-test` (it becomes
  `required-features = ["test-support"]` on that test). Enabled by systest and
  by that host test run.

Removed rather than folded:

- moto-ipc's `stdio-pipe` gated `ipc::stdio_pipe`, the simplex pipe rt.vdso
  uses for cross-process stdio, kept in the library only so it can be
  unit-tested on the host. It adds no dependency, so it compiles
  unconditionally, `#[doc(hidden)]`, with its "rt.vdso only" module doc.
- moto-io's `netdev`, mirrored by rt.vdso's feature of the same name, gates
  test instrumentation: leak checks and counters, fault injection and the
  drop-backpressure and RPC-cancel test state machines. `rt.vdso/build.sh`
  always passes `--features netdev`, so every shipped vdso carries it. The flag
  is removed from moto-api, from rt.vdso's `Cargo.toml` and `build.sh`, and
  from systest, and the code under it is deleted, not kept: in rt.vdso the
  `netdev` arms of `vdso_internal_helper` (post-teardown leak check, pool
  client count, connect poisoning, exhausted-tx-pages arming, construction
  failure injection for channels and the pool runtime, allocator leak
  diagnostics) and `RtTcpStream::arm_writable_without_pages_for_test`; in
  moto-io's net module the hooks they call (`assert_runtime_empty`,
  `poison_connect_for_test`, `fail_construction_for_test`, the
  `*_drop_backpressure_test` and `*_rpc_response_cancel_test` state machines,
  the waiter and socket counters), 79 gated sites in `channel.rs`, `tcp.rs`,
  `udp.rs` and `wait.rs`. The systest cases that drive them go with them:
  `test_channel_allocation_failure`, `test_pool_runtime_allocation_failure`
  and `test_sys_io_unavailable_fails_all` in `net_driver.rs`,
  `test_channel_teardown`, `test_native_listener_drop_under_backpressure` and
  `test_native_stream_drop_under_backpressure` in `tcp.rs`, the pool client
  count check in `diagnostics.rs`, and the helper calls in `poll.rs`
  (`run_mio_accept_pump_case`, `test_writable_registration_arms_page_waiter`).
  moto-rt's `internal_helper` vtable entry stays; the vdso helper keeps only
  its ungated arms.

## Steps

1. **Interim, before the merge:** rmux, russhd, rnetbench, rust-analyzer-smoke
   and wasm-smoke-suite (and through it javy-smoke, wasmtime-smoke and lorry's
   editor-workspace test program) go back to path dependencies on moto-rt and
   moto-sys, as before 2026-10-20, so the tree builds: a crate cannot mix
   crates.io moto-rt with an in-tree library that brings the in-tree moto-rt
   along. rush, lorry, gears, gix, curl and httpd-axum stay on crates.io. The
   twelve-crate publishing metadata prepared on 2026-10-20 is dropped, except
   the `repository` fix of moto-sys and moto-sys-io.
2. **The merge**, one atomic patch under `src/sys`: create `moto-api`, move
   the sources, fix paths and features, update every manifest and the 119
   importing files, delete the eleven directories; rewire the feature users
   (rt.vdso `default-features = false`; the `netdev` feature and the code under
   it deleted from rt.vdso, moto-io's net module, `build.sh` and systest;
   systest `features = ["test-support"]`, `full-test-prepare.sh` and the
   moto-mpmc, moto-async and moto-ipc host tests in `full-test.sh` pointing at
   the merged crate). Gate: three debug and three
   release `full-test.sh` runs, `full-test-dev.sh --release`, `test-wasm.sh`
   under QEMU and Cloud Hypervisor (the smoke suites move with the rest).
3. **Publish** (owner): `cargo publish -p moto-api` from `src/sys`, version
   0.1.0; moto-rt 0.17.9 and moto-sys 0.3.2 are already on crates.io.
4. **Switch the outside**: every crate outside `src/sys` declares
   `moto-api = "0.1"`, `moto-rt = "0.17"` and `moto-sys = "0.3.2"`; lockfiles
   re-resolved; no path dependency remains outside `src/sys` except the
   imager's. Gate again, commit. The forks already take only crates.io Motor
   OS crates (wasmtime `08a09edea`, javy `12a6c52`).
5. **Docs**: replace the old crate names in `docs/*.md`; the dependency rules
   go into `AGENTS.md` (owner).

## Open points

- Module name for moto-async: `runtime` proposed.
- moto-ipc 0.2.4 stays on crates.io, orphaned.
- The in-tree moto-rt source is 0.17.8 while crates.io has 0.17.9; sync before
  the next moto-rt publish.
- A change to any module bumps `moto-api` as a whole; that is the intended
  trade: one version, one publish.
