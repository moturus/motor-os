# moto-sdk: one published crate for Motor OS userspace services

Status: plan, revised 2026-10-21. Preparatory steps (a), (b), and (c) are
committed. SDK consolidation has not started.
Owner rulings of 2026-10-20:
crates under `src/sys` reference each other by path; every other crate (in
`src/bin`, `src/tests`, the forks, the toolchain) takes Motor OS crates from
crates.io only; no external repository takes a Motor OS crate by git or path;
`motor-fs` stays unpublished. The imager keeps the path-dependency exception
described below. Owner rulings of 2026-10-21: `moto-sdk` re-exports `moto-rt` as
`rt` and `moto-sys` as `sys`, both only when `std` is enabled. Remove `netdev`
entirely and delete its instrumentation from rt.vdso, sys-io and other
production components to remove runtime overhead. Networking test hooks are
only for systest's own SDK instance, behind `test-support`. Three preparatory
patches land before the consolidation (see "Preparatory steps"): the edition
move, the `netdev` removal, and the native test phase with its dependency
closure preinstalled on the developer image. moto-io's build script is dropped.
The developer image stages the sources under test at
`/devtools/src/motor-os/sys/lib/`, and the test step runs only `lorry test`.
Later rulings of 2026-10-21 replaced the host precompile: units built on Linux
can never be cache hits on Motor (see "Developer image requirement"), so
`make dev.img` boots the new image once and vendors and compiles there.
A registry build script may compile in the test step, as under Cargo.

The consolidation itself is one large patch, after the preparatory patches.
moto-async becomes `async_runtime` (the Rust module spelling of the requested
`async-runtime`). Backward compatibility is not required for this change:
update the code and pass all build/test gates. Follow standard Rust/Cargo
versioning; add no machinery for a future breaking-change workflow.

The Unix SDK surface is limited to `async_fs`, `iobuf::IoBuf` and
`tooling::mode2048`. MPMC, async-runtime and stdio-pipe remain Motor-only;
their host tests move to native `lorry test` runs in preparatory step (c).
MPMC will not gain a Unix implementation.

## Why one crate

Programs outside `src/sys` need thin slices of the system libraries: rmux the
IPC channels, russhd the filesystem client with role permissions plus the
async runtime, the log facade and the terminal helpers, the benchmarks and
smoke suites the stats protocol. The forks need none of them since Wasmtime's
filesystem adapter became path-based (2026-10-20; true at the fork revision
`src/build-addon-sources.sh` pins, which the add-on build checks out). Publishing
the eleven libraries that serve those slices as separate crates means eleven
versions to bump for every protocol change and a dependency graph that nobody
outside the tree uses. These closely coupled libraries total about 23k lines
and become one crate, `moto-sdk`. The three primary published Rust libraries
are `moto-rt` (runtime ABI, std's dependency), `moto-sys` (syscalls) and
`moto-sdk` (userspace services); `moto-rt-cabi` remains separately published.

## Crates combined into moto-sdk

All eleven are merged as modules and their directories under `src/sys/lib`
are deleted. Most call sites change only their prefix
(`moto_ipc::sync::ClientConnection` becomes
`moto_sdk::ipc::sync::ClientConnection`); the table lists module renames.

| Crate (version) | Lines | Module | In-tree consumers today | Outside `src/sys` |
| --- | --- | --- | --- | --- |
| fittings (0.1.0) | 125 | `iobuf` | moto-tooling, async-fs, motor-fs | imager |
| moto-mpmc (0.1.0) | 1786 | `mpmc` | moto-async, moto-io, systest | — |
| moto-async (0.1.0) | 3412 | `async_runtime` | rt.vdso, sys-io, strobe, sysbox, virtio-async, systest, virtio-task-tests | russhd |
| moto-ipc (0.2.6; crates.io has 0.2.4) | 4203 | `ipc` (`io_channel`, `sync`, `stdio_pipe`) | rt.vdso, sys-io, strobe, sys-tty, dns-resolver, sysbox, moto-dns, systest | rmux |
| moto-tooling (0.1.0) | 348 | `tooling` (`mode2048`); its DMA buffer becomes `iobuf::VirtioIoBuf` | sys-io, virtio-async, async-fs, motor-fs | russhd |
| async-fs (0.1.0; name taken on crates.io) | 1715 | `async_fs` (block device and filesystem traits, block cache) | moto-io, moto-sys-io, motor-fs, virtio-async, sys-io | imager |
| moto-sys-io (0.2.4) | 2448 | `sys_io` (`api_fs`, `api_net`, `api_vsock`, `icmp`, `stats`) | rt.vdso, sys-io, sysbox, systest | — |
| moto-io-internal (0.1.0) | 641 | `io_internal` (`#[doc(hidden)]`) | rt.vdso, sys-io, moto-io | — |
| moto-io (0.1.0) | 7713 | `io` (`fs` client with role permissions, `net`) | rt.vdso, strobe, sysbox, systest | russhd |
| moto-stats (0.1.0) | 490 | `stats` | sys-io, strobe, sysbox, systest, tokio-tests | rnetbench, rust-analyzer-smoke, wasm-smoke-suite |
| moto-log (0.1.0) | 317 | `log` | strobe, sys-init, sys-tty, dns-resolver, systest | russhd |

Total: 58 source files, about 23.4k lines, 136 importing files elsewhere in
the tree.

Of the eleven, only moto-ipc is on crates.io (0.2.4). moto-log and
moto-sys-io were never published, so their `[patch.crates-io]` entries are
dead and go with the merge. `moto-sdk` is free on crates.io.

## Stays outside

- `motor-fs` (10.7k lines): path dependency of sys-io and the imager, not
  published (owner ruling).
- `memfs`.
- `virtio-async`, `timeq`, `frusa`, `moto-dns`, `rt.vdso`: internal, path.
- `moto-rt`, `moto-sys`: published as today; inside `src/sys` they are
  `version` plus `path` dependencies.
- `moto-rt-cabi`: already published separately; the toolchain builds it from
  the tree into the sysroot.
- The imager (`src/imager`) is build tooling inside the tree and keeps path
  dependencies on `moto-sdk` and `motor-fs`; it links only in-tree copies, so
  it never mixes sources.

## Shape of the crate

- Edition 2024. Preparatory step (a) moves the four 2021 crates first, so the
  merge moves no edition.
- `#![no_std]` with `alloc` at the root and conditional access to `std`, since
  rt.vdso uses it. Std-only parts sit behind `std`. `stats` and
  `tooling::mode2048` already support `no_std` with `alloc` and retain that
  support; `iobuf` uses `alloc` throughout.
- The nightly features the merged code needs (`allocator_api`,
  `likely_unlikely`, `local_waker`, `negative_impls`, `async_trait_bounds`,
  `trait_alias`) all belong to Motor-only modules. Enable them with
  `cfg_attr(target_os = "motor", feature(...))` so the Unix slice needs none.
- Two Cargo features: `std` (default) and `test-support`; see below.
  rt.vdso and every transitive SDK dependency in its build disable defaults.
- moto-async's API moves under `moto_sdk::async_runtime`. Rust module names
  use underscores rather than hyphens; this is the requested `async-runtime`
  name, not a separately published crate.
- Motor-only dependencies: `moto-rt = { version = "0.17", path = "../moto-rt" }`
  and `moto-sys = { version = "0.3.2", path = "../moto-sys" }`. Keep external
  dependencies where their modules need them: crossbeam/crossbeam-utils for
  the Motor-only code; log, async-trait, lru and bytemuck for the filesystem
  code; tokio and camino for the Unix `std` filesystem implementation.
- On Motor with `std`, the crate root exposes the underlying crates directly:

  ```rust
  #[cfg(all(target_os = "motor", feature = "std"))]
  pub use moto_rt as rt;
  #[cfg(all(target_os = "motor", feature = "std"))]
  pub use moto_sys as sys;
  ```

  Motor SDK consumers can use `moto_sdk::rt` and `moto_sdk::sys`, or local
  import aliases, and drop redundant direct dependencies. These are re-exports, so
  their types are the same types the SDK uses. Neither alias exists on Unix
  or without `std`: the Motor SDK implementation and `no_std` consumers retain
  direct dependencies on `moto-rt` and `moto-sys` as needed. This does not add an SDK
  dependency to Rust stdlib, moto-rt or moto-sys.
- `iobuf` holds both buffer types: `IoBuf`, fittings' pinned buffer aligned to its
  own size, and `VirtioIoBuf`, moto-tooling's Motor-only wrapper around it that
  caches the physical addresses a virtio device needs (whole buffer and per 4 KiB
  page). The rename is part of the merge, so the two types stop sharing a name;
  the call sites in virtio-async, sys-io, async-fs and motor-fs change with it.
- The SDK has no build script (moto-io's goes in preparatory step (b)).
  Tests move with their code. The two integration tests named `fallible`
  need distinct names, such as `mpmc_fallible` and `async_runtime_fallible`,
  under `moto-sdk/tests`. Both are Motor-only native tests since step (c).
- Inside moved code, `crate::` paths gain the appropriate module prefix. No
  crate in the merge exports a macro.
- `src/sys/Cargo.toml`: one member replaces eleven; its `[patch.crates-io]`
  loses the moto-ipc, moto-log and moto-sys-io entries.

## Cargo features

The flags consolidate to `std` and `test-support`. Production builds contain
none of the former `netdev` instrumentation, which preparatory step (b)
removes; the retained SDK hooks serve systest only.

- `std` (default). On Motor, enables the `rt` and `sys` re-exports, the `log`
  module, `sys_io::icmp` and `sys_io::stats`. On both supported target families,
  enables the std implementation of `async_fs`
  (std collections and locks, `Result = std::io::Result`) and, off Motor, its
  file-backed block device. Enabled by userspace consumers including sys-io,
  strobe, sys-init, sys-tty, dns-resolver, sysbox, systest, russhd, rmux,
  rnetbench, the smoke suites and the imager. rt.vdso builds separately with
  `default-features = false` and `-Zbuild-std=core,alloc`. Every transitive
  dependency on the SDK in that invocation must also disable defaults,
  especially the replacement for `moto-dns`'s `moto-ipc` dependency. A separate
  build prevents workspace feature unification, but transitive dependencies
  can still enable `std`. Check the resolved feature graph, as well as
  building the VDSO.
- `test-support`, off by default. Test-only hooks: moto-log's
  `test_set_tag_id` and `test_rpc_enabled`, which systest uses to check the
  log RPC path, and the moto-io networking hooks that step (b) keeps under
  moto-io's own `test-support` feature. The merge carries that feature over
  unchanged. It does not expose Motor modules on Unix or imply `std`.
  rt.vdso, sys-io, other production services and ordinary host tools never
  enable it, directly or transitively.

Systest enables `moto-sdk/test-support` in its own Cargo invocation. The
Makefile builds every component in its own `cargo build`, so features do not
unify across components; keep it that way, since building them together can
put the hooks back into services. Check the resolved production feature
graphs to ensure `test-support` stays off. The VDSO and services used by
systest are the ordinary production builds, with no alternative instrumented
VDSO or service image.

Flags removed without removing functionality:

- moto-ipc's `stdio-pipe` gated `ipc::stdio_pipe`, the simplex pipe rt.vdso
  uses for cross-process stdio. It remains in the SDK, behind the Motor target
  gate, without a separate feature gate. Keep `#[doc(hidden)]` and its
  "rt.vdso only" module doc; its unit tests run natively with `lorry test`.
- moto-stats' `userspace`: no current consumer disables it. Keep the stats
  protocol and client available on Motor without requiring `std`.
- fittings' and moto-tooling's allocator-selection `std` flags: use `alloc`.
- moto-async's `host-construction-test` and the host exception in `timeq.rs`:
  already removed by step (c); the entire `async_runtime` module is Motor-only.

## Target boundaries and validation

Use `#[cfg(any(target_os = "motor", unix))]` for `async_fs`, `iobuf::IoBuf`
and `tooling::mode2048`. Supported Unix SDK builds enable `std`; the filesystem
implementation uses Tokio there. Imager, motor-fs and memfs need the filesystem API; imager and motor-fs
also use `IoBuf`. Linux russhd needs `mode2048` for terminal handling.

All other SDK modules, including `mpmc`, `async_runtime`, `ipc`, `io`,
`sys_io`, `io_internal`, `stats`, `log` and `iobuf::VirtioIoBuf`, use
`#[cfg(target_os = "motor")]`, plus any applicable `std`/`test-support` gate.
Apply the same target split to dependencies. Ordinary Unix builds do not
compile Motor modules, even with `test-support` enabled.

MPMC uses Motor waits/wakeups, thread handles, clocks and a futex-backed
mutex (`moto-mpmc/src/{utils,context,waker}.rs`). It stays Motor-only; its
tests run natively since step (c), with the async-runtime construction and
stdio-pipe tests.

| Build | Required behavior |
| --- | --- |
| Motor, default features | Userspace services and applications; `rt` and `sys` re-exports available; no networking test instrumentation |
| Motor, defaults disabled | SDK and full rt.vdso dependency graph build with core/alloc; no `rt` or `sys` re-exports or networking test instrumentation |
| Motor systest, `std,test-support` | SDK networking and log hooks are confined to systest; VDSO and services remain production builds |
| Unix, default features | Portable SDK modules support imager, motor-fs, memfs and russhd; no Motor dependencies or test hooks |
| Motor, native `lorry test` | MPMC, async-runtime construction and stdio-pipe tests compile and run inside Motor OS from the staged SDK sources and the preinstalled, precompiled dependency closure, offline |

The merge re-points the native test phase from the standalone crates to the
SDK workspace and keeps the same tests executing. Verify that the expected
tests execute, not merely that test compilation succeeds.

Retain host tests for the portable modules, imager, motor-fs, memfs and Linux
tools, including russhd's terminal tests. Update moto-tooling's test commands
to the SDK's portable tests. Keep the standalone IPC-sync host harness and
update its source include: it supplies its own syscall stubs and does not
expose IPC in the Unix SDK. Other host suites (frusa, netstack, moto-sys,
sys-init's parser, build tooling and application tests) keep their existing
locations. SFTP scripts remain host-driven tests against the Motor VM.
Verify the std-only `rt`/`sys` re-exports on Motor, including type identity
with SDK APIs.

Verify production builds in both debug and release without `test-support`,
including when the test image contains systest.

## Developer image requirement

The developer image carries everything a native `lorry test` run needs, so
the run is offline and starts with `lorry test`: the sources under test,
their whole dependency closure, and the workspace's admission state. Before
the merge that is moto-mpmc, moto-async and moto-ipc with moto-rt and
moto-sys; after it, moto-sdk with moto-rt and moto-sys.

Host-built units cannot be native cache hits. Lorry's cache key covers the
path, size and mtime of the Lorry and rustc binaries, and motor-fs stamps every
file with the image-build time. The key also covers the host triple and
rustc's host line. A build script such as crossbeam-utils' must run on Motor,
and Lorry, like Cargo, never caches build-script executables. So the closure
is compiled natively, once per image build (owner rulings of 2026-10-21).
As built for step (c):

- The imager stages the in-tree crates under
  `/devtools/src/motor-os/sys/lib/`, mirroring the tree so `../moto-rt` path
  dependencies resolve. A static workspace manifest from `img_files` names the
  members under test and makes them the default members.
- `src/sys-lib-workspace.sh` assembles the same workspace on the host. Its
  Cargo.lock comes from `src/sys/Cargo.lock`, so native tests use the in-tree
  dependency versions.
- `src/build-motor-os.sh` has an add-on, `sys-lib-deps`: a host-built Lorry
  runs `lorry fetch --locked` on that workspace. Fetch takes every package the
  lockfile names, whatever features are selected, so the lockfile and the
  recipe alone key the add-on. The assembly overlay goes into the image's
  user-role repository (`/devtools/lorry/user/vendor`). On Motor, Lorry allows
  a `system` repository only in the Linux base layer. A changed lockfile needs
  `src/build-motor-os.sh --sys-lib-deps-only`, like any other devtools change.
- `make dev.img` runs `src/prepare-dev-image.sh`. It boots the new image once
  under QEMU, installs the workspace's Cargo.lock, and runs native
  `lorry vendor --locked --offline --accept-all` and
  `lorry test --no-run -j 4`. It then removes `target/` and shuts down. The
  image keeps the admission record, the motor user's approval under
  `/user/cfg/lorry-workspaces/`, and the compiled dependencies in
  `/devtools/lorry/user/cache`. This is part of the image build, not of the
  native test step. It has its own deadline (300 seconds release, 1200 debug;
  it takes about 10 seconds and 4 minutes), and it succeeds only when the
  guest shuts down by itself: a forced stop could lose unflushed writes, and
  any failure removes the image. `--accept-all` gives the workspace
  Cargo-like trust, so `lorry.toml` needs no grants for it.
- The test step in `test-dev-sources.sh` runs only `lorry test -j 4`, offline.
  It fails if a registry library or proc macro compiles, or if Lorry prints
  "Rebuilding global dependency cache". A registry build script may compile.
  Every `#[test]` in the three crates' sources must pass.
  Both runs use four jobs because build-script environments, which include
  `NUM_JOBS`, enter the cache keys.
- No Lorry code changed. Its spec and design now say the image ships these
  objects and cache entries.
- After the merge the same flow covers `moto-sdk`. Its closure adds proc
  macros (async-trait, bytemuck_derive), which Lorry caches, and build
  scripts (proc-macro2, quote, syn), which compile in the test step.

## Publication and versioning

One version and one publish covers the merged modules. Follow standard
Rust/Cargo versioning. No backward compatibility with earlier SDK/OS versions
is required for this change. Update the affected services and applications,
verify the packaged SDK, and pass all test gates with the resulting OS image
and registry consumers. Do not add compatibility shims, version negotiation,
or infrastructure for hypothetical future breaking changes.

Before the first publish, use `cargo package` verification and build/test the
extracted package in isolation for the supported configurations above, with
registry moto-rt/moto-sys and no workspace patches. Packaging strips path
dependencies and patches; passing in-tree tests alone is insufficient. Check
the packaged source paths and required dependency versions.
The selected Motor toolchain is required for Motor builds; do not assume a
default host `cargo publish` verification covers the Motor configurations.
Package verification must also be wired into the full-test gate. Fetch required
registry inputs during preparation; regular tests use cached inputs and locked,
offline resolution. Local moto-rt is already 0.17.9; verify builds against its
published version rather than scheduling a version-number sync. moto-sys is
0.3.2.

## Preparatory steps

Three patches, each committed on its own after its gate, in this order. The
core gate is three debug and three release `full-test.sh` runs.

### (a) Edition 2024

Move moto-mpmc, moto-ipc, moto-stats and moto-log from edition 2021 to 2024;
the other seven crates are there already. Edition 2024 warns on unsafe
operations in `unsafe fn` bodies: the ten bodies without them, all in
moto-ipc's `sync.rs` and `stdio_pipe.rs`, get inner `unsafe` blocks. No new
warnings. The IPC-sync host harness compiles `sync.rs` with `--edition=2021`
in `src/tests/test-moto-ipc-sync.sh`; change it to 2024 in the same patch.

The same patch deletes moto-mpmc's `select!` macro and `Select` API (owner
ruling 2026-10-21). Nothing in the tree used them, and the macro had not
compiled since the port: it named a `never` channel the port dropped, and its
non-blocking rules transmuted a `Result` into an `Option`, which inverts the
outcome because the port's `Token` has no niche. The select handles, the
wakers' watch lists and the four select error types go with them. moto-mpmc
keeps `bounded`, `try_bounded`, the endpoints and their errors.
Gate: the core gate.

### (b) Remove `netdev`

rt.vdso's `build.sh` builds the production VDSO with `--features netdev`
today, so this removes real overhead.

- Delete the `netdev` feature from the rt.vdso, moto-io and systest manifests
  and from both cargo lines in `src/sys/lib/rt.vdso/build.sh`.
- rt.vdso: delete all seven arms of `vdso_internal_helper` in
  `src/net/rt_net.rs` (leak check, pool client count, connect poisoning,
  writable-without-pages, channel and runtime construction failure, allocator
  leak diagnostic). Delete `arm_writable_without_pages_for_test` in
  `rt_tcp.rs`; `FAIL_RUNTIME_CONSTRUCTION_FOR_TEST`, its setter and its load in
  `net/pool.rs`; and `NET_POOL.client_count` and `NET_POOL.assert_empty`,
  which only the arms call. The moto-rt `internal_helper` ABI entry and the
  dispatcher in `main.rs` stay; no replacement test helper is added.
- sys-io: has no test instrumentation; nothing to remove.
- moto-io: rename the gate to a new `test-support` feature and keep only the
  hooks systest calls directly through its own SDK instance:
  `with_tx_pages_exhausted_for_test` (tcp and udp), `inject_empty_rx_for_test`,
  `channel_udp_socket_count_for_test`, `fail_for_test`,
  `channel_rpc_waiter_count_for_test`, `channel_tx_waiter_count_for_test`,
  `fill_stream_drop_send_queue_for_test`, the `rpc_response_cancel_test`
  functions, and the listener-drop and stream-drop state machines plus the
  counters and fields these hooks read. Delete `poison_connect_for_test`,
  `fail_construction_for_test`, `assert_runtime_empty` and whatever only they
  used. Every retained field, update and branch shares the gate, so an SDK
  instance without `test-support` carries none of it.
- Delete moto-io's `build.rs`. The net module's no-blocking contract (no
  `SysCpu::spawn`, `block_on_sync`, `SyncWaiter`, `thread::sleep`,
  `sched_yield` outside comments) becomes a grep over the module in
  `full-test.sh`.
- systest and mio-test: networking `internal_helper(0, ..)` calls lose their
  VDSO side. The separate diagnostic dispatch group (`internal_helper(1, ..)`
  in `diagnostics.rs`) remains. Rewrite a
  test only where systest can exercise and assert the behavior through its
  SDK instance or public APIs; otherwise remove it and record the coverage
  loss in the commit message. No weakened or empty passing tests. SDK-level
  replacements do not establish coverage of VDSO pool internals.

Gate for this patch (owner ruling 2026-10-21): one debug and one release
`full-test.sh`, plus one `full-test-dev.sh --release`. The full-test workflow
checks production feature graphs for `test-support` and the network module's
no-blocking contract through `test-net-contract.sh`.

Local validation prerequisite: the installed Wasmtime assembly was built from
`fda311d08cf93052a1af34f50f96271d1ad1b556` and lacked
`memory64-grow.cwasm`, which stopped the developer gate's WASM phase.
`src/build-motor-os.sh --wasmtime-only` refreshed it, updating the clean sibling
`../wasmtime` checkout to the repository's existing pin,
`08a09edeacd8eb82399f9e4bbbba7d06e7f97292`, and rebuilding the runtime and
fixtures. Step (b) adds no source patch to that fork. One debug and one release
`full-test.sh` passed. The complete developer release gate passed after the
refresh, including both memory64 checks and all 98 Wasmtime commands on each
image. Formatting and strict Clippy checks passed for the touched crates.

Coverage changes to carry into the step (b) commit message:

- Remove the VDSO pool cold-start coalescing and channel-churn live-allocation
  tests: they require private pool/allocator introspection.
- Remove the injected sys-io-unavailable, channel-construction OOM and
  runtime-construction OOM tests. Their production failure branches remain;
  their fault-injection switches are deleted.
- Remove the channel-teardown leak test and the final mio-test leak
  assertion. Native driver shutdown, reservation accounting and cancellation
  tests remain, but do not prove that the VDSO pool is empty.
- Keep the public consecutive-accept readiness test; remove its forced
  provisioning-failure case and pool-layout assertions. Recovery of the
  VDSO accept pump after that injected failure is no longer covered.
- Replace the VDSO writable-registration hook test with a native
  `maybe_can_write` test that exhausts TX pages and asserts the WRITABLE edge
  on release. This tests the SDK operation, not VDSO poll registration.

### (c) Native tests and the preinstalled closure

- Implement the "Developer image requirement" above for moto-mpmc,
  moto-async and moto-ipc with moto-rt and moto-sys.
- Flip the guards of `moto-mpmc/tests/fallible.rs` and
  `moto-async/tests/fallible.rs` from host to Motor, preserving the
  allocation-failure, cleanup and queue assertions. Remove the
  `host-construction-test` feature and the host exception in
  `moto-async/src/timeq.rs`. stdio-pipe's unit tests stay with the module;
  moto-ipc also compiles the module for its own unit tests, so a plain
  `lorry test` runs them.
- Remove the host cargo commands for these three crates from `full-test.sh`
  and `full-test-prepare.sh`. Add the native phase to the developer-image
  gate (`test-dev-sources.sh`, run by `full-test-dev.sh --release`), after the
  existing native builds, and check that the expected tests executed.
- The moto-tooling host tests stay: they are portable.

Gate: the core gate plus `full-test-dev.sh --release`. This is the first
native `lorry test` in any gate. The native phase compiles only the staged
crates, their test binaries and crossbeam-utils' build script, in about
seven seconds; the image build's preparation takes about ten more.

## Steps

1. **Baseline:** the interim path dependencies for rmux,
   russhd, rnetbench and the smoke suites are already present. Keep them until
   the registry switch to avoid mixing SDK-facing types from different crate
   sources. Use the target and test split specified above.
2. **Preparatory patches** (a), (b) and (c), in that order, each gated and
   committed on its own.
3. **The merge:** create `moto-sdk`, move the sources and tests, add the
   std-only re-exports, fix paths and feature/target gates, update manifests
   and importing files, and delete the eleven directories. This touches
   consumers outside `src/sys` as well as the libraries. Re-point the native
   test phase at the SDK workspace; retain the portable host tests.
   Production networking semantics stay the same.
   Gate: the configuration matrix above, three debug and three release
   `full-test.sh` runs, `full-test-dev.sh --release`, and `test-wasm.sh` under
   QEMU and Cloud Hypervisor. Keep developer-image testing release-only.
   `test-wasm.sh` checks prebuilt add-on inputs, so it proves the image, not
   the fork builds.
4. **Package gate:** verify the distributable against registry dependencies
   as described above, including std-only exports. Preserve all checks in the
   full-test workflow.
5. **Publish** (owner): publish `moto-sdk` 0.1.0 from `src/sys` after all
   gates pass. moto-rt 0.17.9 and moto-sys 0.3.2 are the existing published
   dependency versions to validate against.
6. **Switch the outside:** consumers adopting the SDK declare
   `moto-sdk = "0.1"` and use `moto_sdk::rt` and `moto_sdk::sys` with `std`.
   Remove their redundant direct dependencies and Motor crate path patches;
   keep direct registry dependencies where needed for feature selection or
   by consumers that do not need the SDK. Do not add SDK dependencies to every
   application or to the toolchain. Re-resolve lockfiles; no Motor crate path
   dependency remains outside `src/sys` except the imager's. Repeat the gates with the
   actual registry consumers. No changes to repositories outside the main
   Motor OS tree are planned; any newly required changes must be discussed.
7. **Docs:** update current crate/module references in `docs/*.md`; document
   the dependency rules, imager exception and versioning policy. The
   dependency rules go into `AGENTS.md` (owner). Previously published crates,
   including moto-ipc 0.2.4, remain published; consumers migrate to the SDK.

## Open questions

None currently. The owner rulings of 2026-10-21 settle the staging path, the
precompiled closure in the Lorry cache, vendoring at image build with the
test step reduced to `lorry test`, their place outside the test timeout, and
Lorry changes if they are needed.
