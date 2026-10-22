# Javy and Wasmtime infrastructure for Motor OS

Promote the prototype into maintained forks in small, tested milestones.
Preserve working engine/platform integrations and regressions; replace
fixture-specific helpers with shared production code. Milestones 0–2 are
delivered: the maintained Motor branches are published, and Javy/Wasmi and the
runtime-only `wasmtime-rt` build through the normal add-on workflow, ship in
the developer and small wasm images, and pass their installed-tool checks on
both images at 256 and 224 MiB. HTTP serving (milestone 3) and the full
compiler with native packaging (milestone 4) are ahead; see
[Status and resume point](#status-and-resume-point-2026-10-19).

This document records the requirements, the design contracts, a short account
of the completed work and the detailed plan for the milestones ahead. The
settled points of the earlier plan reviews are folded in.

## Status and resume point (2026-10-19)

Evidence under `build/` is host-local and not required.

- **Forks:** pushed on 2026-10-20, branches at these heads: mio `motor-1.2.0`
  `87e045c`, tokio `motor-1.51.1` `860f25ca`, wasmi `motor-1.1.0` `18be00bc`,
  javy `motor-9.1.0` `12a6c52` (on the owner's `c496a4f`), wasmtime
  `motor-48.0.1` `08a09edea` (on top of `8804845d7` and `5d9818f3c`, lazy
  guarded fiber stacks). They end every cross-repository path dependency; see
  [the dependency scheme](#fork-dependency-scheme-2026-10-20). Javy and
  Wasmtime take `moto-rt` and `moto-sys` from crates.io, and Wasmtime's WASI
  filesystem adapter is path-based over `moto-rt` (see
  [Native filesystem](#native-filesystem-clocks-and-networking)). The tree pins
  the javy and wasmtime revisions it builds in `src/build-addon-sources.sh`;
  since 2026-10-22 wasmtime is at `633e7de36`: `08a09edea` plus outgoing
  `wasi-http` TLS that trusts the system CA bundle (see
  [Fibers, resource limits and HTTP](#fibers-resource-limits-and-http)).
  With the 2026-10-20 pins, `make BUILD=release`, both add-on builds and
  `full-test.sh --release` pass (2026-10-20, the owner limited the check to
  that); the wasm matrices under QEMU and Cloud Hypervisor passed the same
  morning with wasmtime `08a09edea` and the same Javy content before its
  rebase. Wasmtime `633e7de36` has passed only its add-on build,
  `make images BUILD=release` and a one-off hermetic HTTPS check of its
  source: it accepts a server certified by a local CA in the image's bundle
  and refuses one certified outside it, where `08a09edea` refused the first
  too (2026-10-22, the owner limited testing to small checks). Tree work is on
  the `wasm` branch.
- **Done: Linux-parity memory limits** (owner rulings 2026-10-18, in
  [the memory contract](#javy-pipeline-and-memory-backing)). Those fork heads
  and tree `c4e44de3..c3ecb975` replace 96 MiB per memory, 128 MiB per
  process and four memories with 4 GiB per memory and no total or count, and
  stop Wasmi writing zeros into reservations. The add-ons rebuilt from the
  published heads pass `test-wasm.sh` under QEMU (384 s) and Cloud Hypervisor
  (392 s) and `full-test-dev.sh --release` (3,433 s, ALL PASS), which also
  covers the gate of Wasmtime `75d22026a` that the previous resume point asked
  for. Before publication, with locally built binaries swapped into the assembly
  (evidence in `build/claude-targets/sparse-limits/`), both VMM matrices pass
  (QEMU 387 s, Cloud Hypervisor 390 s; 66 `javy-smoke` commands, 70 on the
  first VM, and 97 `wasmtime-smoke` commands per VM), and `memory-check` and
  the Javy native tests pass at 224 MiB: 64 untouched 4 GiB reservations hold
  132 KiB, and growth to 4 GiB in 1 MiB steps takes 31 ms. Five alternating
  runs of the old and new tools on one 224 MiB VM show no memory or time cost
  (TypeScript compile median 20.99 s against 21.14 s, equal peaks; Wasmi and
  `wasmtime-rt` execution equal). TypeScript compile peaks at 224 MiB are now
  181–189 MiB with either set of tools, down from 201.6–204.2 MiB on
  2026-10-11; the newer kernel and assembly account for that.
- **Now milestone 3, step 3a, waiting on publication.** 3a's measurements
  found two limits at 224 MiB. Closed connections exhausted the VM through
  sys-io's TIME-WAIT memory; that is fixed by the standalone sys-io patch
  `4ee0cf22`. Eager fiber stacks allowed only 8 in-flight p2 requests; the
  owner ruled (2026-10-19) for lazily committed guarded stacks, as on Linux,
  and Wasmtime `5d9818f3c` (pushed 2026-10-20) builds them on the kernel's
  guarded heap maps (`fc48f27d`). Its local build passes `stack-check` and
  serves 64 concurrent p2 requests at 224 MiB. **Resume** with the "Next"
  item of "Lazy guarded fiber stacks" under
  [Milestone 3](#milestone-3-httphttps-and-opt-in-p3): once the owner pushes,
  rebuild the add-on and gate it. The other 3a rulings (2026-10-19):
  deadlines follow Linux, and connection timeouts and accept errors follow
  upstream.
- **Working rules from the owner:** commit messages are one line with no
  trailers, in this tree and in the forks; the owner pushes fork branches; the
  `moturus/javy` fork takes code only; stop for review before any change under
  `src/sys`, to moto-rt or to the toolchain; run `full-test-dev.sh` release-only.

## Deliverables and constraints

Ship all four tools in both the developer image and a new small wasm image:

| Tool | Responsibility |
| --- | --- |
| `javy` with Wasmi | Compile JS with default/custom plugins to core Wasm; write its own output. |
| `wasmi` | Execute raw core Wasm and Javy plugin linkage; support invocation, exits and optional fuel. |
| Wasmtime full | Upstream `run`/`serve`/`compile`, Pulley precompilation, native core/component compilation and a separate Motor ELF packaging subcommand. |
| Wasmtime runtime-only | Precompiled Pulley command/HTTP execution and the installed native core/component ELF template; no Cranelift. |

- Every tool must work as role **None**, at **256 MiB and an actual 224 MiB
  margin VM**, on both images. Hello and the 9,112,951-byte TypeScript workload
  are mandatory. The small image has `data_partition_size_mb: 1024` (1 GiB).
- Build tools externally with the selected Motor Rust/C/C++ toolchain. Run JS
  compilation, Wasm execution, Pulley/native compilation and packaging on Motor;
  the small image needs no Cargo, rustc, Clang or SDK.
- Use standard Rust/native Motor APIs for integration; retain upstream QuickJS,
  Binaryen and CXX. Link unchanged in-tree moto-rt. No rt.vdso, kernel or
  toolchain API change is planned.
- Use existing native networking behavior. No networking API/service changes,
  UDP-close barrier, interface-discovery API or shared Tokio/Mio migration are
  requested or prerequisites for this port. Adapt WASI behavior in the wasm
  dependency graph and document native limitations.
- Native code enters through OS-loaded RX ELF segments. No tool receives
  `CAP_IO_MANAGER`; no JIT, executable heap, RWX or self-mapped executable code.
- Tools write directly to OS-permitted destinations. Rush supplies capability
  masks, sys-init supplies service masks, and compilation/execution are separate
  invocations. No launcher, worker subprocess or output relay.
- WASI p2 is supported; p3 is compiled in and explicitly opt-in. No boot-time
  compilation, downloads or plugin initialization.

Excluded: Javy profiling/Whamm and alternate compiler backends, toolchain
self-hosting, persistent AOT caching, arbitrary cross-CPU native portability,
direct JS-to-p3 compilation and I/O-dependent p2 custom-plugin extensions.
General Wasm GC/threads require separate evidence; QuickJS GC and p3 async do
not establish them.

## High-level design

- Wasmi runs Javy plugins, schema calls and Wizer initialization. Javy emits
  QuickJS bytecode plus the QuickJS Wasm runtime; the Wasmi runner executes it.
- One Wasmtime CLI source provides full and runtime-only builds at distinct
  installed paths. Both share command/HTTP hosts and resource policy.
- Full Wasmtime runs raw Wasm through Pulley and compiles Wasm to Pulley or
  x86-64. Native compilation translates the Wasm runtime, not JavaScript itself.
- The runtime-only executable doubles as a read-only template: an empty
  artifact section selects its CLI; a populated section executes embedded
  native core/component code. Core programs do not require componentization.
- Preserve upstream canonical ABI, resources, rights and protocol state
  machines. Narrow filesystem/socket adapters use native Motor APIs, with
  Tokio -> Mio for asynchronous TCP/UDP and guarded, pooled fiber stacks.
- OS roles/capabilities bound process authority. Engine-enforced WASI grants,
  memory limits and HTTP deadlines/concurrency/buffering restrict guest use.

```text
 External host: maintained forks + Motor toolchain + pinned guest fixtures
                                  |
                         release builds/images
                                  v
                   Developer image AND small wasm image
                                  |
           Rush: MOTOR_OS_CAPS=... / sys-init service masks
                                  v
 +-------------------------- None processes --------------------------+
 |                                                                    |
 | [javy + Wasmi]       [wasmi]           [Wasmtime full + Cranelift] |
 | JS -> core Wasm      raw execution     raw run/serve -> Pulley     |
 | plugin + Wizer                         compile -> Pulley .cwasm    |
 |                                       compile/package -> ELF       |
 |                                                                    |
 | [Wasmtime runtime-only / populated native ELF]                     |
 | precompiled Pulley OR embedded native core module/component        |
 |                            |                                       |
 |           Shared command/HTTP host: p1/p2, opt-in p3               |
 |           WASI grants, resource limits, guarded stacks             |
 |                            |                                       |
 |          Motor FS adapter       Tokio -> Mio -> Motor TCP/UDP      |
 |          moto-rt path calls      native clocks/entropy             |
 +----------------------------+---------------------------------------+
                              | native calls / existing IPC
                              v
             Unchanged moto-rt/rt.vdso; sys-io; kernel/ELF loader

 Compiler -> own scratch output -> separate masked shell invocation
```

## Completed work

### Milestone 0: feasibility and maintained baseline

The Rust/shell prototype established feasibility on both release images at
224/256 MiB: 160 runtime cases, 184 Javy cases and 24 buffered HTTP cases,
plus native stack checks, 17 compiler-policy checks and 11 native-adapter
baseline checks, recorded in `build/wasm-redo/qualification.md`. Those results
belong to the recorded prototype snapshots, not to a reproducible build; the
premature Motor OS test/build/image integration was removed.

| Measured operation | 224 MiB VM peak (MiB) | 256 MiB VM peak (MiB) |
| --- | ---: | ---: |
| Native core / component compilation | 173.69 / 181.26 | 183.64 / 195.77 |
| Pulley core / component compilation | 110.70 / 124.21 | 123.44 / 136.72 |
| Streaming native ELF publication | 43.01 | 53.16 |
| Native core/component execution | 104.96 | 115.12 |
| Precompiled Pulley core/component execution | 103.20 | 113.53 |
| p2/p3 hello and p3 echo, Pulley/native | 84.84 | 94.43 |
| Guarded fibers, teardown/yield/cancellation | 45.70 | 56.02 |
| Javy hello / TypeScript static compile | 181.45 / 219.61 | 192.93 / 229.77 |
| Wasmi hello / TypeScript execution | 56.30 / 83.45 | 66.42 / 93.62 |
| GC/p2 custom plugin initialization/compile | 185.44 | 195.39 |
| Owned-memory backing / TLS cleanup | 66.82 / 50.62 | 76.98 / 60.89 |

Cells are the larger sampled whole-VM peak across images and applicable
hello/TypeScript paths, including services and the harness; they are lower
bounds, not RSS. All rows ran as role None with zero sampling errors. Admission
refusals were zero except for four deliberate Javy fault-exhaustion cases with
one each; containment and cleanup passed. Thirty-two on-VM artifacts matched
Linux bytes. Usable RAM is 222.49/254.49 MiB; the narrowest sampled headroom was
2.883 MiB at 224 MiB. HTTP qualification covered four concurrent complete
requests per case with buffered headers; earlier fragmented/different-header
requests intermittently reset before a status line, which remains unexplained,
and graceful shutdown and Ctrl-C were not qualified.

The owner published the six maintained branches on 2026-10-07. Each is a real
upstream repository with a Motor branch. The tree checks out only `javy` and
`wasmtime`, beside this repository, at the revisions pinned in
`src/build-addon-sources.sh`; the other four, and the Motor OS crates, are git
dependencies that the forks' lockfiles pin (since 2026-10-20; the heads below
are the 2026-10-07 publication).

| GitHub repository | Branch | Head |
| --- | --- | --- |
| `moturus/javy` | `motor-9.1.0` | `51a5c4553a64e833dd72addcfd1e734894897c52` |
| `moturus/wasmi` | `motor-1.1.0` | `f230d9203a1a390fff178ae93413442d9bcbe8cf` |
| `moturus/wasmtime` | `motor-48.0.1` | `ff4e0e55f670ed96777cf49cf0ab81c0f6b7fb9b` |
| `moturus/target-lexicon` | `motor-0.13.5` | `4b61b4eae17fd05d9553733c70972571c2df49a6` |
| `moturus/tokio` | `motor-1.51.1` | `62d8324a0594408af99376a90cec00d9e5604243` |
| `moturus/mio` | `motor-1.2.0` | `e4884150d93331f7a48560ad8be640bab28d47b1` |

What the branches carry:

- `moturus/wasmi`: the IR signed-branch-offset correction and owned nonmoving
  linear-memory allocations; static-buffer growth returns an error instead of
  panicking.
- `moturus/javy`: Wasmi as the only engine for compilation and Wizer snapshots,
  compiler/module state released between build phases, the Javy-local C++ TLS
  shim with its ownership/TLS checks, the build and test scripts,
  and the runner fixes (stdin read lazily inside `fd_read`; mistyped
  `wasi_snapshot_preview1` imports rejected at instantiation).
- `moturus/wasmtime`: Wizer instrumentation decoupled from the runtime,
  allocator-backed compilation and loading, Motor filesystem/socket/clock/entropy
  adapters (path-based directory capabilities over `moto-rt`),
  target-resolved native defaults and `Config::motor_runtime()` for
  Pulley, immutable native ELF templates with a publisher, bounded guarded
  stacks, shared command/HTTP hosts, Motor's `P3_DEFAULT=false`, the runtime-only
  CLI with an explicit ELF layout, and build/check scripts. The role/mask guard
  runs only in the runtime-only (`motor-template`) build; the full CLI has none
  yet. These implementations still need the qualification and image delivery
  specified in milestones 2–4.
  `moturus/target-lexicon`, `moturus/tokio` and `moturus/mio` carry the target
  and asynchronous networking ports.

Focused validation of fresh builds from these branches on a 256 MiB VM is
recorded in `build/wasm-ports/validation.md`: raw core/component execution,
on-VM native and Pulley compilation, runtime-only precompiled Pulley execution,
native ELF publication and execution, p2/p3 HTTP responses and native
filesystem confinement checks. It did not remeasure the 224 MiB margin.

### Milestone 1: maintained Javy/Wasmi delivered

Build and images:

- `src/build-javy.sh`, called from `src/build-motor-os.sh` (the normal
  `build_addons` stage or `--javy-only`), follows the published `javy`, `wasmi`
  and `wasmtime` branches with the add-on checkout helper, fetches under the
  Motor toolchain named by `rust-toolchain.toml`, sizes `JOBS` by available
  memory, downloads the plugin and TypeScript inputs by digest, and records the
  resolved source graph in `/devtools/javy/sources.txt`. Reuse is keyed on
  that manifest, so a new fork head rebuilds the add-on.
- Binaries install at `/devtools/bin/javy` and `/devtools/bin/wasmi`, the
  default plugin at `/devtools/javy/plugins/default.wasm` and provenance under
  `/devtools/javy`. Test inputs (the TypeScript workload and the Linux identity
  digests) are staged in the assembly's `tests/javy`, outside the images, and
  `test-wasm.sh` uploads them to `/none/tmp`; the developer image adds the
  `/devtools/src/wasm` example and `/devtools/www/wasm.html`. The 1 GiB wasm
  image (`src/imager/motor-os-wasm.yaml`) installs the same overlay. The
  user-facing guide is `docs/wasm.md`; the build steps are in `docs/build.md`
  and `docs/build-motor-os.md`.
- Both a complete managed `src/build-motor-os.sh` run and the javy-only path
  reproduce the add-on from fresh published checkouts and an empty Cargo cache.
  R1 below is fixed by 1j: the orchestrator's selection reaches the fetch and
  the fork build, and the manifest records it.

Tests:

- `src/tests/javy-smoke` is a Rust crate that runs only the installed tools:
  57 commands covering static/dynamic linkage, default/explicit/initialized
  plugins, malformed plugins, schema/configuration, WIT exports, promises,
  modern JS, source modes, deterministic repeatability, errors, guest
  exits/traps/fuel, runner WASI behavior from hand-written modules and
  role/capability/output denial. It samples whole-VM memory and reports the
  admission-refusal delta.
- `src/tests/test-javy.sh` (`--prepare`, `--image`, `--memory`,
  `--vmm qemu|chv`) builds both images and the crate, boots each image at 256
  and 224 MiB from a QEMU snapshot or a disposable Cloud Hypervisor copy,
  checks that the installed binaries equal the staged add-on bytes, and runs
  the crate over SSH. Evidence is written to `build/javy-images`, replaced on
  each run. It is registered in `full-test-dev.sh --release`; debug suites do
  not run this matrix. Host contract tests in `full-test.sh` cover the
  developer-suite wiring and generic add-on helpers; Javy-specific toolchain
  selection needs the contract test planned in 1j.

| TypeScript compilation | VM RAM (MiB) | Sampled whole-VM peak (MiB) | Sampled headroom (MiB) | Time (s) |
| --- | ---: | ---: | ---: | ---: |
| Small wasm image | 256 | 216.97 | 37.52 | 20.970 |
| Small wasm image | 224 | 205.66 | 16.83 | 20.940 |
| Developer image | 256 | 226.92 | 27.57 | 20.944 |
| Developer image | 224 | 214.06 | 8.43 | 21.132 |

These are sampled lower bounds including the test driver and services, with
maximum sampling gaps of about 30 ms. Javy/Wasmi occupy 21,668,528 bytes
together. The 2026-10-08 rerun after the runner fix passed eight boots (both
images at 256/224 MiB under QEMU and Cloud Hypervisor), 41 commands each, with
zero admission refusals; four boots take about 4.5 minutes per VMM.

Still open from this milestone and planned below as its close-out: R1–R6,
the retained custom GC/p2 plugin and forced-exhaustion matrix, compressed
Linux/Motor byte identity, streaming plugin validation and lazy-backing timing.

### Review findings: 2026-10-08

Review covered the 12 Motor integration commits `582ce13c` through `02893284`
and relevant code at the maintained fork heads above. Both release VMM matrices
passed again: eight boots, 328 smoke commands and zero admission refusals.
Thirty-five imager tests passed (three existing tests remained ignored), as did
`test-build-addons.sh`, `test-dev-memory-contract.sh` and `test-full-test-size.sh`.
The review used the installed binaries and did not rebuild an authoring toolchain.

The following findings remain open. R1 was confirmed with a hermetic
build-script probe; R2–R5 were reproduced against the installed runner as None
with mask `0` in a disposable 224 MiB VM; R6 was found by code inspection.
The passing smoke matrix does not exercise these failures. A second review of
the same code confirmed all six; severities below are from that review.

| ID | Severity | Location | Finding and evidence | Follow-up |
| --- | --- | --- | --- | --- |
| R1 | Medium | Motor `src/build-javy.sh`; Javy `motor-build.sh` | Both overwrite the selected `RUSTUP_TOOLCHAIN` with the checked-in managed selector, and the fork script resolves the managed assembly. An authoring assembly can receive managed-toolchain binaries while its manifest records authoring provenance. Only full builds in authoring mode are affected. Wasmtime's `motor-build.sh` has the same override. | 1j, 2a |
| R2 | Low | Javy `crates/motor-engine/src/wasmi_backend.rs`, `define_host_imports` | A valid module importing `wasi_snapshot_preview1::proc_exit` twice fails with a duplicate-definition error; the runner exits 1 instead of 0. Toolchains merge duplicate imports and Javy never emits them. | 1k |
| R3 | Low–medium | Same file, `Vm::call`; runner invocation loop | `proc_exit(0)` becomes ordinary success. `--invoke exit-zero --invoke trap` executes the later trap and exits 1 instead of terminating successfully. | 1k |
| R4 | Low | Same file, `wasi` descriptor handling | `fd_close` reports success without changing guest descriptor state. Closing stdin twice returned 0 twice; the second close should return `BADF` (8). Reads, writes and descriptor queries also lack closure checks. Only descriptors 0–2 exist. | 1k |
| R5 | Medium–low | Same file, `wasi` clock handling | `clock_time_get` ignores the clock ID and always supplies wall-clock time, so the monotonic clock is not monotonic. ID 999 returned success instead of `INVAL` (28). | 1k |
| R6 | Low | Motor `src/tests/test-javy.sh` | The shared evidence directory is cleared before the launcher acquires its VM lock, and that lock is taken per boot. An overlapping invocation can erase an active run's evidence, including its Cloud Hypervisor runtime directory, even when its boot is refused. | 1l |

Review evidence is retained under `build/javy-review.Sa2dn9/`: the
[QEMU](../../build/javy-review.Sa2dn9/qemu.log) and
[Cloud Hypervisor](../../build/javy-review.Sa2dn9/chv.log) matrices,
[toolchain probe](../../build/javy-review.Sa2dn9/toolchain-probe.log), and
[runner probe results](../../build/javy-review.Sa2dn9/runner-probes.log).
The directory also holds the diagnostic scripts and WAT fixtures. Promote
regressions into maintained tests; these generated artifacts are evidence only.

## Implementation contracts

### Javy pipeline and memory backing

Use one owned, nonmoving reservation per guest memory through existing
`moto-sys::SysMem::map(SELF, F_READABLE | F_WRITABLE | F_LAZY, ...)`, with
automatic addresses and small pages. The Wasmi hook is delivered; the following
contract governs it and the later Wasmtime integration:

- Linux parity (owner ruling 2026-10-18): reserve each memory's declared
  maximum, or 4 GiB without one, the whole 32-bit range and what upstream
  Wasmtime reserves on 64-bit Linux. There is no process-wide total and no
  memory count. A 64-bit memory cannot grow past 4 GiB: `memory.grow` returns
  -1 instead of moving it, as upstream does with `-O memory-may-move=n`, and a
  larger initial size fails instantiation. Upstream's `-W max-memory-size` and
  `-W max-memories` keep their meaning. This replaces the earlier 96 MiB per
  memory, 128 MiB total and four memories, which existed only because
  reservations were costly; preserve guest-visible types/lengths.
- Never write zeros into a reservation: untouched lazy pages already read as
  zero, and a memory never shrinks or reuses its mapping, so growth touches no
  page. Wasmi's owned-buffer contract requires zeroed buffers for this. Keep the
  mapping alive through all engine references and release it on drop, failed
  instantiation and cancellation. Cover defined/imported memories, multiple
  memories, snapshots and growth zeros.
- Use the owned-buffer/allocator hook in Wasmi/wasmi_core for `Memory::new`,
  shared by Javy and the runner. Keep `Memory::new_static`'s explicit
  caller-owned buffer semantics; it bypasses the allocator. Do not leak
  mappings or invent unconstrained static lifetimes; preserve non-Motor/no-std
  behavior. Wasmtime's `Config::with_host_memory` integration must satisfy its
  reservation/guard contract and retain explicit bounds checks.
- `F_LAZY` is a hint, and lazy mappings are already in production use:
  `moto_rt_vm_map` in `moto-rt-cabi` maps with `F_LAZY` for the C runtime, so
  Binaryen depends on it and systest covers lazy admission. Lazy segments are
  sparse ([kernel memory](../kernel-mm.md), [OOM handling](../oom-handling.md)):
  an untouched reservation holds one segment node, mapping is admitted
  at a flat 256 KiB held only during the call, and map time does not depend on
  size. A touched page adds its 72-byte descriptor, which the process's pool
  keeps for reuse until exit, so a long-running server retains descriptors for
  its busiest moment's touched pages only. One map is limited to 1 TiB and the
  user region to 32 TiB, room for about 8,000 live 4 GiB memories. The full
  reservation counts against the process's accounted cap
  (`DEFAULT_MAX_USER_MEMORY` in `src/sys/kernel/src/config.rs`), which is
  `u64::MAX` and so not an effective quota; `ps` reports reservations and
  resident memory separately. Fault-time physical admission is the binding
  native limit.
- Fault-time physical exhaustion terminates the faulting thread and therefore
  its process (`src/sys/kernel/src/uspace/process.rs`); it cannot return a
  growth error. Test bounded-growth failure separately from fault
  containment/cleanup. Report an unmet backing contract before selecting
  another design or introducing OS changes.
- Ordinary heap allocations of 2 MiB and more are backed by huge pages
  (`HeapSizing` in `src/sys/kernel/src/mm/user.rs`); the lazy path maps small
  pages only. Record execution time as well as memory whenever a backing change
  is measured.

The static pipeline is unconditional: compile JS bytecode; drop the compiler
VM; compress source with existing settings; initialize/snapshot the plugin and
construct output; emit Wasm; drop Walrus IR; run Binaryen. Preserve static
linkage, deterministic initialization, source embedding and optimization.
Streaming plugin validation is a separate measured optimization that must
preserve complete Wasm validation and malformed-input checks. The traced
256 MiB run gives the phase budget it would change:

| Phase boundary | Whole-VM use (MiB) |
| --- | ---: |
| Start | 73.2 |
| Plugin validated | 137.0 |
| Compiler VM instantiated | 233.8 (eager 96 MiB buffer) |
| Output module constructed | 191.0 |
| Output module dropped, before Binaryen | 139.2 |

Plugin validation leaves about 54 MiB resident through the compiler phase.
Streaming validation would move the binding peak to the output-module phase,
predicting roughly 152 MiB there instead of the current compiler-phase peak.

### Cranelift and static initialization

Retain serial compilation, normal optimization and backtracking register
allocation. The diagnosed native-compilation OOM comes from thousands of
active segments expanding the generated initializer; coalescing fixes it.
Single-pass allocation fails the margin and runtime stack requirements; no
compiler rewrite, larger stack default or Winch substitution is needed.

Retain the explicit coalescing policy already passed from resolved target
configuration into module translation. The maintained fork selects native
defaults in `Tunables::default_for_target` and exposes `Config::motor_runtime()`
for the explicit Pulley profile. Qualify the policy for
`x86_64-unknown-motor` and the **Motor Pulley runtime profile**, on Linux or Motor
compiler hosts. A Pulley architecture alone does not identify its destination
OS. Apply the same policy to raw run, precompilation and core modules inside
components; preserve other targets' defaults and keep `memory_init_cow(false)`.

Set **`Config::memory_guaranteed_dense_image_size(0)`** explicitly. This removes
the unconditional sparse-image allowance: without CoW, gaps occupy artifact
bytes and are copied at instantiation. Coalescing still applies when the extent
is less than twice the sum of active-segment bytes. Both measured Javy inputs
span 396,021 bytes with 285,851/285,873 active bytes, satisfying that heuristic
without the allowance. Compiler-policy checks and both mandatory execution paths
are qualified with this setting.

Retain checks for defined memories and constant in-bounds offsets, plus segment
ordering, passive data, empty/out-of-bounds behavior, start ordering and fallback.
The heuristic counts overlapping bytes, permits large dense images and adds
page padding; it is not a resource limit. Sparse/dynamic fallback can still
produce large initializers. Bound compilation and image/instance resources.
Test Linux/Motor compiler hosts, Motor Pulley, sparse extents below/at/above the
old 16 MiB threshold, dense images and multiple memories. Record initializer
choice, artifact size, copy cost and resolved policy with artifact identity.

### Authority and direct outputs

Use existing [roles](../process-roles.md), [caps](../caps.md) and
[filesystem permissions](../fs-permissions.md). Rush passes a
`MOTOR_OS_CAPS=...` prefix to the child (`src/tests/test-rush-script-caps.sh`):

| Mask | Authority |
| --- | --- |
| `0` | Neither network nor filesystem writes. |
| `0x100` | `CAP_NET`. |
| `0x200` | `CAP_FS_WRITE`; compilation/packaging outputs. |
| `0x300` | Both. |

Before reading/parsing/deserializing input, plugins or embedded artifacts, check
`ProcessStaticPage::get().capabilities`: require None and no bits outside
`CAP_NET | CAP_FS_WRITE`; show appropriate masks on refusal. `--help`/`--version`
are exempt. Check populated ELFs even when invoked from an Interactive shell.
Caps are immutable; tools do not demote/relaunch themselves.

Services are the exception to settle in milestone 3: sys-init's default None
child receives `CAP_LOG`, and dns-resolver runs with `0x108`. A wasm service
started by sys-init therefore carries a bit the check rejects. Decide whether
`CAP_LOG` is an accepted bit before the first service-mask test.

Writes fail through ordinary sys-io permission errors. Do not pre-validate WASI
writable preopens against OS path policy. None with `CAP_FS_WRITE` can write
only `/none/tmp` ([filesystem permissions](../fs-permissions.md)); users move
outputs with their own authority. Verify scratch ELF creation, executable
permission finalization and separate masked execution, plus stdio, exits/traps
and parent-exit behavior.

None is neither tenant isolation nor a RAM quota. Scratch is shared, public
`/user` data remains readable, and [process-control limitations](future-work.md#any-process-can-kill-most-other-processes-2026-09-26)
remain. WASI grants depend on engine integrity and do not survive native-code
compromise. Serialized/native artifacts may contain arbitrary native code;
compatibility checks are not authentication, and arbitrary ELFs can omit role
checks. No artifact-authentication subsystem is required.

### Native filesystem, clocks and networking

Prefer existing `moto-rt::fs` APIs for ordinary tool inputs/outputs and metadata.
`stat(path)` returns `FileAttr` v2, including `entry_id`, type, size, permissions
and timestamps. Open files and directory streams already retain entry IDs;
`get_file_attr(fd)` queries their identity without resolving their old pathname.
Use these existing facilities before adding a native API.

For WASI directory-relative operations, qualify pathname-based access against
the required directory-handle semantics. `stat(path)` has no parent-ID/dirfd
argument: rt.vdso normalizes the path, resolves it from the filesystem root and
fetches metadata in a second request. Returning an ID does not make a later
path lookup relative to that ID. A saved path can disappear after rename or
select a replacement object. Checking its ID before a child operation leaves
a check/use race; checking again afterwards still permits replace/use/restore
interleavings and cannot undo a write or truncate. `chdir` stores a process-wide
pathname, not a directory identity; process-local locks cannot prevent another
process's rename.

| Existing API use | Applicability and limitation |
| --- | --- |
| `stat(path)`, `open(path)` and ordinary output creation | Sufficient for ambient tool I/O under OS permissions. |
| `get_file_attr(fd)`, file reads/writes and `readdir(dirfd)` | Retain the opened object's identity across rename; no descriptor-relative child lookup/create API follows from this. |
| Saved-directory-path plus guest-relative path | Works with a stable namespace; cannot implement unrestricted renamed-directory handles or concurrent replacement confinement. |
| Parent/child ID checks before or after pathname operations | Detect some replacements; cannot make lookup/create/truncate/unlink atomic with the identity check. |

An unchanged-native 224 MiB VM probe as None (`0x200`) confirmed metadata/IDs,
descriptor reads and directory enumeration after rename, pathname replacement,
CWD behavior, check/use/restore and stat/open mismatches. Existing `CMD_STAT`
lookup by the original parent ID still found the original child after rename
and replacement. The [probe source](../../build/wasm-slice0/fs-stat/source/probe.rs)
and [results](../../build/wasm-slice0/fs-stat/small-224-probe.log) retain the
deterministic interleavings; these test adapter design limitations, not native
API defects or production client cancellation.

Keep production WASI rights and directory confinement as requirements. A
stable-namespace fixture can establish prototype feasibility, but must state
that assumption and cannot qualify unrestricted filesystem acceptance. Reject
absolute guest paths, NULs and traversal above a preopen before I/O; lexical
path validation alone does not address directory replacement. Test renamed
preopens/subdirectories, replacement between check and use, stat/open mismatch,
stale generations, permissions and descriptor lifetime.

Until 2026-10-20 the `motor_fs` adapter used `moto_io::fs::FsClient` operations
on entry IDs and `motor_lookup::lookup` for parent-relative `CMD_STAT` walks.
Milestone 2 qualified that implementation beyond its existing rename/replacement
and client-reuse tests, including ownership, cancellation/reentrancy, stale
connections and IPC cost. `stat(path)` reuses the VDSO I/O runtime but is
synchronous and performs path lookup plus metadata RPCs; identity-only walks
can avoid metadata fetches. ID-based enumeration is another existing option,
with extra per-entry RPCs and mutation/cursor concerns. Do not duplicate the
full filesystem client merely to avoid a small wrapper. A `moto-io` `stat_at`
does not exist in the tree; proposing one remains optional and unapproved, and
no new filesystem protocol is required. Generation IDs do not imply POSIX
open-after-unlink. Hardlink, symlink and set-times return explicit unsupported
errors.

**Decision 2026-10-20 (owner):** the adapter is path-based over `moto-rt`,
so that Wasmtime depends on no unpublished Motor OS crate. A directory
descriptor is the absolute path below its preopen; every operation composes
the guest's relative path with it and calls the native path API (`stat`,
`open`, `mkdir`, `unlink`, `rmdir`, `rename`, `opendir`/`readdir`). A handle
names a place, not an object: a renamed directory is not followed, a
replacement under the same name is reached, and a `..` that leaves a file
fails with `NotADirectory` as the old walk did. Open files are native
descriptors (positioned I/O is `seek` plus `read`/`write` under a per-file
lock, since the native calls use the descriptor's position) and keep the
object they were opened on; identity for `metadata-hash`, `is-same-file` and
p1 inodes is `FileAttr::entry_id`. Confinement is unchanged: absolute paths,
NULs, overlong names and `..` above the preopen are refused before I/O, and
Motor has no symlinks. What is given up is handle-follows-rename and
replacement confinement, which no upstream fixture in the smoke suite needs;
the fork's `motor-host-tests` now pin the path semantics instead. `moto-io`,
`moto-async`, `moto-ipc` and `moto-sys-io` left the fork with the rewrite.

There is no public clock-resolution API. Derive the adapter's nanosecond
resolution from the existing VDSO tick-rate value with ceiling division; do not
assume a 1 GHz minimum. Clocks, timers and entropy remain native.

Reuse Tokio -> Mio -> native TCP. `httpd-axum` binds a std listener that
axum-server converts to Tokio; its asynchronous traffic follows this path.
No reservation/activation/bound-connect APIs, vtable/IPC additions or sys-io
states are added; do not tunnel them through existing entries. Native bind
already starts listening (`src/sys/sys-io/src/runtime/net/tcp_listener.rs`),
and `moto-io` rejects a wildcard address with port zero
(`src/sys/lib/moto-io/src/net/tcp.rs`).

| Accepted TCP behavior | Required coverage |
| --- | --- |
| Bound-connect returns `not-supported`; ordinary unbound connect works. | Motor variants of `test_tcp_connect_explicit_bind` in `p2_tcp_connect.rs` and `p3_sockets_tcp_connect.rs`. |
| Native bind starts listening; peers may queue before WASI listen, but no guest data is exposed. | Focused bind/listen ordering regression. |
| `0.0.0.0:0`, `[::]:0` and p3 implicit listen-bind return `not-supported`; `127.0.0.1:0` works. | Motor variants of unspecified-address ephemeral cases in `p2_tcp_bind.rs` and `p3_sockets_tcp_bind.rs`. |

Modify assertions in these monolithic fixtures; do not skip entire binaries.
Use existing no-delay, TTL, linger and TCP buffer support. Report actual
grow-only ring capacities and size the p2 host write queue accordingly.

| WASI keepalive operation | Native mapping |
| --- | --- |
| Get enabled / set true / set false | `true` / success / `not-supported`. |
| Get idle time / interval / count | 20 s / 20 s / 15. |
| Set positive duration/count / set zero | Success clamped to native value / `invalid-argument`. |

These values reflect native 20 s probes and 300 s timeout on established
connections, set in `src/sys/sys-io/src/runtime/net/socket/tcp.rs`; listening
sockets use 5 s and 15 s until established. Reference that file beside copied
constants, keep them synchronized and carry Motor variants of
`p2_tcp_sockopts.rs` and its p3 twin. No new native keepalive option is needed.

Reuse the Motor Tokio/Mio ports in the wasm dependency closure without
upgrading the Motor workspace or existing users/forks; Helix pins its own
Tokio/Mio revisions and does not move. Keep version/API adaptation in owned
wasm dependency copies. Preserve native readiness/lifecycle and nonconsuming
UDP peek; qualify the versions actually linked.

Delegate UDP binding, route selection and close to existing native APIs. Native
unspecified-address bind selects one local address; report that behavior in the
Motor fixture variants. The prototype's all-interface endpoint fan-out,
discovery query and route cache are removed; no local-address query API is
added. Explicit loopback/external-address binding remains available. UDP
send/drop retains native semantics: accepted traffic may be discarded on close,
and neither send success nor close promises delivery. Use an acknowledged local
receiver before closing when a fixture needs to assert receipt, and test
immediate-close behavior separately without a delivery assertion. No barrier,
retries or timeout changes make that case appear reliable. Retain capability
denial, cancellation, teardown and finite resource tests.

### Fibers, resource limits and HTTP

Guard host fiber stacks using `Config::with_host_stack`, `StackCreator` and
`StackMemory::guard_range`, with Motor-specific code calling moto-sys's
guarded heap maps:

```text
SysMem::map2(SELF, F_READABLE | F_WRITABLE | F_LAZY | F_GUARDED,
             u64::MAX, u64::MAX, PAGE_SIZE_SMALL, num_pages)
```

The map is `num_pages + 2` pages at an automatic address, with a page that is
never mapped at each end; a touch on either kills the thread. It needs no
capability, and only touched pages are committed, so stacks are limited as on
Linux, by the request bound. A pool caches two stacks per engine; a zeroed
request takes a fresh map. Until 2026-10-19 the stacks were eager
`F_SHARE_SELF` maps at fixed addresses in the custom userspace region, eight
per process; "Lazy guarded fiber stacks" under milestone 3 records the change.

Require a deliberate overrun as None/mask 0 to kill only that process, thousands
of teardown cycles to return memory, and acceptable per-stack cost. If this
probe fails, the approved fallback is unguarded stacks with suspend/finish
canaries, deep-call tests in debug/release and the documented None containment
boundary. A guest stack limit alone does not protect host fibers.

Set finite defaults for StoreLimits, tables/resources, compiler inputs/
outputs, instances, requests, bodies/buffers and stack pools; linear memories
follow Linux, as the memory contract above describes. Include image
copies and temporary growth buffers. Store limits do not cover every host/
Cranelift allocation; global admission and sampled watchdogs are not worker
quotas. `run` may remain indefinite but interruptible, with optional fuel/time
controls. `serve` requires per-request deadlines and bounded concurrency/buffering.
Command-runtime defaults are a milestone 2 exit requirement (2g); milestone 3
adds HTTP-specific limits and concurrency sizing, and milestone 4 adds compiler
input/output limits. Later measurements may refine the defaults.

Use upstream command/HTTP bindings and lifecycle in both CLIs and native ELFs.
Keep p3 stores through post-return body completion/drop and join connection/
handler tasks. Cover slow readers, concurrent streams, disconnects, cancellation,
foreground None Ctrl-C and active-request/background shutdown. Background
Ctrl-C registration `NotFound` means unavailable. A native zero-transmit TCP
close deliberately sends reset; shutdown checks accept that native close result.
Audit outbound HTTP grants independently of socket grants.

Compile p3 through `component-model-async`; `P3_DEFAULT` in `src/common.rs`
follows that feature upstream, and Motor sets it to `false` and requires
`-S p3`. Label it experimental and test default rejection. Retain selected p3
regressions, updating/dropping fixtures on rebase only with a recorded upstream
reason. Do not freeze p3 behavior or promise broader conformance/patch support.

Keep Rustls/Ring validation and native clocks/entropy. Outgoing TLS trusts the
system bundle `/system/cfg/ssl/ca-certificates.crt`, as curl, gix and Lorry do,
instead of the WebPKI roots once compiled into `wasmtime-rt` (wasmtime
`633e7de36`, 2026-10-22; `crates/wasi-tls`, which `wasmtime-rt` does not build,
still uses them). Images take the bundle from the build host (`ca_bundle` in
[docs/imager.md](../imager.md)), so a rebuild on an updated host updates the
roots, and a test image can name a bundle that adds a local CA. Test hermetic
local-CA success, wrong-name/IP, expired/not-yet-valid and invalid-chain failures,
plus streaming failure/cancellation; no Internet in regular
tests. Add a representative TypeScript HTTP fixture; the command workload and
small hello/echo servers do not cover it.

### Native artifact packaging

Stream a new core/component ELF from the installed read-only runtime template,
using exclusive creation, atomic publication, permission finalization and
failure/cancellation cleanup. Validate ELF arithmetic, ranges, alignment,
overlap, lengths and code lifetime; review fixed addresses/envelopes as internal
implementation. Match packager/template with an exact custom Wasmtime version
string and retain upstream configuration/CPU checks. That string is the fixed
`48.0.1-motor.1` today, so it does not change when fork commits change compiled
code or engine internals: bump it with every such change, or derive it from the
fork revision at build time, before any precompiled artifact outlives the
build that produced it. Producers must use the
consumer feature graph and compile epoch instrumentation for HTTP deadlines;
precompiled artifacts cannot acquire missing instrumentation at execution.
Regenerate artifacts for image/runtime upgrades; an old ELF cannot identify or
reject a different running image. Deploy the native graph as a matched whole.

## Build, ownership and maintenance

| Owner | Maintained work |
| --- | --- |
| `moturus/javy` | Wasmi integration, phase lifetimes, local C++ TLS shim, plugins/direct outputs, the `wasmi` runner. |
| `moturus/wasmtime` | Motor adapters, target policy, shared host/CLI, full/runtime-only builds, packager, p2/p3. |
| `moturus/target-lexicon` | Motor target/System V ABI recognition. |
| `moturus/wasmi` | IR backward-branch correction and Linux reproducer/upstream report, owned backing. |
| `moturus/tokio`, `moturus/mio` | The versions Wasmtime requires; existing Motor users keep their pinned versions. |
| Brotli | Use upstream. The prototype's compression-determinism workaround is not an approved production fork. |
| Ring/getrandom | Reuse the published Motor Ring port and upstream getrandom's custom entropy hook. |
| Motor tree | Build/image wiring and integration tests of delivered tools; any filesystem API proposal requires separate review. |

Dependency work is **outside the Motor repository** in maintained forks;
`/tmp` experiments are migration inputs, not production dependencies. Do not
commit Motor build/image/test wiring that depends on a manually prepared source
directory, unpublished commits or private fixture/cache contents. There is no
`src/wasm` source/patch/bootstrap subtree and no Python test or preparation
driver. Engine unit/regression tests belong in the owning dependency
repositories, with one exception: the `moturus/javy` fork stays minimal, so
new Javy and `wasmi` runner regressions go into `src/tests/javy-smoke` and
exercise the installed tools. Its existing native test crate and host tests are
kept but not extended. Motor integration tests must be Rust crates called by shell
scripts and exercise tools produced by the normal reproducible build and
installed in the image. Keep generated evidence under `build/` and distinguish
prototype results from delivered implementation. Keep Wasmi's core/IR crates in
its workspace and Wizer in Wasmtime's `crates/wizer`. Native libraries are git
dependencies on `moturus/motor-os` pinned by the forks' lockfiles; no fork
refers to a sibling checkout by path, and the tree's own `src/sys/lib` is not
an input of the add-ons (owner rule 2026-10-19, scheme below).

After correction 1j, repeat the integration pattern for Wasmtime: one assembly
add-on per tool family built by a script under `src/`, at the fork revision
pinned in `src/build-addon-sources.sh` by the add-on checkout helper, recording
the resolved source graph (with the git dependencies the lockfiles pin) with
the installed files, and invalidating reuse on changes to the pinned revision,
build settings or pinned inputs. Binaries go
to `/devtools/bin`, tool data and provenance to `/devtools/<tool>` (never
`/devtools/cfg`), and test inputs stay outside the images in the assembly's
`tests/<tool>`; both images consume the same release overlay. Integration tests
live in a Rust crate under `src/tests`, run only the installed tools, and are
called by a focused shell entry point that boots both images at 256 and
224 MiB under either VMM. Owner ruling 2026-10-10: `full-test-dev.sh
--release` runs every wasm test on the wasm image at 224 MiB and the developer
image at 256 MiB, and checks independent of the VM (determinism repeats, Linux
identity) once, on the first. No full
OS gate is needed for wasm-only validation. Retain `motor_fs as cap_primitives`
and `motor_sockets as rustix`; wholesale
cap-std/io-lifetimes/io-extras/system-interface/socket2/rustix ports are
unnecessary.

Build release add-ons with `panic="abort"`, `lto="fat"`, `codegen-units=1` and
`strip=true` at each owning workspace root; record C/C++ settings and verify
stripped/populated templates on Motor. The full and runtime-only Wasmtime graphs
use separate output directories so compiler features do not leak into the
runtime template. Avoid recompiling Binaryen or both Wasmtime variants during
every debug gate. Install digest-verified plugins/adapters and a selected
prebuilt guest fixture set with sources and external-host recipes; no new Motor
wasm32 targets, `--ignore-rust-version` or test-time downloads. Budget all four
tools/templates, populated ELFs, fixtures and simultaneous scratch/output files
within 1 GiB. Track file/loadable bytes and spawn/compiler peaks separately;
acceptance does not depend on the separate
[spawn optimization](spawn-optimization.md).

Keep future delivery reproducible: source refs, Cargo lockfiles, adapters and
guest fixtures must remain obtainable from declared repositories or
digest-pinned release inputs. Prototype source snapshots and old harnesses
under `build/` are historical evidence, never dependencies of the maintained
integration. The retired prototype pieces (`javy-wasmtime`, `JAVY_MOTOR_ENGINE`,
`JAVY_MOTOR_AOT_TEMPLATE`, Wasmtime-based Wizer execution, `motor-aot-build`,
`motor-component-build`, separate core/component templates, the duplicate
Wasmtime tree, `PROTO_*` and fixed-connection servers) must not return; keep
the p1-to-p2 adapter as a component-I/O fixture, not a native-core prerequisite.

Retain/review the Javy-local C++ TLS shim (ABI/alignment, destructor order,
reentrancy, allocation/unwind failure and Binaryen/CXX coverage), its
128-destructor regression, allocator-backed loading and Wasmtime Rust TLS hooks.
Preserve non-Motor/no-std behavior and broaden determinism fixtures. The
recorded `f32::log2` differences came from Rust's bundled libm (FreeBSD msun's
`log2f`) versus glibc's (Arm optimized-routines, also in musl), which differ on
11,575,817 of the 2^32 inputs; upstream Brotli's compressed source bytes
followed them. Since toolchain `dev.2-abb676f7` (motor-os `3d98cd10`) both
Motor's Rust libm and mlibc use glibc's algorithm, bit-identical to glibc 2.43
on all inputs, and `javy-smoke` checks Motor Javy's output against Linux
Javy's. The prototype's f64-then-round workaround stays retired. Preserve C++ TLS teardown and QuickJS/WIT diagnostics. The
unresolved Pulley invalid-opcode event requires an explicit disposition in 2f;
later passing matrices alone do not explain the original failure.

Triage security advisories promptly, expedite applicable fixes and review/rebase
at least monthly. Verify upstream support/LTS status before selecting the
maintained baseline. Upstream bases are Javy 9.1.0
`04a467bc776b72450e660274929e0eafc8558c19`, Wasmtime 48.0.1
`7bac2c2775808aaec5d4aa5627a5e447b51102cf`, Wasmi/IR 1.1.0
`8273dfb09d493971b7bb12fe614d740cdc857175`, p2 0.2.12, p3 0.3.0, Tokio 1.51.1,
Mio 1.2.0, Ring 0.17.14, getrandom 0.2.15 and Brotli 8.0.4.

### Fork dependency scheme, 2026-10-20

Owner rules (2026-10-19): no cross-repository path dependencies anywhere;
only `build-motor-os.sh` clones other repositories into `../` and works with
them; any branch of this tree must build with any version of the forks and of
the toolchain; upgrading or switching must be easy for a human. Until
2026-10-19 the wasm forks patched Tokio, Mio, target-lexicon, Wasmi, Wizer and
the Motor OS crates in by sibling path (`../tokio`, `../motor-os/src/sys/lib`),
unlike the older Motor branches of Mio and Tokio, which took `moto-rt` from
crates.io. A path dependency pins the sibling's version in the fork's
lockfile, so one tree branch's moto-rt bump broke `cargo build --locked` of
the fork for every other branch.

The scheme now:

| Dependency | Declared as | Pinned by |
| --- | --- | --- |
| Motor OS crates | Javy: `moto-rt` and `moto-sys` by `git = "https://github.com/moturus/motor-os", branch = "main"`, one revision for both; Wasmtime (since the update below): `moto-rt = "0.17"` and `moto-sys = "0.3.2"` from crates.io, which Tokio's and Mio's `moto-rt = "0.17"` share | the fork's lockfiles |
| Fork-to-fork (Wasmtime → Tokio, Mio, target-lexicon; Javy → Wasmi, Wizer in `moturus/wasmtime`) | `[patch.crates-io]` entries with `git = "https://github.com/moturus/<repo>", branch = "motor-<version>"` | the fork's lockfiles |
| Ring | unchanged: git, exact rev | the fork's lockfiles |
| Javy and Wasmtime themselves | `src/build-addon-sources.sh`: branch and full revision, like `src/toolchain-versions.sh` | the tree branch |
| Toolchain and sysroot for the fork scripts | `RUSTUP_TOOLCHAIN` and `MOTOR_SYSROOT` in the environment, exported by `build-motor-os.sh`; the scripts no longer read `../motor-os` | the tree branch |

Cargo accepts a lockfile pinned to a commit that is not on the declared
branch (`cargo update -p moto-rt --precise <rev>` fetches it by hash, as does
a fresh `cargo fetch --locked`), so the forks name `main` and today pin
`fc48f27d` (the `dev` head, which has `F_GUARDED` and the same `src/sys/lib`
as `wasm`). Once `main` carries it, plain `cargo update -p moto-rt` suffices.
Measured: resolving the Motor OS crates from GitHub takes 4 s and the repository
is 22 MiB in Cargo's git cache; Javy's Wizer dependency clones `moturus/wasmtime`
(140 MiB) once per machine.

**Update, later on 2026-10-20:** the owner published `moto-rt` 0.17.9,
`moto-sys` 0.3.2 (equal to the tree's `src/sys/lib/moto-sys`, with
`F_GUARDED`) and `moto-rt-cabi`, and ruled that Wasmtime takes `moto-rt` and
`moto-sys` from crates.io with a path-based filesystem adapter. Wasmtime
`08a09edea` declares `moto-rt = "0.17"` and `moto-sys = "0.3.2"` in its four
workspaces, patches no Motor OS crate by git any more, and dropped `moto-io`,
`moto-async`, `moto-ipc` and `moto-sys-io` with the adapter rewrite, so
nothing it needs is unpublished. Javy still takes `moto-rt` and `moto-sys` by
git at `fc48f27d`; both are published, so switching it is the same two-line
change per manifest plus `cargo update --workspace`. The "publish" alternative
below is therefore taken for the two crates every consumer needs; the other
nine are needed by nothing outside the tree.

**Tree-wide, same day:** the owner first ruled that everything takes
`moto-rt` from crates.io. The build showed the limit of that: a crate outside
`src/sys` that also uses an unpublished sys library by path (rmux with
moto-ipc, russhd with moto-io) then links two copies of moto-rt and moto-sys
and fails on mismatched types. The final ruling is therefore: crates under
`src/sys` reference each other by path (moto-sys keeps `version = "0.17"` next
to `path`, so the published crate asks crates.io), and every crate outside
`src/sys` takes Motor OS crates from crates.io only, which needs the remaining
libraries published as one crate, `moto-api`; see
[docs/plans/moto-api.md](moto-api.md). Its interim step 1 is in place: rmux,
russhd, rnetbench and the smoke suites keep path dependencies on moto-rt and
moto-sys until moto-api exists, rush moved to crates.io, and ten lockfiles
record the owner's moto-sys 0.3.2 bump (`32756ef6`). Open points for the
owner: the in-tree moto-rt source is 0.17.8 while crates.io has 0.17.9, and
`src/toolchain-runtime.sh` still describes the pre-ruling layout.

What a human does:

- **Advance a tree branch's toolchain or `src/sys/lib`:** nothing in the
  forks. Their locks keep their Motor OS revision and crates.io versions.
- **Use a new kernel or sys-io feature in a fork:** for Javy, push the tree
  commit and `cargo update -p moto-rt [--precise <rev>]`; for Wasmtime, publish
  the crate and `cargo update -p moto-sys` (or `moto-rt`); in each workspace with a
  lockfile (Wasmtime: root, `motor-runtime`, `motor-tests`, `motor-host-tests`;
  Javy: root, `motor-tests`), commit, push; then set the fork's `MOTOR_*_REV`
  in `src/build-addon-sources.sh` and gate.
- **Change Mio, Tokio, target-lexicon or Wasmi:** push the fork; in Wasmtime
  or Javy `cargo update -p <crate>`; then as above.
- **Switch tree branches:** `build-motor-os.sh` moves a clean `../javy` or
  `../wasmtime` to the branch's pinned revision (fast-forward on the fork
  branch when possible, otherwise detached, `git checkout <branch>` resumes
  work). It never leaves commits that are on no branch of the fork; an
  exported `MOTOR_JAVY_REV`/`MOTOR_WASMTIME_REV` builds a committed but
  unpinned revision.
- **Push order:** forks before the tree commit that pins them, so every
  machine can fetch the pin.

Alternatives considered:

- **Publish the Motor OS crates to crates.io** and take them by version, as
  `std` takes `moto-rt`. This is the only option that also removes the git
  dependency on the tree. It needs eight crates published in dependency order
  (`moto-sys` 0.3.2, `moto-ipc` 0.2.6, `moto-mpmc`, `moto-io-internal`,
  `moto-async`, `moto-sys-io`, `moto-io`, and `async-fs` renamed, since that
  name is taken on crates.io), `version =` on their in-tree path dependencies,
  and a publish for every sys-io protocol change the forks need. Published
  `moto-sys` 0.3.1 already differs from the tree's 0.3.1 (no `F_GUARDED`, no
  `E_PAGE_ABSENT` retry in `do_syscall`), which is the hazard: a version that
  was not bumped is silently stale, whereas a git revision is exact. The git
  scheme can move to this one crate by crate without touching the tree's
  scripts.
- **Declare `branch = "dev"`** instead of `main`, so that plain `cargo update`
  follows `dev`. A one-line change per manifest plus `cargo update`.
- **Pin ripgrep, Helix and sed by revision** the same way (`repo:branch:rev`
  in `src/build-addon-sources.sh`); they still follow their branch heads.
- **Move the Motor WASI host out of the fork** into a tree-owned crate that
  depends on Wasmtime by git, so that the tree's own path dependencies serve
  it. Too large: the adapters implement `wasmtime-wasi`'s internal backends.

Pre-existing, unchanged: Javy's lock carries three copies of the
`wasmtime-internal-*` crates (upstream Javy's crates.io Wasmtime and the Wizer
workspace's), as it did with the path patch.

**Gate, 2026-10-20 (fork heads pinned in the tree, pushed later that day).** Every
workspace resolves and fetches with `--locked`, also from an empty Cargo home;
`src/check-addon-lockfiles.sh` validates all twelve add-on workspaces offline;
`test-build-addons.sh` covers the pinned checkouts (older revision detaches,
newer fast-forwards, unpublished revision refused, revision on another branch
fetched, local commits never left). `src/build-motor-os.sh --javy-only` and
`--wasmtime-only` rebuilt both add-ons from the pins (Javy 1 m 43 s, Cargo
reusing Binaryen). Fork tests: Wasmi's regressions and no-std check, Wasmtime's
compiler-policy and ELF tests, `motor-wasi-tests` and Javy's `motor-tests`
built for Motor. VM gates on the rebuilt images: `test-wasm.sh` under Cloud
Hypervisor PASS (97 `wasmtime-smoke` commands per VM) and
`full-test-dev.sh --release` ALL PASS (QEMU wasm:224 and dev:256 included,
about 41 min). Logs: `build/claude-targets/deps/`.

### Deterministic reference recipe

Move these retained inputs into the maintained fixture manifest/host recipe:

| Input | Retained path | SHA-256 |
| --- | --- | --- |
| Linux Javy | `build/javy-prototype/artifacts/javy-linux` | `f6f12dc42ffcaa1c19244b1a332893d636d0d56d26e02089d94dc296b22fa719` |
| Plugin for both builds | `build/javy-prototype/artifacts/plugin.wasm` | `180230f9346dc4b7d7139791280c9f4da09b2292eef751a3d35ae80154d88350` |
| Hello source | `build/javy-prototype/artifacts/hello.js` | `e7b2c74fb0326fa7640e06f750757880bb87d3609ab684ea381f521925f7719f` |
| TypeScript source | `build/javy-wasi-prototype/fixtures/retained/typescript-workload.js` | `4969f6546b830e751b6797be028accd242fd24e6e506661c51ddcd16b2646d68` |

```sh
build/javy-prototype/artifacts/javy-linux build "$input" \
  -C plugin=build/javy-prototype/artifacts/plugin.wasm \
  -C deterministic -o "$output"
```

Use identical input/plugin bytes and flags on Motor, with default static linkage,
compression and optimization. Compare bytes and execute both outputs; record
arguments, all digests, status and stdio. Compare Motor's embedded-default path
with its explicit-plugin path; pin custom plugins individually. Linux's embedded
plugin differs, so never compare defaults implicitly. Diagnose mismatches rather
than replacing golden outputs to pass.

## Milestones ahead

Implement in 100–300 LOC review units including tests. Each item names where
its output lands: **fork** (reviewed commits on the named Motor branch, with
the engine tests that belong there; for `moturus/javy`, code only, with its
regressions in `src/tests/javy-smoke`), **tree** (commits in this repository:
build, imager, docs and integration tests) or **evidence** (measurements under
`build/`, never a dependency). Each milestone adds its build/image/test
integration once its maintained sources are published. A milestone is complete
when its implementation is delivered and its required behavior is verified;
test counts alone do not complete it. Preserve failures and diagnose their
causes; no retries, longer timeouts or weakened assertions conceal defects.

For each delivered row, test **both images at 256 and 224 MiB**, with matching
tools, services, workload settings, caps and concurrency, under the existing
`test-javy.sh` pattern. Require correct output, normal completion, zero
admission-refusal deltas, cleanup and VM responsiveness; record expected
refusal/trap cases separately. Record usable RAM, role/mask, resolved
binaries/features/profile/policy, service/image digests, cold/warm startup,
phase peaks/sampling gaps, sizes, scratch and concurrency. A sampled peak on a
larger VM does not establish the margin.

The final matrix covers hello and TypeScript through Javy, Wasmi, raw Wasmtime,
Pulley/native compilation, packaging, precompiled/native execution,
core/component paths and HTTP serving. Include malformed/mismatched inputs,
permission/authority refusal, allocation failure, cancellation, repeated
invocations and sustained concurrency/resource limits. Prebuilt artifacts may
isolate runtime checks but do not count as on-VM compilation. Each milestone
sets its numeric resource defaults from its measurements; the final matrix
confirms or refines them. No latency target is inferred from one run.

### Milestone 1 close-out: Javy/Wasmi remainder

Status 2026-10-09: 1f–1l are done, which closes milestone 1. All fork commits are
published (Javy `3a04d39`, Wasmtime `a6b85b1cb`, each ending with the
moto-rt 0.17.7 lock). The add-ons built from them with toolchain
`dev.2-abb676f7` passed the matrix under QEMU and Cloud Hypervisor: four
boots per VMM, 57 `javy-smoke` (61 with the identity checks) and 43
`wasmtime-smoke` commands each, zero admission refusals, about 280 s per VMM
(310 s with the identity checks) against `test-wasm.sh`'s 600 s bound.
Before publication, a temporary overlay of locally built binaries had passed
the QEMU matrix, and the new runner cases failed against the then-published
binaries.

- **1h:** streaming validation passed the matrix and cut sampled peaks where
  validation dominates: dynamic hello 168.5 to 81.4 MiB and `init-plugin`
  179.7 to 129.0 MiB at 224 MiB. The static TypeScript peak did not move
  (210.4/216.4 to 212.6/210.3 MiB on the wasm/dev images at 224 MiB); it is
  set later in the pipeline, so the headroom remains about 10–12 MiB.
- **TypeScript peak, 2026-10-11:** the peak is Binaryen's start on top of
  45–53 MiB of freed walrus memory that Frusa keeps until its 5 s reclaim.
  Javy `3dc8be1` (`Generator::generate_owned`) frees the 9 MB source once its
  bytecode and source section are built. Five runs each on the wasm image at
  224 MiB went from 207.3–212.4 MiB (median 212.1) to 197.3–208.1 MiB (median
  207.0); the spread follows the reclaim timing. Compile time stays 20.7 s.
  The add-on built from the published commit passed both matrices and
  `full-test-dev.sh --release`, with peaks of 201.6–204.2 MiB (wasm) and
  200.6–202.9 MiB (developer) at 224 MiB, so the median headroom is now about
  15 MiB. Reclaiming in Frusa on free was rejected: it puts heap-sized work on
  the free path.
- **1i:** owned lazy small-page backing costs about 4% of Wasmi TypeScript
  execution (326 against 314 ms median, five runs, at 256 and 224 MiB) and
  about 2 ms of instantiation; hello is unchanged. Accepted: the backing
  bounds memory and avoids grow-by-copy. No fork change.
- **1j–1l:** fixed with regressions as specified. Evidence is under
  `build/javy-milestone1/`.

Resolve the review corrections 1j–1l first, in small patches with their
regressions. Items 1f–1i remain independent of the Wasmtime milestones and
can be scheduled separately. All new Javy/Wasmi tests in this milestone go
into `src/tests/javy-smoke`; its build script already assembles WAT fixtures
from `fixtures/` with the `wat` build dependency, so hand-written modules need
no new dependency.

1. **1f — retained plugin and exhaustion matrix (done 2026-10-09).** Owner rulings 2026-10-09:
   real plugins install under `/devtools/javy/plugins/` (only the default
   today); test plugins are part of no image and live under `/none/tmp` during
   tests, uploaded by `test-wasm.sh` like the other test inputs. The custom
   GC (p1) and p2 plugin sources move from the prototype archive to
   `src/tests/javy-smoke/plugins`, a test-only workspace outside the fork.
   QuickJS needs wasi-sdk to build them: `src/build-motor-os.sh` fetches the
   pinned, digest-checked wasi-sdk 24.0 (the release rquickjs-sys would
   otherwise download unchecked), and the Javy add-on builds the raw plugins
   with the pinned guest Rust into the assembly's `tests/javy`. Run the
   retained custom GC/p2 plugin cases and the four deliberate fault-exhaustion
   cases on the delivered pipeline, all through the installed tools in
   `javy-smoke`. Backing cases (reservation growth to the limit, failed
   `memory.grow`, refused fault, cleanup) use WAT fixtures run by `wasmi` with
   `MOTOR_OS_CAPS=0`; custom plugin initialization, schema, compile and
   deterministic output use digest-pinned test plugins uploaded to `/none/tmp`.
   Expected refusals are recorded separately from the zero-delta rule. Output:
   tree tests, evidence at 256/224 on both images.
   Result: `javy-smoke` runs 71 commands per boot (75 with the identity
   checks). One memory grows to the then 96 MiB limit with zeroed pages and a
   refused further `memory.grow`, and a 1,537-page memory is refused at
   instantiation (since 2026-10-18 the memory grows untouched to 4 GiB and
   the oversized case is gone). With the driver holding all usable memory but
   48 MiB, the runner faulting in its 96 MiB is killed (status -1) with
   exactly one user admission refusal, recorded as expected; afterwards the
   full 96 MiB faults
   in again, and used memory is back within 1.2 MiB of before (the suite
   allows 8 MiB). The two plugins each initialize twice to identical bytes
   (7.3 and 7.6 s); p1 reports its option schema and compiles deterministically
   a program that uses `gc()`, `WeakRef`, `atob`, `DOMException`, the
   string-kind hook and `performance`, and the p2 program checks its globals.
   Sampled plugin peaks are 193/183 MiB at 256/224 MiB. Both matrices pass
   (four boots each, 71 + 93 commands, four expected refusals, 458 s under
   QEMU and 461 s under Cloud Hypervisor, up from about 295 s), and so does
   `full-test-dev.sh --release`, whose matrix with the identity checks then
   took about 490 s of `test-wasm.sh`'s 600 s bound; its two VMs now take
   238 s.
2. **1g — byte identity (done 2026-10-09).** Rule, set by the owner's choice
   of a toolchain fix: Motor output equals upstream Linux Javy 9.1.0
   (digest-pinned release, same explicit plugin, `-C deterministic`) byte for
   byte in every source mode. The only earlier difference, compressed
   TypeScript's `javy_source` (1,151,218 against 1,151,115 bytes), came from
   `log2f` in Brotli and disappeared with the toolchain fix above.
   `src/build-javy.sh` runs the pinned Linux Javy at add-on build time on
   `javy-smoke/fixtures/hello.js` (compressed, uncompressed, omitted) and the
   TypeScript workload (compressed) and stages the four digests as
   `linux-reference.txt` with the test inputs; `javy-smoke --linux-identity`
   compiles the same four on Motor and requires equal digests. The four
   compiles take about 32 s, so they run once per `full-test-dev.sh`, which
   passes `test-wasm.sh --linux-identity` to the first VM; `full-test.sh`
   and standalone `test-wasm.sh` runs skip them.
3. **1h — streaming plugin validation.** Implement validation that does not
   retain the whole plugin through the compiler phase, preserving complete
   validation and the malformed-input checks. Measure the phase budget before
   and after on both images at 224 MiB; the current headroom is 16.83 MiB on
   the small image and 8.43 MiB on the developer image. Malformed-plugin cases
   join `javy-smoke`. Output: fork code, tree tests, evidence.
4. **1i — backing timing.** Record Wasmi hello and TypeScript execution time
   with the owned small-page lazy backing against a heap-backed build on the
   same VM, and accept or justify the difference. Output: evidence; a fork
   change only if the difference is unacceptable.
5. **1j — selected toolchain and provenance (R1).** Resolve the Rust toolchain
   and assembly once in the orchestrator and pass that selection through fetch
   and the Javy fork's build script. Preserve explicit authoring selections;
   standalone builds may resolve a default when no selection was supplied.
   Verify that the installed manifest names the compiler and sysroot actually
   used. Add hermetic host contract tests with distinct managed/authoring
   selections, including reuse invalidation when the selection changes; the
   review's build-script probe, which stubs `cargo` and the fork script to log
   the toolchain they receive, is the model. Output: tree, `moturus/javy` fork
   build script, evidence.
6. **1k — runner correctness (R2–R5).** Fix the failures in small code-only
   patches in `moturus/javy`. Register each supported WASI function once with
   its fixed signature, so duplicate imports link and the linker rejects
   mistyped ones, while unknown preview1 names still fail only when called.
   Treat any guest exit status, including zero, as terminal in the runner's
   invocation loop rather than in `Vm::call`, so the compile paths keep their
   behavior. Track guest descriptor closure for descriptors 0–2. Dispatch the
   realtime and monotonic clocks correctly, return for the CPU-time clocks
   what Wasmtime's preview1 host returns so both runners agree, and reject
   unknown IDs with `INVAL`. Regressions go into `javy-smoke` as WAT fixtures
   run by the installed `wasmi`: duplicate imports, mistyped signatures, exits
   preventing later invocations, repeated close and read/write/stat after
   close, valid/invalid clocks, and lazy stdin (a guest that never reads while
   stdin stays open, partial reads and EOF). Output: fork code, tree tests,
   evidence.
7. **1l — evidence-directory ownership (R6).** Acquire a checkout-level harness
   lock before replacing `build/javy-images` and hold it across the entire
   image/memory matrix, retaining the launchers' separate VM lock. A contending
   invocation must fail without touching active evidence. A dedicated host
   contract test for this lock is optional; record one manual contention check
   as evidence. Keep one replaceable evidence directory and preserve failure
   evidence before a diagnostic rerun. Output: tree, evidence.

Exit: R1–R5 have passing regressions and R6 a recorded contention check, the
published/staged fixes pass the installed-tool matrix under both VMMs, the
retained matrix and byte-identity rule pass under the common acceptance rules,
the streaming and backing-timing measurements are recorded, and no diagnostic
switch remains in maintained code.

### Milestone 2: runtime-only Wasmtime and p2

Deliver `wasmtime-rt` in both images with precompiled Pulley command execution
under WASI p2, using the native adapters already on `motor-48.0.1`.

Status 2026-10-08: 2a is delivered; 2b, 2c, 2e and 2g are implemented as
`moturus/wasmtime` commits `e0e9548fb..146853f2f`, published, and were
qualified with locally built binaries on both images at 224 MiB (evidence in
`build/wasm-milestone2/`). 2d is done and 2f is partly done (below); since
2026-10-09 the delivered add-on passes the matrix under both VMMs. Since
2026-10-11 all items are done, and since 2026-10-18 the published heads are
gated ([the resume point](#status-and-resume-point-2026-10-19)).

- **2b:** owned lazy reservations (then 96 MiB per memory, 128 MiB and four
  per process; 4 GiB and no total or count since 2026-10-18) back every
  memory; `memory-check` grew a memory to the limit in 1 MiB steps with zeroed
  pages in about 82 ms, enforced the limits and left
  no charge after 256 teardown cycles and failed instantiations. TypeScript
  through `wasmtime-rt` ran about 3.5% faster than the copying
  `MallocMemory` path (563 against 583 ms over SSH, five runs).
- **2c** (entry-ID adapter, superseded on 2026-10-20 by the path-based one; see
  the decision under Native filesystem)**:** new checks cover NUL rejection, renamed subdirectory handles, stale
  handles to deleted directories, replacement after `stat` and unsupported
  link operations. A three-level parent-ID walk costs 41–54 µs against
  98–101 µs for a native path `stat`. A stale handle fails with
  `InvalidData` instead of `NotFound` (`InternalError` until 2026-10-09, when
  the lookup misread every sys-io error response): Motor FS refuses the stale
  generation, so confinement holds, but WASI sees an I/O error; mapping it
  better is a `src/sys` question and is not changed here.
- **2e:** the stack check passes (teardown, yield, eight-slot limit,
  zeroing), a deliberate overflow kills only its process, and a 2 MiB stack
  costs 4,202,496 bytes of charge. `run` delivers stdout and stderr, exit
  status 7, traps as abnormal exits, and `-W timeout=1s` interrupts a loop
  compiled with epoch interruption. The arena is documented in the fork's
  MOTOR.md. Since 2026-10-11 `wasmtime-smoke` also covers foreground Ctrl-C
  and parent exit on the fixture's `ready-loop` export (fork `75d22026a`).
  The driver supplies the terminal: rush runs with a stdin pipe marked as a
  terminal, and Ctrl-C on it ends a `run` spinning in Pulley with status 130
  while rush is still held. A runtime whose rush is killed ends once rush is
  reaped. Both passed on both images and in ten consecutive suite runs at
  224 MiB.
- **2g:** stores default to 64 instances, 16 tables and 32,768 table
  elements, overridable with `-W`; the reservations are a fixed host bound.
  Defaults are recorded in `docs/wasm.md`.

**2d and 2f, 2026-10-08.** `src/build-motor-os.sh` installs a pinned upstream
Rust (`WASM_GUEST_TOOLCHAIN`, 1.99.0) with `wasm32-wasip1`/`wasm32-wasip2` for
guest programs; the Motor toolchain still has no wasm32 targets. The Wasmtime
add-on builds a host Pulley `compile` tool from its own sources and precompiles
22 fixtures (about 12 MiB, staged outside the images since 2026-10-09): the
fork's lifecycle, limit and memory WAT modules, a native-target artifact for
refusal, 13 p2 socket programs, and the TypeScript workload compiled by the
digest-pinned upstream Linux Javy 9.1.0 with the pinned plugin.
`src/tests/wasmtime-smoke` (43 commands) and `javy-smoke` share
`src/tests/wasm-smoke-suite`; `src/tests/test-wasm.sh` replaces `test-javy.sh`
and runs both suites in each boot. With a locally built overlay, the QEMU and
Cloud Hypervisor matrices passed (four boots, 57 + 43 commands, zero admission
refusals, about 4.6 minutes per VMM). TypeScript through `wasmtime-rt` peaks at
89.6/99.9 MiB at 224/256 MiB.

The fork commits `62a4ed98a..113ca953f` are published. Running upstream's
socket programs on Motor found four adapter defects, now fixed: every WASI UDP
socket was bound at creation (upstream's writability wait reached the lazy
bind), native in-use and non-local binds surfaced as `unknown`/
`invalid-argument`, accepted TCP sockets ignored listener options, and without
`CAP_NET` guests saw `invalid-state` instead of `access-denied`. Twelve upstream
programs gain Motor branches under a `motor` test-programs feature, plus a
bind/listen ordering program; the non-Motor builds still pass on Linux under
upstream Wasmtime 48.0.1.

Native behaviors found and left unchanged (`src/sys`): a wildcard UDP bind
selects the non-loopback address, and that socket's sends to loopback succeed
but are never delivered; without `CAP_NET`, native socket calls fail with
`NotConnected`; TCP connection rings default to 64 KiB at 224 MiB and 128 KiB at
256 MiB and only grow; UDP has no buffer options; a closed UDP receiver reports
nothing to the sender.

**2f filesystem and stdio, 2026-10-09.** 48 more upstream programs (34 p1, 14
p2) run through the installed `wasmtime-rt` as None with `CAP_FS_WRITE`, with
the preopens and arguments upstream's own tests give them: per-program scratch
preopens, a driver-owned `readonly` preopen whose file must survive, CLI root
and multiple preopens, `-S cwd`, stdin from a file, an append to a guest-owned
file and 256 KiB of stdout; one write is refused without `CAP_FS_WRITE`.
`wasmtime-smoke` runs 93 commands, about 3 s more per boot; the fixtures grow
by 14.4 MB to 26.3 MB (70 artifacts). Since the same day they and Javy's test
inputs (8.8 MB) are staged outside the images and uploaded per boot, which left
the Cloud Hypervisor matrix at 296 s. The programs found six adapter defects,
fixed in published fork commits `44bb21055..46465a092`: the lookup misread
sys-io error responses as protocol errors, paths ending in `/` or `/.` did not
have to name a directory, directories opened for writing, a read-only handle
could be truncated, a non-empty directory surfaced as `EFBIG` (sys-io encodes
it as `FileTooLarge`), and rename replaced a destination of the other kind.
Seventeen programs are excluded for missing Motor features: symlinks (9), hard
links (2), settable times (2), a host-set extreme mtime (1), read-only
preopens, which the CLI cannot grant (2), and `EPIPE` for a writer whose reader
is gone (1). The native behaviors behind these are in `future-work.md`. The
add-on built from the published fork passes the QEMU and Cloud Hypervisor
matrices (four boots each, 57 + 93 commands, zero admission refusals, 290 and
295 s).

The Pulley disposition was accepted on 2026-10-09 (see the item below), which
completes 2f.

1. **2a — add-on delivery (delivered 2026-10-08, `--wasmtime-only`).** A
   host-precompiled Pulley hello ran on the wasm image as None, with role and
   capability refusals; evidence in `build/wasm-milestone2/2a`. Add
   `src/build-wasmtime.sh` on the corrected
   `build-javy.sh` pattern: follow `moturus/wasmtime`, `target-lexicon`, `tokio`
   and `mio`, build the runtime-only graph with the release profile in its own output
   directory, stage `/devtools/bin/wasmtime-rt`, record the source graph in
   `/devtools/wasmtime/sources.txt`, and key reuse on it. Install in both
   images and extend the imager policy test and build docs. Pass the selected
   toolchain/assembly through `motor-build.sh`; its current managed-selector
   override must receive the same correction as 1j. Output: tree, fork build script.
2. **2b — guest memory backing.** Integrate `Config::with_host_memory` with the
   owned-reservation contract shared with Wasmi: per-memory, aggregate and count
   bounds; zeros on growth; failed `memory.grow` at the limit; release on drop,
   failed instantiation and cancellation. This replaces the zero-reservation
   `MallocMemory` path that grows by copying. Qualify growth to the per-memory
   limit in steps on both images at 224 MiB, and record execution timing as in
   1i. Output: fork with engine tests, evidence.
3. **2c — filesystem confinement** (done with the entry-ID adapter, which the
   path-based adapter over `moto-rt` replaced on 2026-10-20; its
   `motor-host-tests` cover the same cases with path semantics)**.** Qualify the existing entry-ID adapter
   (`motor_fs` plus `motor_lookup::lookup`) against the contract: absolute paths,
   NULs and traversal rejected before I/O; renamed preopens/subdirectories,
   replacement between check and use,
   stat/open mismatch, stale generations, permissions and descriptor lifetime
   covered in the fork's `motor-host-tests`; unsupported operations return
   explicit errors. Extend the existing rename/replacement and client-reuse
   tests with the missing interleavings and lifecycle cases. Measure ownership,
   cancellation, stale connections and IPC cost of the existing narrow `CMD_STAT`
   lookup before final acceptance. Output: fork tests/fixes, evidence.
4. **2d — networking subset.** Carry the Motor variants of the p2 fixtures in
   the accepted-TCP and keepalive tables, the bind/listen ordering regression,
   the UDP unspecified-bind and immediate-close cases, and the ring-capacity
   report for the host write queue. Constants reference the sys-io source.
   Output: fork.
5. **2e — authority, stacks and lifecycle.** Qualify the existing role/mask
   guard of the runtime-only (`motor-template`) build before input parsing
   (exemptions and populated-ELF rule as in the contract). The full CLI has no
   guard yet; 4b adds it. Promote the existing
   guarded fiber stacks: named sub-range, alias unmap, overrun kills only the
   process, repeated teardown returns memory, per-stack
   cost recorded; fall back to canaries only if the probe fails. Verify `run`
   stdio, exits/traps, parent exit and interruptibility. Output: fork,
   evidence.
6. **2f — integration tests and Pulley disposition (done 2026-10-09).** Add
   `src/tests/wasmtime-smoke` and reuse the corrected Javy image-matrix driver
   through a shared wasm driver or a thin `test-wasmtime.sh` entry point.
   Register it in `full-test-dev.sh --release` and update the host contract
   tests. The driver reuse requires 1l. Qualification depends on 2b–2e and the
   command defaults in 2g.
   Fixtures are digest-pinned prebuilt Pulley artifacts (hello, echo and the
   TypeScript workload) built on the host and uploaded to `/none/tmp` with the
   tests. Cover precompiled p2 rights and preopens,
   EOF/partial I/O, descriptors/directories, network denial under mask `0`,
   cancellation, finite limits, repeated invocations, malformed/mismatched
   artifacts and the refusal cases. Investigate the retained unexplained
   Pulley invalid-opcode event against the maintained runtime: identify the
   original binary/configuration/fixture and preserve its diagnostics. Record
   either a diagnosed fix with a regression or an explicit owner-reviewed
   scope/acceptance decision before milestone 2 exits; non-recurrence alone
   does not resolve it. Analysis 2026-10-08: the retained
   `build/javy-prototype/logs/vm-serial.log` shows the kernel's
   `INVALID OPCODE in uspace` (an x86 `#UD` in some user process, which the
   kernel does not name), not a Pulley decoder error. Native panics and
   `abort()` on Motor no longer raise `#UD` (both exit -1, checked), and no run
   in this milestone raised one. The likely sources are native code: wasm
   traps compiled as `ud2` under signal-based traps, which
   `Config::motor_runtime()` now disables, or CPU features missing in the VM.
   Disposition, accepted by the owner 2026-10-09: closed for Pulley, as not
   reproduced on the maintained runtime; 4d carries a native trap check (the
   trap is reported, no `#UD`). Record sizes and the disk budget. Output: tree, fork
   regression/fix as indicated, evidence on both images at 256/224 under both VMMs.
7. **2g — command resource defaults.** Before 2f acceptance, set finite
   StoreLimits and limits for tables/resources, instances and command stack
   pools from the 2b/2e measurements. Memory count, aggregate backing and
   per-memory growth use the bounds 2b establishes rather than a second set;
   include temporary buffers in the budget. Cover default-limit enforcement,
   allowed overrides, refusal and cleanup. `run` remains interruptible with
   optional fuel/time controls.
   Record numeric defaults here and in the installed guide. Output: fork,
   tree documentation, evidence.

Exit: precompiled p2 workloads pass with explicit caps/WASI grants under the
common acceptance rules; backing, confinement, networking subset and stack
containment are qualified in the fork; finite command defaults and the Pulley
failure disposition are recorded; existing Tokio/Mio users remain on their
pinned versions and untouched.

### Milestone 3: HTTP/HTTPS and opt-in p3

Deliver `serve` on the runtime-only build, with bounded resources and the
experimental p3 path behind `-S p3`.

**Status 2026-10-14: measurements and decisions.** Nothing for milestone 3 is
committed yet. The measurements used the published runtime on the wasm image
at 224 MiB, upstream serve test programs precompiled like the 2d/2f fixtures
(p2 `p2_cli_serve_hello_world`, `p2_cli_serve_sleep`, `p2_api_proxy_streaming`;
p3 `p3_cli_serve_hello_world`, `p3_http_echo`, `p3_cli_serve_sleep`) and an
out-of-tree load client that 3f's in-crate client replaces.

- **Flags.** p2 serving needs `-Scli`; p3 needs
  `-Wcomponent-model-async -Sp3,cli`.
- **Memory limits block concurrency.** p2 creates an instance per request, and
  a memory without a declared maximum reserves the full 96 MiB, counted in full
  against the 128 MiB process total, so any second concurrent p2 request gets
  HTTP 500 ("Wasm memory reservation limits reached"). p3 reuses an instance
  for 128 requests (16 at once) and served 8 concurrent clients, but 7 of 400
  requests failed while a retiring instance overlapped its replacement. Echoes
  of 2 and 8 MiB work under p2 and p3 when the client writes and reads
  concurrently. One p2 hello request costs about 4.5 MiB of VM memory.
- **Prototype.** Counting the total against grown size (a new memory charged
  its initial size, each growth its increase, a growth past the total failing
  `memory.grow`, a drop returning the current size) with 16 memories served
  8 concurrent p2 requests (+7–10 MiB), 8 × 2 MiB p2 echoes, 400 p3 requests
  without failure and 32 staggered p3 echoes. It is about 15 lines in the
  fork's `src/motor_memory.rs` and is not committed.
- **Superseded 2026-10-18.** The kernel's sparse lazy segments made untouched
  reservations nearly free, and the owner ruled for Linux parity: 4 GiB per
  memory, no total and no count (the
  [memory contract](#javy-pipeline-and-memory-backing)). The 2026-10-14 ruling
  to keep 96 MiB and four memories and the open question of the 128 MiB total
  are void. Both failures above came from reservation accounting; 3a
  remeasures p2 concurrency and p3 instance turnover. The trade-off accepted:
  a guest is bounded only by RAM, and when RAM runs out the process whose
  fault is refused dies, which can be the server or another process.
- **Bound requests, not connections.** Upstream defaults both
  `--max-concurrent-requests` and `--max-concurrent-connections` to 1,000. The
  request bound makes extra requests wait after accept; the connection bound
  holds accepts back, and below 256 MiB sys-io queues only 8 completed
  connections per listener (`docs/networking.md`) and resets the rest. Upstream
  `serve` accepts continuously, so only simultaneous connect bursts overflow:
  16 clients connecting at once lost 6 to resets, while 16 or 32 spread 5 ms
  apart lost none, and a native std server behaves the same. 3a bounds
  requests; 3f's client spreads its connects or keeps bursts at 8 or fewer.
- **Other inputs to 3a.** Fiber stacks are eight eager 2 MiB slots charged
  about 4 MiB each, and sparse lazy segments do not help them: a lazy map has
  no fixed address or guard page from userspace. With memories unbounded they
  are the next limit on serving concurrency; the owner ruled (2026-10-18) to
  measure them in 3a before choosing a design. Upstream uses lazily committed
  stacks with a guard page and no slot limit. Each closed connection held
  about 130 KiB in sys-io for 10 s (TIME-WAIT), which bounds sustained
  connection rates on small VMs; 3a measured 400 KiB, and the TIME-WAIT
  release below removes most of it. Drivers should let servers
  inherit their stdio: a None child cannot write a file that rush redirected
  for it without `CAP_FS_WRITE` (`docs/caps.md`).

**3a measurements, 2026-10-18.** Published `wasmtime-rt` with a temporary
stack-reporting patch, the wasm image at 224 MiB, the same fixtures plus
epoch-compiled sleep and hello variants, and the load client sampling the
server's resident memory; servers and client share the VM, so each closed
connection has both ends in sys-io. Log and patch in `build/claude-targets/m3/`
(`x3a-224.log`, `diag-stack.patch`).

- **Fibers.** Eight slots, refused at once when full (`Motor fiber stack
  limit reached`, HTTP 500). p2 takes one per in-flight request: the ninth
  concurrent sleeping request fails while eight wait. p3 shares them: 64
  concurrent hello requests used 2 slots and 32 sleeping requests 5. Pulley
  serving used at most 6 KiB of each 2 MiB stack over about 930 leases, so the
  eager 2 MiB (about 4.2 MiB of server memory per in-flight p2 request) is
  nearly all unused. Native AOT will put Wasm frames on these stacks too.
- **Deadlines.** None by default. Eight never-ending p2 requests hold every
  slot, and all later requests get 500 until restart. `-W timeout=2s` with
  epoch-compiled artifacts turns them into 500s at 2 s and frees the slots
  (p2 and p3); a server with a timeout rejects artifacts compiled without
  epochs, and the reverse.
- **Connection memory.** Each closed loopback connection held about 400 KiB of
  sys-io for 10 s (29.9 to 75.0 MiB over 114 p2 requests), the figure the
  `future-work.md` TIME-WAIT entry left unexplained, not 130 KiB. Eight
  concurrent requests for 50 rounds, or 64 concurrent p3 requests for a few
  rounds, filled the VM to about 200 MiB; `rt_net` then reported `accept pump
  reservation failed: OutOfMemory` and the server exited with `Error:
  OutOfMemory (os error 8)`, because `serve` returns on any accept error. The
  TIME-WAIT release below fixes the memory. Sixty-two idle connections held 45 MiB (34 in sys-io, 12 in the server), and
  nothing times them out: Hyper has no timer, so no header-read or idle
  timeout applies, and the connection limit is 1,000.
- **Per request.** 2 MiB echoes: 8 concurrent p2 requests raised the server by
  about 32 MiB, 16 concurrent p3 requests by about 7 MiB.

**TIME-WAIT release, 2026-10-18 (sys-io patch `4ee0cf22`).** The owner asked
for a standalone `src/sys` patch, fully gated and left uncommitted for review,
and committed it on 2026-10-19 after review. It changes no fork, moto-io,
moto-rt or kernel code and adds no statics.

- **Causes.** A server closes first, so its socket spends `CLOSE_DELAY` (10 s)
  in TIME-WAIT, and three things kept its memory there:
  1. The socket's `ClientSender` kept the client channel's 64 + 64 shared
     pages (512 KiB) mapped in sys-io after the client was done with it.
  2. The netstack shrinks an orphaned socket's rings only on a state change,
     and only if `rx_shutdown` is already set, so a socket that reached
     FIN-WAIT-2 or TIME-WAIT before its close kept its rings (64 KiB each way
     at 224 MiB).
  3. In `process()` the state change runs before the ACK of the FIN dequeues
     the data it also acknowledges, so the rings still held data at the
     transition. 199 of 200 `serve` sockets took this path: they were closed
     in FIN-WAIT-1.
- **Fix.** The netstack (`src/sys/sys-io/netstack/src/socket/tcp.rs`) gets one
  `release_orphan_rings` helper, called from `set_state`, from
  `set_rx_shutdown` and after that dequeue; the floors stay 16 KiB in
  FIN-WAIT-2 and 1 byte in TIME-WAIT. An orphaned socket ignores text past
  the peer's FIN, as RFC 9293 does, so no ring is released under text already
  admitted to it. In sys-io (`runtime/net/socket.rs`, `socket/tcp.rs`,
  `socket/udp.rs`), `SocketBase::client_sender` becomes an `Option`, and the
  channel handle that keys the client's socket set is kept beside it; every
  ownership check compares that handle. Linger step 3, which waits out
  TIME-WAIT, drops the sender, and the state-change notifier skips a socket
  without one. A close of a socket the client has already closed fails with
  `NotFound` instead of running teardown again.
- **Review, 2026-10-18.** A reviewer found three crashes in the first version,
  each reproduced in a VM. All three are fixed above:
  1. A UDP request naming the retired TCP socket's ID, from any client,
     panicked sys-io: the UDP ownership checks read the released sender
     before checking the socket type.
  2. The owner's second close ran teardown again and panicked on the released
     sender. HEAD also accepts a second close: it answers OK and runs
     teardown again.
  3. In debug builds, the netstack asserted when the ACK that ends CLOSING
     carried text past the peer's FIN: the release shrank the receive ring
     after the text was admitted. HEAD hits the same assertion, through the
     `set_state` release, when our data was acknowledged with the peer's FIN.

  The review also asked for a single-connection systest with an isolated
  baseline, TIME-WAIT checked after the channel is released, and the
  FIN-WAIT-2 release test folded into an existing test.
- **Tests.** Each new test fails without its fix.
  - netstack: `test_rx_shutdown_in_time_wait_releases_rings`,
    `test_rx_shutdown_rings_released_when_fin_ack_covers_data` and
    `test_rx_shutdown_ignores_text_after_peer_fin` are new, and
    `test_no_rx_shutdown_keeps_rings_in_fin_wait_2` now continues through
    both releases. `cargo test --lib` passes all 916 tests.
  - systest: `test_time_wait_releases_client_channel` runs one connection in
    a child (`tcp-time-wait-child`) whose server end closes as an HTTP/1.1
    server does. With no other socket closing, it requires `net.channels`
    back at its baseline, and then the socket still in TIME-WAIT. HEAD fails
    it with `timed out waiting for net.channels; last value was 2`.
  - systest: `test_requests_to_retired_tcp_socket` takes a raw channel's
    socket through a positive-linger close to TIME-WAIT. It then sends a
    second close (expects `NotFound`) and UDP get-option requests on the TCP
    socket from the owner (`InvalidData`) and from another client
    (`NotFound`). The first version panics sys-io on it, with or without the
    close fix; HEAD fails it at the second close.
- **Effect.** Measured on the wasm image the gate built, at 224 MiB, with
  `xtw.sh` and `x3b.sh` (logs `xtw-base-224.log`, `xtw-final-224.log` and
  `x3b-224.log`).
  - 200 `Connection: close` hello requests to `wasmtime-rt serve`, 8 at a
    time, leave 208 sockets in TIME-WAIT. sys-io resident is then 22.6 MiB
    with 3 channels, against 97.8 MiB with 101 channels before the patch, from
    a baseline of 17.3 MiB. Once the sockets expire, sys-io settles at
    21–22 MiB both with and without the patch.
  - The 3a cases that ran the VM out of memory now pass with no failures: two
    rounds of 400 p2 requests at 8 concurrent, then a p3 server taking 400 at
    8 and 256 at 64. The VM stays at or below 53 MiB during the p2 run and
    63 MiB during the p3 run, with up to 1,465 sockets in TIME-WAIT, about
    10–12 KiB of sys-io each. Before the patch, the first p2 round filled the
    VM to about 200 MiB, and `serve` exited on `OutOfMemory`.
- **Gate.** The first version passed `full-test.sh` 3 times in debug and 3
  times in release, and `full-test-dev.sh --release`. The revised version
  passed the same gate on 2026-10-18: debug 1,094, 1,034 and 1,030 s, release
  781, 699 and 662 s, `full-test-dev.sh --release` 2,427 s. Both new systests
  passed in all six `full-test.sh` runs. `xtw.sh` on the revised image
  (`xtw-rev-224.log`) leaves sys-io at 22.1 MiB with 2 channels after the
  `serve` burst, in line with the first version's numbers.
- **Docs.** The P2 TIME-WAIT entry in `future-work.md` becomes a P3 for what
  remains, 10–25 KiB per socket: the netstack socket, the `MotoSocket` and
  its linger task.
- **Next.** 3a resumes with the decisions below.

**3a decisions** (put to the owner 2026-10-18):

1. **Stack slots** (ruled 2026-10-19: lazy guarded stacks, as on Linux), not
   a p2 request cap or smaller stacks. Done in the fork; see below.
2. **Deadlines** (ruled 2026-10-19: Linux parity). No default timeout;
   document `-W timeout` and epoch compilation.
3. **Connection timeouts** (ruled 2026-10-19: upstream). Hyper gets no timer,
   so idle and slow connections stay open up to the connection limit;
   document it.
4. **Accept errors** (ruled 2026-10-19: upstream). `serve` exits on any
   accept error, including a transient `OutOfMemory`.

**Lazy guarded fiber stacks, 2026-10-19 (fork `5d9818f3c`, not yet
published).** The kernel's guarded heap maps (`fc48f27d`, merged into `wasm`
at `832be142`) made the planned lazy map at a fixed address unnecessary.
`SysMem::F_GUARDED` with `F_READABLE | F_WRITABLE | F_LAZY` maps
`num_pages + 2` small pages at an automatic address, with a page at each end
that is never mapped. `map2` returns the lower guard's address and the full
size, `free` takes that address, touched pages are charged as they are
faulted in, and a None process needs no capability. A touch on either guard
kills the thread.

- **Fork change** (`src/motor_stack.rs`, `MOTOR.md`). One guarded lazy map
  per stack: the stack is its interior and `guard_range()` its lower guard.
  The slot arena, the `OCCUPIED` bitmask, the 8-slot limit, the 2 MiB size
  cap, the custom-region convention and `contains()` are gone, so stacks are
  limited as on Linux, by `--max-concurrent-requests`. The pool still caches
  two stacks per engine. A zeroed request takes a fresh map, whose pages read
  as zero, instead of zero-filling a cached stack and committing all of it.
- **Tests** (`motor-runtime/src/bin/stack-check.rs`). A 2 MiB stack reserves
  exactly 2 MiB plus two pages; touching its two ends commits exactly two
  pages. A cached stack is reused with its bytes, and a zeroed request gets
  a different, zeroed stack. The 2,048-cycle teardown loop returns the
  reservation exactly. 1,000 stacks leased at once, each with its top page
  touched, commit 4.37 MiB (1,000 pages plus 472 KiB of the leases' heap,
  bounded at 1 MiB), and dropping them leaves less than one stack's
  reservation behind: the test's own heap, 456 KiB, on which an exact check
  failed in the first run. The test reads only its own process's
  `memory_usage` and `memory_resident` metrics; an earlier version read
  system-wide used memory, which other processes move, and wrote through
  raw addresses from a safe closure. Wasmtime's callbacks run on the
  stacks the pool handed out, and `stack-check overflow` is killed (exit -1)
  by a refused fault outside the main thread's stack while the shell
  survives. `memory-check` still passes. Neither binary runs in a tree test.
- **Measured** on the release wasm image rebuilt from `832be142`, at 224 MiB,
  with the fork's local build (`build/claude-targets/fiber/`, `xfib.sh`,
  `xfib2-224.log`):
  - p2 sleeping requests under `-W timeout=2s`: 9, 16 and 64 concurrent all
    end in the 2 s timeout, and none is refused at once. The server grows
    11.2 MiB for 8 (33.4 MiB in 3a) and 81.0 MiB for 64, about 1.3 MiB per
    in-flight request; that is the instance, not its stack. The VM peaks at
    165.8 MiB.
  - p2 hello at 16 and 64 concurrent (3 rounds) and 8 × 50: no failures.
    p2 2 MiB echoes at 8 and 16 concurrent: no failures, with the server up
    13.7 and 21.6 MiB (32 MiB for 8 in 3a).
  - p3 hello at 64 concurrent and 8 × 50: no failures; 32 sleeping p3
    requests end in the 2 s timeout. p3 used 2–5 stacks before and is
    unchanged.
- **3a's request bounds stay upstream's.** At about 1.3 MiB per in-flight p2
  request, a 224 MiB VM runs out of RAM near 100 sleeping requests, far below
  the default of 1,000; then whichever process has a fault refused dies. That
  is the Linux-parity trade-off already accepted for linear memories.
- **Docs.** `docs/wasm.md` now covers the stacks and the upstream `serve`
  behavior the 3a rulings keep: the default request and connection limits,
  no default deadline (`-W timeout` needs epoch-compiled artifacts), no
  header-read or idle timeout, and exit on accept errors. `MOTOR.md` needs
  nothing for behavior that matches upstream.
- **Next.** The forks are pushed (2026-10-20: mio, tokio, wasmi, javy
  `12a6c52`, wasmtime `08a09edea`, which carries `8804845d7` and `5d9818f3c`);
  the tree changes of that day are staged for the owner's commit. The moto-rt
  0.17.9 lock that blocked `--locked` builds on 2026-10-19 is gone with
  [the dependency scheme](#fork-dependency-scheme-2026-10-20): Javy and
  Wasmtime take `moto-rt` 0.17.9 and `moto-sys` 0.3.2 from crates.io. The
  add-ons rebuilt from the pinned revisions through `src/build-motor-os.sh
  --javy-only` and `--wasmtime-only`; the wasm matrices passed under QEMU and
  Cloud Hypervisor with wasmtime `08a09edea`, so 3a closes once the owner's
  commit lands; 3b and 3f follow the moto-api merge
  ([docs/plans/moto-api.md](moto-api.md)).

1. **3a — HTTP resource defaults.** Extend milestone 2's finite command defaults
   with request, body/buffer and serving-concurrency limits; size the stack pool
   for the intended concurrency and wire epoch deadlines. Measure aggregate
   resource use across concurrent stores and adjust defaults explicitly.
   Output: fork, evidence.
2. **3b — serving lifecycle.** Upstream command/HTTP bindings in the shared
   host; p3 stores kept through post-return; connection/handler tasks joined.
   Cover slow readers, concurrent streams, disconnects, cancellation,
   foreground None Ctrl-C, active-request and background shutdown, and the
   accepted zero-transmit reset. Diagnose the earlier intermittent reset on
   fragmented/different-header requests before this item exits; it is not
   retried away. Output: fork, evidence.
3. **3c — p3 opt-in.** Preserve the existing `component-model-async` build and
   Motor `P3_DEFAULT=false`. Qualify installed default rejection and explicit
   `-S p3` operation, retaining selected p3 regressions with recorded upstream
   reasons. Output: fork/tree tests and any fixes, evidence.
4. **3d — TLS.** Rustls/Ring over native clocks/entropy, trusting the image's
   CA bundle (wasmtime `633e7de36`; roots update with the build host, see
   [docs/imager.md](../imager.md)); hermetic local-CA tests for success, wrong
   name/IP, expired/not-yet-valid, invalid chain, and streaming
   failure/cancellation; no Internet. Output: fork, tree fixtures.
5. **3e — service masks.** Decide the `CAP_LOG` question in the authority
   contract, then test a wasm service started by sys-init with its service mask
   and outbound HTTP grants audited separately from socket grants. Output:
   tree.
6. **3f — integration tests.** Extend the wasm integration crate with hello,
   echo and a representative TypeScript HTTP fixture served by `wasmtime-rt`
   and exercised by an in-crate client with bounded concurrency; p2 and p3
   variants; both images at 256/224. Output: tree, evidence.

Exit: concurrent hello, echo and TypeScript HTTP workloads pass with bounded
resources and clean shutdown on both images; p3 retains its experimental
scope; hermetic HTTPS cases pass.

### Milestone 4: full compiler and native packaging

Deliver the full `wasmtime` CLI and the native packaging path, then run the
complete matrix.

1. **4a — compiler policy qualification.** Retain the existing target-resolved
   coalescing defaults, `Config::motor_runtime()` Pulley profile,
   `memory_guaranteed_dense_image_size(0)` and `memory_init_cow(false)`.
   Extend the fork's `motor-tests` coverage on Linux and Motor hosts: sparse
   extents below/at/above 16 MiB, dense images, multiple memories, passive data, start
   ordering and fallback, recording initializer choice, artifact size and copy
   cost. Qualify the policy through delivered CLI paths, bound compiler
   input/output resources and remove any remaining tracing. Output: fork
   tests/fixes, evidence.
2. **4b — full CLI add-on.** Build the Cranelift graph in `build-wasmtime.sh`
   into its own output directory, stage `/devtools/bin/wasmtime`, and install
   it in both images. Apply the same role/mask guard as the runtime-only build
   before any input parsing, with the same `--help`/`--version` exemptions, and
   test its refusals. Qualify on-VM Pulley and native compilation of hello and
   TypeScript at 256 and 224 MiB; the prototype peaks are 183.64/195.77 MiB
   (core/component, 256 MiB) and 173.69/181.26 MiB (224 MiB). Output: tree,
   evidence.
3. **4c — packager.** The `package` subcommand streams a core/component ELF
   from the installed template with exclusive creation, atomic publication,
   permission finalization and cleanup on failure/cancellation; validates ELF
   arithmetic, ranges, alignment, overlap, lengths and code lifetime; matches
   the exact Wasmtime version string; and compiles with the consumer feature
   graph and epoch instrumentation. Output: fork with publisher regressions.
4. **4d — separate masked flows.** Compile and package under `0x200` into a
   None-writable scratch directory, then execute the populated ELF under `0` or
   `0x100` in a separate invocation, including from an Interactive shell;
   verify stdio, exits/traps, parent-exit behavior and refusal of mismatched or
   stale artifacts. A guest trap in native code must be reported as a trap and
   raise no `#UD` in the kernel log, which closes the 2f Pulley disposition for
   native code. Output: tree tests, evidence.
5. **4e — disk and scratch budget.** Record file and loadable bytes for all
   four tools, the template, populated ELFs and fixtures, plus simultaneous
   scratch/output use, within the 1 GiB small image; record spawn and compiler
   peaks separately. Output: tree (imager sizing if needed), evidence.
6. **4f — final matrix.** Run every row of the final matrix on both images at
   256 and 224 MiB and record each as unrun, failed, passed at 256 MiB or passed
   with margin, naming its binary, image and fixture. Confirm or refine the
   numeric resource defaults adopted at the earlier milestone gates. Output:
   evidence and the status table in this document.

Exit: the complete matrix passes with every installed tool on the final small
image and the developer image within the RAM and disk requirements.

### Order and prerequisites

Recommended next steps: 3a, 3b and 3f, with 3c–3e after them; 4a and 4c can
proceed in the fork alongside. Retain one image-matrix driver and use the common acceptance
rules above for every milestone. Keep Wasmtime engine regressions in its fork;
Javy/Wasmi regressions live in `javy-smoke`.

| Milestone | Starts after |
| --- | --- |
| 1 | Done 2026-10-09. |
| 2 | Done; gated with the memory-limit change on 2026-10-18. |
| 3 | In progress; 3a waits on publishing Wasmtime `5d9818f3c` and its gate, and precedes 3f. |
| 4 | 4a and 4c can start in the fork after 2a; 4b, 4d–4f need the milestone 3 host and the milestone 2 template. |

Production changes follow [AGENTS.md](../../AGENTS.md). Application changes use
focused tests; any separately approved src/sys change requires three debug and
three release main-image passes before commit. Non-Lorry developer-image gates
remain release-only. These gates apply to implementation, not this plan.
