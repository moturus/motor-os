# Javy and Wasmtime infrastructure for Motor OS

Owner direction, 2026-10-27: match Wasmtime on Linux as closely as Motor's APIs
permit, including native execution, compilation, p3 enablement and resource
defaults. Compare the same Wasmtime version with equivalent build features and
options. This supersedes the earlier Motor-specific p3 opt-in and finite store
defaults. Add executable-memory support, then run native code directly inside
Wasmtime. The former Pulley-first delivery and Motor-specific ELF packaging
design are superseded.

Milestone 4 is complete. The OS prerequisite, native Wasmtime v50 integration
and Javy's v50 dependencies are committed. The main tree pins the published
fork revisions used by the qualified release images. Historical qualification
details remain in git history; `2cf4ecdc` contains the previous plan and evidence
record.

## Status and resume point (2026-10-27)

The owner approved the follow-up [fork audit and v50 port](wasmtime-fork-audit.md),
including upgrading Javy's Wasmtime/WASI/Wizer dependencies to v50. Javy retains
its Wasmi backend; keeping Wizer on v48 was a scope choice, not a requirement.
The v50 implementation is published on `motor-50.0.0` and qualified.
Wasmtime passes 143 commands on each image at 224 and 256 MiB, plus the existing
p2/p3 service gate. Javy passes on `wasm:224` and `dev:256`, including all four
Linux byte-identity cases on the first VM. Main-tree commits `5ea18cfd` and
`8e86a569` complete the image integration and installed checks. The v48 branch
and evidence below remain a fallback.

| Area | Current state |
| --- | --- |
| Javy/Wasmi | Javy's Wasmtime/WASI/Wizer dependencies now use v50, retaining Wasmi. Static/dynamic compilation, TypeScript, plugins, byte identity, memory backing and runner regressions pass in the prepared images. |
| Runtime-only Wasmtime | The committed v50 pin loads native command/HTTP artifacts directly, with no template or compiler in the runtime-only binary. |
| HTTP, sockets and filesystem | Native adapters and shared WASI hosts are delivered. Existing lifecycle, timeout, grant, service-mask and p3 regressions pass. System CA loading is delivered. |
| Full CLI foundation | Both v50 CLIs use the upstream package with separate feature selections, sharing authority checks, native network checks, lazy memories and guarded fibers. The runtime wrapper workspace is removed. |
| Full CLI image integration | Delivered: separate full/runtime builds, both required image binaries, normal host cross-compilation, and updated existing smoke checks, using published fork pins. |
| Default policy | v50 uses the native target, upstream p3/store defaults, the upstream TCP write budget and normal artifact versioning. There is no Motor-only 4 GiB memory64 cap or ELF packaging path. |
| Executable memory | Delivered in main-tree commit `9b97640d`, with kernel-only implementation and in-VM systests. No moto-sys, moto-rt or stdlib change was needed. |
| Native workflow | v50 retains owned executable code mappings in both CLIs. Native run/serve/compile, direct loading, traps, TypeScript, p3, limits and memory64 growth pass on both images at 224 and 256 MiB. See the follow-up plan for v50 measurements and failure diagnosis. |

The main tree pins Wasmtime v50 `b5581cade5626f050e6f9002f522b76187b6cf56`
and Javy `e307323d448470f9925f5a05e8ae4e160074c059` in
`src/build-scripts/external-sources.sh`, with checkouts under `external-sources/`.
Both revisions were verified on GitHub before the dependent main-tree commits.
The normal producer passes without a local-source override; evidence is in
`build/wasm-v50/producer-published.log`. No implementation or delivery step
remains in this plan.

Completed HTTP regression work is retained: commits `c8a8dce3`, `50dfb4a7`,
`cba80ac4`, `7154e47b`, `17784888` and `b674858e` cover serving, lifecycle,
deadlines, p3 resources, independent grants and sys-init service masks. The
existing normal runtime suite passed 127 commands per VM. Host-local evidence
is under `build/wasm-m3-{lifecycle,deadline,p3,grants,service}/`.

The old full-CLI candidate passed 18 focused commands on both images at 224
and 256 MiB; evidence is under `build/wasm-m4-cli/`. Those runs established
native compilation and Pulley execution, not direct native execution. The
original CLI-help failure and sandbox KVM preparation failure are retained
there with their diagnoses. They are not prerequisites to repeat this work.

The earlier fragmented-request reset still lacks its original reproducing
binary/log; later passing runs do not diagnose it. It does not block this
work under the owner's existing direction. A historical native invalid-opcode
report was not reproduced in the maintained Pulley runtime. The current native
path passes unreachable and bounds-trap checks on both images at both sizes.

## Target behavior

Ship `/devtools/bin/javy`, `/devtools/bin/wasmi`, `/devtools/bin/wasmtime` and
`/devtools/bin/wasmtime-rt` in both the developer and small wasm images.

| Operation | Required behavior |
| --- | --- |
| `wasmtime run program.wasm` | Compile to native Motor code and execute in the same process, with no intermediate executable or required filesystem writes. |
| `wasmtime serve handler.wasm` | Compile the component to native code and serve it in the same process using the shared WASI HTTP host. |
| `wasmtime compile program.wasm -o program.cwasm` | Emit native code for the host target by default, in Wasmtime's normal serialized artifact format. |
| `wasmtime run --allow-precompiled program.cwasm` | Load and execute a compatible native artifact directly. |
| `wasmtime-rt run` / `serve` with `--allow-precompiled` | Load compatible native artifacts through the same host and code-memory adapter, without linking Cranelift into the runtime-only binary. |
| Explicit `--target pulley64` | Keep upstream Pulley support as an explicit option. It is not the Motor default. |
| WASI p3 | Use upstream's feature-dependent default and explicit enable/disable options; no Motor-only default rejection. |
| Resource limits | Use upstream defaults and command-line overrides; no additional limits selected solely because this is Motor OS or a small VM. |

There is no Motor `package` command, runtime ELF template, populated executable
format, fixed native-code envelope or required compile/package/execute sequence
in the target design. `compile` remains optional before `run`/`serve`, as
upstream. Compilation and execution are not forced into separate invocations,
and execution does not require a launcher, worker or relaunch mechanism.

Preserve Wasmtime's existing serialized-artifact format and version,
configuration and CPU compatibility checks. Compiler and runtime artifacts
must come from matching builds; a Linux artifact is not automatically a Motor
artifact. Do not add a separate publisher/template version protocol.

The objective includes the native CLI workflow, Wasm behavior and defaults.
Native filesystem, networking, process authority and clocks still use Motor
APIs. Retain a behavioral difference only where a concrete native API or OS
permission constraint requires it, and document that constraint. Previously
chosen Motor-only policies are not exceptions merely because they already exist.

## Milestone 4: native execution and delivery

### 4a — executable-memory support

Completed in `9b97640d`. Ordinary processes may create executable mappings in
their own address space. Other-process mapping permissions, the rejection of
sharing an existing mapping into self, and the prohibition of a writable and
executable mapping remain intact.

The existing `SysMem::map2(SELF, F_SHARE_SELF | F_READABLE | F_EXECUTABLE, ...)`
returns separate RX and RW aliases of fresh frames. The runtime owns both,
copies the code through RW, then unmaps RW before exposing RX for execution.
`SysMem::free` synchronously revokes the unmapped alias across CPUs. RX stays
owned until all users of the code have finished. The OS does not automatically
remove aliases or provide an in-place protection-change API.

Only the kernel and systest changed. The in-VM tests cover execution, rejection
of writes through RX, rejection of execution through RW, and access after
unmapping. By the owner's explicit instruction, validation was one debug and
one release `src/tests/full-test.sh`, both passing. Evidence is retained under
`build/self-executable-mappings/`. The small test-harness expectation fix was
committed separately as `5e7201ff` before this work resumed.

### 4b — Wasmtime code-memory adapter and native defaults

Implemented initially in `21c1436ca8` and `3fb032396e`, then carried forward
into the published and qualified v50 fork. The retained platform differences are:

- `CodeMemory` copies position-independent machine code into an owned RX
  mapping, unmaps its RW alias, and retains the serialized image for metadata
  and serialization. Both fresh compilation and deserialization use this path.
  Motor has no in-place protection changes; code editing through `unpublish`
  therefore returns an error. The delivered CLI feature set does not enable
  that debugger path.
- Native target defaults and `Config::motor_runtime` keep explicit traps,
  no CoW/guard-based memory assumptions, and coalesced data initialization
  without large sparse images. Explicit Pulley uses the same backing settings.
  The native target and CPU detection are otherwise upstream defaults; the
  separate Motor artifact-version marker has been removed.
- `MemoryCreator` uses stable lazy reservations. Memory32 is bounded by its
  4 GiB address range; memory64 uses the kernel's 1 TiB per-allocation limit,
  with no smaller Motor policy cap. There is no resize/remap API, so these
  reservations do not move. User-requested `-W` limits remain effective.
- `StackCreator` provides lazy guarded stacks of the requested sizes. Its two
  cached stacks are a reuse optimization, not a stack/concurrency limit.
  HTTP request/connection limits and deadlines remain upstream's defaults.

Implement the platform adapter in the separate repository
`external-sources/wasmtime/`, using the new native API. Wasmtime already exposes
code-memory publication hooks; connect allocation, publication, lifetime and
release to them, or to its platform memory interface where necessary. Make the
same adapter available to full and runtime-only builds.

Change `crates/cli-flags/src/lib.rs` so an omitted target selects the native
host target instead of forcing `pulley64`. Retain explicit Pulley selection.
Verify that both freshly compiled code and deserialized native code use the
adapter. The runtime-only build must continue to reject raw Wasm because it
contains no compiler.

In `src/common.rs`, restore upstream's feature-dependent `P3_DEFAULT` and remove
the Motor-only fallback limits in `RunCommon::store_limits`: 32,768 table
elements, 64 instances and 16 tables. Use the upstream builder defaults and
preserve explicit `-W` overrides. Keep p3's upstream experimental status; it
does not justify a different default on Motor.

Audit remaining Motor-only runtime and compiler settings against the equivalent
Linux build, including memory reservation/growth, stack policy and concurrency.
Remove policy-only differences and retain native backing/lifetime protections.
Document any remaining difference with its actual platform constraint and the
upstream mechanism used to accommodate it. Small-VM resource targets are
measurements to satisfy, not a reason to silently impose additional defaults.

Update the existing command/HTTP p3 assertions to check the upstream default
and explicit `-S p3=n` rejection. Test requested limits with explicit options,
and default behavior without the old Motor caps, using the existing fixtures.
Update `docs/wasm.md` with the delivered behavior when the new fork is pinned;
its description of the currently installed runtime remains valid until then.

Keep native compilation on Cranelift with normal optimization and register
allocation. Do not add Motor-only compiler input/output quotas, alternative
compiler algorithms or a new compilation protocol. Keep implemented memory
initialization adaptations needed by the current native backing, with ordinary
Wasmtime configuration/compatibility checks; the old expanded compiler-policy
qualification project is not a delivery step.

Motor currently selects `signals_based_traps(false)`. This supported upstream
mode uses explicit checks and trap paths and can execute native code without
Unix signal handlers. Keep it while introducing executable memory. Matching
Linux's fault-based optimizations is a separate performance matter, not a
prerequisite for the native CLI workflow. Preserve lazy linear memories and
guarded host fibers in both CLIs.

Replace and remove the old template path as part of this adapter change:
`src/motor.rs`'s embedded-artifact loader, `src/motor_elf.rs`, the prototype
`package` helper, template linker layout and publisher-only tests/build wiring.
Preserve the shared host policy in `src/motor_host.rs` and the useful command,
HTTP, memory and stack adapters. Remove obsolete prototype compiler helpers
where the normal CLI now provides their functionality.

Output: native `run`, `serve`, `compile` and serialized-artifact loading through
the shared host, with Pulley available explicitly and no ELF packaging path.

### 4c — reproducible image integration

Completed in `5ea18cfd` and `8e86a569`. The normal
`src/build-motor-os.sh --javy-only --wasmtime-only` pipeline passes using the
published GitHub pins, and `test-wasm.sh --prepare` builds both release images.
The integration requires and checksums both Wasmtime binaries and uses the
normal host CLI to compile native test artifacts. The matching Javy v50 update
and qualification are recorded in the follow-up plan.

The Cranelift-capable CLI and runtime-only CLI use separate Cargo output
directories. Both binaries are staged with provenance and checksums and required
by both image manifests.

Use the current build layout:

- External repositories are under `./external-sources/`.
- `rust-toolchain.toml` selects the Motor toolchain. Derive its native sysroot
  from `rustc --print sysroot`, under `lib/rustlib/x86_64-unknown-motor/sysroot`.
- Incremental build outputs, image overlays and test inputs live in
  `build/assembly/{build,images,tests}`. Smoke binaries live in `build/obj`.
- The full and runtime-only graphs stay separate so compiler features cannot
  leak into `wasmtime-rt`. The runtime-only binary is not an ELF template.
- Tests upload inputs from the assembly; they do not download from the Internet.

The old pending image integration was rolled back because it would deliver the
Pulley-first default. Reuse the existing external-source and image machinery
when the native behavior is ready. Do not restore tests or documentation that
assume an omitted target means Pulley or require an ELF packaging step.

Keep the forks' locked, published dependencies and the owner-push workflow.
Do not wire unpublished fork revisions or manually prepared build contents into
a main-tree commit. Existing Motor crates come from the published dependencies
selected by the forks' lockfiles, not path dependencies into the main tree.

Output: all four tools installed by the normal release build in both images,
with documentation matching their actual native behavior.

### 4d — focused native validation and resource check

Completed for v50; see the [fork audit](wasmtime-fork-audit.md#implementation-and-qualification)
for its installed matrix, Javy identity and service results, measurements and
failure diagnoses. The v48 results below record the retained fallback.

Qualified v48 baseline: `src/tests/test-wasm.sh --suite wasmtime --release`, 143 commands each
on `wasm:224`, `wasm:256`, `dev:224` and `dev:256`, with zero memory-admission
refusals. The existing `--services --suite wasmtime --vm wasm:224 --vm dev:256`
gate also passed for native p2/p3 services started by sys-init as role None
with capability mask 256. The final suite includes an out-of-bounds load from
the existing memory fixture in addition to `unreachable`, timeout and the
fork's existing engine regressions. No new guest fixture was introduced.

Sampled whole-VM peaks in MiB (not process RSS; sampling can miss short peaks):

| VM | Native `compile` of lifecycle WAT | TypeScript raw compile + run | TypeScript precompiled runtime |
| --- | ---: | ---: | ---: |
| wasm:224 | 45.7 | 165.0 | 78.6 |
| wasm:256 | 55.8 | 174.0 | 88.2 |
| dev:224 | 45.5 | 164.3 | 78.6 |
| dev:256 | 56.0 | 175.6 | 89.4 |

The full CLI is 24,090,792 bytes and the runtime-only CLI is 13,868,816 bytes.
Both fit the existing wasm image's 1 GiB data partition; the built qcow2 uses
87.1 MiB on the host. Evidence, build logs and per-VM measurements are under
`build/wasm-m4-native/`, especially `installed-evidence/`, `installed-matrix.log`
and `services.log`. Lockfile validation, shell syntax, formatter and existing
test-selection checks passed. No new main-tree compiler warnings were emitted;
the fork retains its existing warnings. Ordinary Wasmtime work did not repeat
the already completed kernel gates or the unrelated developer-source suite.

Reuse `src/tests/wasmtime-smoke`, `wasm-smoke-suite` and `test-wasm.sh` with the
existing hello, TypeScript and HTTP programs. Validate the behavior changed by
4a–4c rather than introducing another guest fixture or test framework:

- Raw `run`/`serve` execute native code, and default `compile` produces a native
  artifact that both CLIs load directly. Explicit Pulley selection still works.
- Code publication, use and release preserve lifetime and protection rules;
  guest traps and interruption are reported correctly, including `unreachable`
  and out-of-bounds accesses, without an unhandled CPU exception.
- Existing process masks, WASI grants, CLI help/version and artifact
  compatibility refusals retain their meaning on the native path.
- P3 enablement, default resource limits and explicit overrides match the
  equivalent Linux build, using the existing command and HTTP fixtures.
- The tools and their normal inputs/outputs fit the 1 GiB wasm image and the
  existing 224/256 MiB VM requirements. Record native compiler and execution
  memory separately, using the existing harness measurements.

Keep the existing regressions connected to their established gates. Wasm-only
changes use focused component checks; the release developer gate continues to
run the installed suites on `wasm:224` and `dev:256`. Use both supported image
sizes for the initial native delivery. The kernel gate belongs to 4a and is
not repeated for documentation or ordinary Wasmtime-only changes.

The previously skipped extra HTTP/TLS and compiler qualification work is removed
from this plan, not deferred to another milestone. The separate TypeScript HTTP
fixture proposal is deleted. Completed regressions and their failure evidence
remain; no new test is ignored or weakened to make a failure pass.

Output: direct native execution qualified on the installed tools, with measured
resource use and no mandatory packaging or expanded qualification backlog.

## Retained integration contracts

Javy still uses Wasmi for plugins and Wizer, preserving upstream static/dynamic
outputs, deterministic initialization, source embedding and optimization. Its
Linux/Motor byte-identity contract and existing runner regressions remain.
The v50 dependency update preserves those completed Javy contracts.

Use the native filesystem/socket/clock/entropy adapters and the published
Tokio/Mio/Ring dependency graph. Keep the system CA bundle, lazy memory backing,
guarded stacks, upstream HTTP concurrency/deadline behavior and existing service
masks. No unrelated filesystem/networking or dependency migration is planned.

Both Wasmtime CLIs share the existing role-None guard and accept masks `0`,
`0x100`, `0x200` and `0x300`: filesystem output needs its normal write capability,
network access needs its normal network capability, and raw native execution
must not acquire I/O-manager authority. The new code-memory API's exact
permission policy is reviewed in 4a.

The owner confirmed that Linux parity includes p3 and resource defaults.
The earlier opt-in and finite-store-default decisions are superseded; their
implementation and assertion changes belong to 4b. Required native adapters,
permission checks and explicit-check trap handling remain platform adaptations,
with their constraints recorded rather than presented as Linux behavior.

## Working rules

Follow [AGENTS.md](../../AGENTS.md). Keep implementation patches small, format
with the repository-selected toolchain and introduce no new main-tree warnings.
Do not add core statics, boot-time work or changes to moto-rt/stdlib without the
required review. This plan does not replace those review requirements.

Commit messages are one line with no trailers. The owner pushes fork branches.
Keep engine regressions in their owning fork; new Javy/Wasmi runner integration
checks remain in the main tree. Non-Lorry developer-image checks are release-only.
