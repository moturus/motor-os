# Javy and Wasmtime infrastructure for Motor OS

Owner direction, 2026-10-27: use Wasmtime's native execution and compilation
workflow as on Linux. Add executable-memory support to Motor OS, then run
native code directly inside Wasmtime. The former Pulley-first delivery and
Motor-specific ELF packaging design are superseded.

This revision plans the OS change and rolls back the pending integration for
the old workflow. It does not implement a kernel API or change the currently
installed runtime's execution mode. Historical qualification details remain in
git history; `2cf4ecdc` contains the previous plan and evidence record.

## Status and resume point (2026-10-27)

| Area | Current state |
| --- | --- |
| Javy/Wasmi | Delivered in the developer and small wasm images. Static/dynamic compilation, TypeScript, plugins, byte identity, memory backing and runner regressions are maintained. |
| Runtime-only Wasmtime | Delivered for precompiled Pulley command/HTTP execution. Native loading currently depends on the old prototype ELF template; direct native loading remains to implement. |
| HTTP, sockets and filesystem | Native adapters and shared WASI hosts are delivered. Existing lifecycle, timeout, grant, service-mask and p3 regressions pass. System CA loading is delivered. |
| Full CLI foundation | Local Wasmtime commit `4eede7f3e23371317b2da19514b117ab17447381` shares authority checks, native network checks, lazy memories and guarded fibers between both CLIs, and enables CLI help and Wasm text parsing. Retain this work. |
| Full CLI image integration | The uncommitted Pulley-first build/image changes, pin bump, documentation and compiler-smoke additions have been rolled back. Deliver the full CLI after native execution works. |
| Native workflow | Next: review and implement executable-memory support, connect Wasmtime to it, select the native target by default, then deliver and validate the installed tools. |

The main tree remains pinned to Javy
`12a6c52d7dbd62056ead74d8ddea3f8a235f278f` and Wasmtime
`633e7de368b913a696e7e15d4f546c55fc2eadaf` in
`src/build-scripts/external-sources.sh`. The local Wasmtime foundation commit
is retained in `external-sources/wasmtime/`; it is not a published main-tree
prerequisite yet. The owner publishes fork commits before the main-tree pin
and dependent integration are committed.

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
report was not reproduced in the maintained Pulley runtime; native trap
handling must be checked when direct native execution is introduced.

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

There is no Motor `package` command, runtime ELF template, populated executable
format, fixed native-code envelope or required compile/package/execute sequence
in the target design. `compile` remains optional before `run`/`serve`, as
upstream. Compilation and execution are not forced into separate invocations,
and execution does not require a launcher, worker or relaunch mechanism.

Preserve Wasmtime's existing serialized-artifact format and version,
configuration and CPU compatibility checks. Compiler and runtime artifacts
must come from matching builds; a Linux artifact is not automatically a Motor
artifact. Do not add a separate publisher/template version protocol.

The objective is the native CLI workflow and Wasm behavior. Native filesystem,
networking, process authority and clocks still use Motor APIs. Executable-memory
support does not turn those APIs into Unix APIs. Keep documented native adapter
semantics and existing OS permission checks.

## Milestone 4: native execution and delivery

### 4a — executable-memory support

The current kernel rejects executable mappings into the calling process without
`CAP_IO_MANAGER` in `src/sys/kernel/src/uspace/sys_mem.rs`. Replace that
restriction with a reviewed facility suitable for ordinary language runtimes;
do not give Wasmtime the broad I/O-manager capability.

First review the exact native API and authority policy. It must support owned,
page-backed code allocations with stable virtual addresses, writing generated
or deserialized code, publishing it as read/execute, and releasing it after all
execution has ended. Publication must revoke write access, including writable
aliases, before executing the code. Cross-core permission changes and address
ownership checks belong in the OS contract, not in Wasmtime conventions.

Use standard Rust and native Motor APIs. Keep changes limited to the kernel
memory interface and the necessary native wrappers under `src/sys/lib`.
Identify the exact files and review the interface before implementation.
Any required moto-rt, rt.vdso or Rust stdlib change must be discussed and vetted
under AGENTS.md; do not add stdlib-specific Wasmtime logic. No new boot-time
initialization or service is needed.

Add focused in-VM kernel tests for successful code publication/execution,
permission and ownership rejection, and allocation/protection cleanup. Kernel
tests run inside Motor OS and are included in `src/tests/full-test.sh`.
Before committing core changes, the full main-image gate must pass three debug
and three release runs, as AGENTS.md requires. Diagnose failures rather than
adding retries, larger timeouts or ignored assertions.

Output: the reviewed executable-memory contract, native API implementation and
kernel validation. This step is the prerequisite for direct native execution.

### 4b — Wasmtime code-memory adapter and native defaults

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

After the fork changes are qualified and published, pin the exact revision in
`src/build-scripts/external-sources.sh`. Build the Cranelift-capable CLI and
runtime-only CLI in separate Cargo output directories and stage both binaries
with provenance and checksums. Both image manifests must require them.

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
This execution redesign does not reopen completed Javy work.

Use the native filesystem/socket/clock/entropy adapters and the published
Tokio/Mio/Ring dependency graph. Keep the system CA bundle, lazy memory backing,
guarded stacks, upstream HTTP concurrency/deadline behavior and existing service
masks. No unrelated filesystem/networking or dependency migration is planned.

Both Wasmtime CLIs share the existing role-None guard and accept masks `0`,
`0x100`, `0x200` and `0x300`: filesystem output needs its normal write capability,
network access needs its normal network capability, and raw native execution
must not acquire I/O-manager authority. The new code-memory API's exact
permission policy is reviewed in 4a.

Scope clarification requested from the owner: whether the previously explicit
p3 opt-in and finite store-limit defaults also change to upstream Linux defaults.
Those existing settings are not changed by this rollback. Resolve that question
before changing their behavior or associated assertions; it does not change the
executable-memory prerequisite or reinstate any packaging/fixture work.

## Working rules

Follow [AGENTS.md](../../AGENTS.md). Keep implementation patches small, format
with the repository-selected toolchain and introduce no new main-tree warnings.
Do not add core statics, boot-time work or changes to moto-rt/stdlib without the
required review. This plan does not replace those review requirements.

Commit messages are one line with no trailers. The owner pushes fork branches.
Keep engine regressions in their owning fork; new Javy/Wasmi runner integration
checks remain in the main tree. Non-Lorry developer-image checks are release-only.
