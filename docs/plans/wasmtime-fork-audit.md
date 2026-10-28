# Wasmtime fork audit and proposed v50 port

2026-10-27. Status: audit complete; implementation proposal awaiting review.
This supplements [javy-wasmtime.md](javy-wasmtime.md), whose Linux-parity target
and retained integration contracts still apply.

## Recommendation

Start a `motor-50.0.0` branch from upstream v50.0.0 and port the necessary
adapters as small patches. Preserve `motor-48.0.1` as the qualified fallback
and Javy's dependency. Do not replay the whole Motor commit series: it contains
superseded ELF packaging, resource limits, dependency paths and test utilities.

Executable mappings remove the reason for the old native ELF template and
Pulley-first workflow. They do not replace the filesystem, socket, memory,
stack, TLS-slot or entropy adapters. The current local fork already removes
the execution workarounds; further simplification is mostly build structure,
obsolete utilities and adapting to upstream's newer filesystem interface.

## Scope and evidence

Reviewed the 44 commits after upstream v48.0.1 and the resulting changes in all
92 files, including tests, scripts, documentation and dependency lockfiles.
The comparison is the final delta, with historical commits used to identify
why changes were introduced.

| Revision | Meaning |
| --- | --- |
| `7bac2c2775808aaec5d4aa5627a5e447b51102cf` | Upstream v48.0.1, original fork base. |
| `633e7de368b913a696e7e15d4f546c55fc2eadaf` | Published fork tip and committed main-tree pin at the start of this audit. Still has the old execution design. |
| `3fb032396ea3898de562786e9a4060783e83e286` | Local fork tip; three commits ahead of the published branch. Native execution and packaging removal are here. |
| `ebe5e8df1f4e12c5fc2f5954926881d8d61367d8` | Upstream v50.0.0, fetched and inspected without changing the active branch. |
| Motor OS `9b97640d` | Kernel support for self-executable mappings. |

The v48 delta is 9,307 insertions and 154 deletions. Four lockfiles account for
5,894 insertions and 16 deletions; the remaining 88 files contain 3,413
insertions and 138 deletions. The size is not evidence of thousands of lines
of JIT workarounds.

Existing native v48 qualification is recorded in the parent plan. This audit
did not build or run v50. It inspected upstream source and compared the two
v48 runtime dependency graphs with offline, locked `cargo tree` commands.
No implementation source was changed during the audit.

## What executable mappings make obsolete

These changes are already present locally in `21c1436ca8` and `3fb032396e`,
but are not yet published through the main-tree pin:

- Native code now uses owned executable mappings, without an ELF template,
  native `package` utility, custom linker layout or separate packaged loader.
- Default compilation/execution selects the native host. Pulley is explicit.
- Normal Wasmtime artifact versioning replaces the `48.0.1-motor.1` marker.
- Upstream p3 and store defaults replace Motor-only policy limits; memory64
  is no longer arbitrarily capped at the Wasm32 limit of 4 GiB.

The latter policy changes follow the owner's Linux-parity direction; they were
not technically required by the executable-mapping restriction. Earlier fixed
memory totals and bounded stack arenas were already replaced by lazy mappings
before these three local commits. None belongs in the v50 port.

The kernel API creates separate RX and RW aliases. The runtime copies code
through RW, unmaps it, and retains RX until the module is dropped. Upstream's
`CustomCodeMemory::publish_executable(ptr, len)` still returns `Result<()>` in
v50: it expects permissions to change at the supplied address. It cannot
return Motor's different executable address. Keep the small `CodeMemory`
adapter unless a separate future OS/API design supplies that contract.

Likewise, upstream's `custom-virtual-memory` interface includes in-place
protection changes and mapping operations beyond this kernel addition. Merely
enabling that feature would not implement them. The executable-mapping change
also does not supply recoverable fault traps or private file-backed CoW.

## Disposition of the current patches

Paths below are relative to `external-sources/wasmtime/`. Groups cover the
entire final delta; some files participate in more than one behavior.

| Area and affected files | Disposition and reason |
| --- | --- |
| `crates/wasmtime/src/runtime/code_memory.rs`, `code_memory/motor.rs`, `crates/wasmtime/Cargo.toml` | **Keep.** Own native RX mappings and release the writable alias before execution. Required with the new kernel API, rather than a leftover restriction. v50 retains the same in-place custom-code hook. |
| `crates/wasmtime/src/runtime/vm.rs`, `vm/mmap_vec.rs` | **Keep the file-read fallback.** v50 still assumes an mmap-backed file loader despite its allocator-backed configuration. Reading a serialized image into owned storage remains necessary. Drop incidental import reordering. |
| `crates/environ/src/tunables.rs`, `crates/wasmtime/src/config.rs`, `crates/cli-flags/src/lib.rs` | **Keep required target defaults; reduce duplication where practical.** Motor requires explicit bounds/trap checks, no CoW and memory settings compatible with its custom allocator. Native cross-compilation must resolve these from the final target; Motor's explicit Pulley path needs equivalent settings. Do not reinstate a forced target or private artifact version. |
| `crates/environ/src/compile/module_environ.rs`, `crates/wasmtime/src/compile.rs`, `compile/code_builder.rs`, `engine/serialization.rs`, associated tunable/config additions | **Keep static data coalescing independently of CoW.** v50 still calls `try_static_init` only when CoW is enabled. Dense-segment regressions demonstrate much smaller initializer code; sparse images must remain bounded. Keep cache-key separation and avoid changing serialized compatibility for a compilation-only strategy. Executable mappings do not solve this. |
| `src/motor_memory.rs` | **Keep lazy reservations.** Replacing them with allocator-backed memory would commit/copy much more memory during growth. The 1 TiB ceiling comes from Motor's per-mapping limit. The configurable private ceiling is used only by a manual test; simplify that interface if the test is retired. |
| `src/motor_stack.rs` | **Keep guarded, lazy fiber stacks.** Executable mappings do not provide upstream's stack allocation/protection interface. The two-stack cache is an existing reuse optimization, not a limit on live stacks; do not remove it without evidence about allocation costs. |
| `src/lib.rs` TLS exports, corresponding exports in test binaries | **Keep required TLS slots.** Upstream's custom-platform runtime still asks the embedder for these. Avoid duplicating them in utilities that are removed. |
| `src/motor_host.rs`, `src/bin/wasmtime.rs`, `src/commands/run.rs`, `src/common.rs` | **Keep explicit integration policy and OS wiring.** Role None, allowed capability masks, CAP_NET propagation, shared memory/stack creators and Motor trap exit behavior are independent of executable mapping. The authority guard is a retained security policy, not a generic Wasmtime requirement. |
| `src/commands/serve.rs` | **Keep terminal-error handling and shared host configuration.** A service without a foreground terminal must still support shutdown and draining. v50 changes graceful-shutdown internals but still unwraps the first Ctrl-C registration and treats the second registration's completion as a signal. Reapply the narrow Motor behavior to the new code; reevaluate feature-specific warning fixes. |
| `crates/wasi/src/motor_fs.rs`, `filesystem/motor.rs` | **Keep native operations; adapt their interface.** Native descriptors, serialized positioned I/O, path confinement, object identity and error translation do not depend on executable memory. v50 offers a better integration point described below. Remove compatibility-only wrappers when their upstream consumers disappear. |
| `crates/wasi/src/filesystem.rs`, `ctx.rs`, `p1.rs`, `p2/filesystem.rs`, `p2/host/filesystem.rs`, `p3/filesystem/{mod.rs,host.rs}` | **Port the platform-file type and native error handling.** Directory paths and native file descriptors cannot simply become Unix directory descriptors. v50 still lacks most of the added `ErrorKind` mappings. Replace the old `cap_primitives` aliases with its internal filesystem boundary. |
| `crates/wasi/src/motor_sockets.rs`, `motor_udp.rs` | **Keep.** They implement native options/errors and lazy UDP binding while reusing upstream WASI state machines. They are unrelated to JIT permissions. Native bind/listen ordering, bound TCP connect, UDP wildcard selection and socket option differences remain explicit platform constraints. |
| `crates/wasi/src/sockets/{mod.rs,tcp.rs,udp.rs}`, `p2/{network.rs,host/network.rs}`, `p3/sockets/conv.rs` | **Keep native socket integration.** Accepted TCP sockets need listener options reapplied; native errors need WASI classification. Port on top of v50's accepted-peer-address handling instead of replacing upstream fixes. |
| `crates/wasi/src/p2/tcp.rs` | **Remove the Motor-only 256 KiB write budget.** Its comment and introducing commit identify a test-buffer assumption as the reason. Upstream uses 64 KiB; a larger application queue is not needed by Motor's socket API. Adjust the existing shutdown/backpressure test as described below. |
| `crates/wasi/src/clocks.rs`, entropy registration in `lib.rs`, native dependencies in `Cargo.toml` | **Keep native clock resolution and entropy.** v50 does not supply the Motor backend. Do not carry the cap-primitives dependency relocation: upstream removed those dependencies. |
| `crates/wasi-http/src/default_send_request.rs` | **Keep as an explicit retained policy.** The Motor system CA bundle differs from upstream's compiled-in webpki roots, but the approved plan specifically retains it. This is neither necessary for executable mappings nor an obsolete workaround. |
| Root `Cargo.toml`, `Cargo.lock` | **Keep required dependency patches; regenerate the lock against v50.** Tokio, Mio, target-lexicon and Ring supply Motor support. Scope release profile overrides to Motor build invocations while retaining delivered binary settings. Do not port v48 lockfile edits mechanically. |
| `motor-build.sh`, `motor-runtime/Cargo.toml`, `motor-runtime/Cargo.lock` | **Replace the runtime wrapper with upstream CLI feature selection.** It compiles the very same `src/bin/wasmtime.rs`. Offline graph comparison proves the root package can supply identical runtime dependency features without Cranelift. Keep separate output directories and install the second binary as `wasmtime-rt`. |
| `crates/wizer/{Cargo.toml,src/lib.rs,src/parse.rs}` | **Retain for Javy on v48; omit from the new CLI-only v50 branch.** Javy still consumes runtime-independent Wizer using Wasmi. Its Cargo.lock pins `fda311d08cf93052a1af34f50f96271d1ad1b556` on `motor-48.0.1`. A CLI upgrade need not update that dependency or reopen Javy's byte-identity contract. |
| `motor-tests/src/bin/compile.rs` | **Remove.** This second custom compiler helper survived removal of the packaging workspace's compiler. The prepared main builder uses the normal host CLI; there is no maintained caller. |
| `motor-tests/{Cargo.toml,Cargo.lock,src/main.rs,fixtures/*}`, `motor-test.sh` | **Keep maintained engine regressions.** The main builder installs this binary as `engine-tests`; it checks initializer semantics, bounds traps, target defaults, cache separation and direct native loading. The seven fixtures still have callers. |
| `motor-runtime/fixtures/{lifecycle,limits-elements,limits-memories,limits-tables,memory-grow,memory-too-large,memory64-grow}.wat` | **Keep.** The installed suite uses these through normal CLI compilation. They do not require the runtime wrapper workspace. Old names referring to limits do not mean old default limits remain. |
| `motor-runtime/src/bin/{memory-check,stack-check}.rs`, `motor-runtime/fixtures/stack-yield.wat` | **Historical manual qualification, not runtime implementation.** Only the old port guide describes running these; the maintained gate does not invoke them. Do not recreate this separate manual qualification path on v50. Keep the existing installed memory/lifecycle coverage and preserve an indispensable assertion in the existing test path if needed by a changed adapter. |
| `motor-host-tests/{Cargo.toml,Cargo.lock,src/main.rs,src/filesystem.rs,src/interleavings.rs}` | **Historical manual qualification.** The source installer fetches its dependencies, but the maintained build/test gate does not run this binary. Do not port its separate workspace or lookup benchmark just for continuity. Preserve any necessary confinement/lifetime regression in the existing test path when adapting the filesystem. |
| `crates/test-programs/Cargo.toml`, `src/sockets.rs`, `src/bin/p2_tcp_{bind,bind_listen_order,connect,sockopts,states}.rs`, `src/bin/p2_udp_{bind,sample_application,send_to_closed_receiver,sockopts,states}.rs` | **Keep the applicable existing Motor assertions.** They describe actual networking behavior: wildcard binding, fixed keepalive, grow-only buffers, UDP close/delivery and unsupported options. A Wasmtime upgrade or executable mapping does not change these native operations. Preserve assertions rather than silently skipping failures. |
| `crates/wasi/tests/all/p2/{async_.rs,sync.rs}` | **Keep registration of the bind/listen ordering regression** with its corresponding guest program. |
| `MOTOR.md` | **Rewrite for the delivered design.** It still describes ELF templates, the removed package utility, a 4 GiB memory64 limit, finite store defaults and an obsolete main-tree build-script path. |

## Concrete simplifications

### Build the runtime from the upstream package

The following offline, locked v48 dependency query has exactly the wrapper's
normal/build package-and-feature set after removing the wrapper package itself:

```sh
cargo tree --offline --locked --target x86_64-unknown-motor \
  --no-default-features \
  --features run,serve,pulley,component-model-async,gc,gc-drc,disable-logging,clap/default \
  --edges normal,build --prefix none --format '{p} {f}'
```

Neither graph contains `cranelift-codegen`. This supports deleting the
41-line wrapper manifest and its 2,873-line lockfile. It is dependency evidence,
not a substitute for building the resulting v50 binaries. Retain the two
installed commands and their intended compiler/runtime feature difference.

### Restore the upstream TCP write budget

`p2_tcp_streams::test_tcp_shutdown_should_not_lose_data` requests a 1 KiB
native send buffer and assumes a single permitted WASI write is larger than
that buffer. Motor's rings retain at least their 128 KiB default, while
upstream's WASI write permit is 64 KiB. The fork increases every Motor write
permit to 256 KiB to make that assumption true.

Keep the upstream 64 KiB production budget. Adapt this existing test to fill
the connection with a bounded sequence of permitted writes, sized from actual
socket capacities, until a write is pending. Then perform shutdown and verify
all submitted data arrives. Do not weaken the delivery
assertion, add sleeps/retries, or change native socket behavior. This is one
targeted correction to remove a production fork, not new qualification scope.

### Integrate with v50's filesystem boundary

Upstream v50 vendors, trims and then removes its cap-primitives dependencies
(`eb5a7cfa36`, `652f9cb63f`). Its common callers now use
`filesystem::primitives`, standard `SystemTime` and fewer compatibility types.
Select a Motor implementation at that boundary and reuse the existing native
operations. Remove aliases pretending `motor_fs` is `cap_primitives`, the
`ambient_authority` placeholder and obsolete time/options wrappers.

The upstream primitive implementation still assumes Unix or Windows and uses
directory-relative native handles. Its existence does not make Motor's path
adapter redundant. Preserve confinement and document the existing semantics:
directory handles name paths and do not follow renames, while open files retain
their native object. Do not broaden this migration into new filesystem APIs.

## Why v50, and what it costs

[v50.0.0](https://github.com/bytecodealliance/wasmtime/releases/tag/v50.0.0)
was released on 2026-10-20 and requires Rust 1.97.0; the selected Motor 1.99.1
toolchain meets that requirement. It releases cached compiler contexts between
compilations, improves async fairness, and includes HTTP and shutdown fixes.
Those are useful for Motor's small VMs. The filesystem restructuring is a
separate concrete opportunity to reduce port scaffolding.

This is a source port, not a Cargo version substitution:

- Reconcile the filesystem primitive boundary and p3 host changes.
- Adapt `serve` to upstream's revised shutdown logic and callback types.
- Rebuild p3 guests against the matching async/component definitions. v50
  changes cancellation semantics and `Accessor::spawn`; retain upstream
  behavior and defaults, including WASIp0 becoming explicit opt-in.
- Rebuild all precompiled artifacts using the same new fork revision. Keep
  ordinary Wasmtime version checks rather than accepting v48 artifacts.
- Existing Tokio 1.51.1 and target-lexicon 0.13.5 fork versions match v50's
  declared requirements. Re-resolve the graph and verify it; this audit does
  not establish that every transitive dependency builds on Motor unchanged.
- Wizer is still coupled to Wasmtime in upstream v50. Leaving Javy's existing
  v48 dependency untouched avoids making this CLI migration a Javy port.

## Proposed implementation sequence

1. Create `motor-50.0.0` from the inspected upstream tag in the Wasmtime fork
   under `external-sources/wasmtime/`, retaining the current v48 branch. Port
   required dependency wiring, allocator file loading, target/initializer
   policy and owned executable mappings in reviewable patches.
2. Port native filesystem/socket/clock/entropy adapters and shared CLI host
   integration. Adapt filesystem wiring to v50; preserve the system CA policy,
   capabilities, lazy memories and guarded stacks. Keep upstream p3 defaults.
3. Build both CLIs from the root package with separate feature selections and
   output directories. Remove obsolete helpers/manual workspaces, retain
   fixtures used by installed tests, restore the upstream TCP write budget,
   and rewrite `MOTOR.md`. Keep meaningful existing engine regressions.
4. Update the main-tree Wasmtime source revision, producer, artifact staging
   and existing tests/docs. The current uncommitted v48 integration is useful
   input but is not a completed v50 integration. In particular,
   `test-external-sources.sh` still asserts the former runtime-only build and
   custom compiler command; `test-wasmtime-fetch.sh` models the old wrapper.
   Update those existing checks together with the producer instead of adding
   replacement test infrastructure.
5. Format with the selected toolchain and run the existing affected build and
   component gates. Compare Linux and Motor at v50 with equivalent features
   and options. Use the maintained native run/compile/serve, p3, filesystem,
   socket, TypeScript and authority checks; do not revive skipped test work.
   Qualify the new binaries at the existing 224/256 MiB image sizes and retain
   failure evidence. No kernel/core changes are proposed, so the core OS
   repeated debug/release gate is not part of this port. Developer-image runs
   remain release-only.
6. Commit incremental fork patches with one-line messages. The owner publishes
   the fork before the dependent main-tree pin/integration is committed. Do
   not rewrite Javy's pinned v48 history or publish anything upstream.

Implementation changes would be in the external Wasmtime fork and the
wasm-related main-tree build/test/docs files. No changes to moto-sys, moto-rt,
stdlib, kernel, unrelated external forks or boot-time work are proposed.
If the port reveals a requirement outside that boundary, diagnose it and
bring the concrete decision back for review.

Approval requested: use this reduced patch set for v50.0.0, retaining v48 for
Javy and as the fallback. The planning review is required by
[AGENTS.md](../../AGENTS.md): “On larger tasks, first create a plan in an *.md
file in docs/plans/, ask for review, then proceed in incremental steps. Do not
change any code during the planning step.”
