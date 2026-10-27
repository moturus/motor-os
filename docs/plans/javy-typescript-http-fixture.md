# TypeScript HTTP fixture: proposed component composition

Pending owner review, 2026-10-27. This resolves the open fixture design in
[milestone 3f](javy-wasmtime.md#milestone-3-httphttps-and-opt-in-p3).
No implementation of this proposal has started.

## Why a decision is needed

The pinned Javy exports core Wasm. Its WIT generator in
`external-sources/javy/crates/codegen/src/wit.rs` rejects imported interfaces,
exported interfaces, parameters and return values. It therefore cannot
directly export the WASI HTTP handler interface. Wasmtime's preview1 adapter
can turn its command into a component, but does not supply an HTTP handler.

The main plan requires a representative TypeScript HTTP workload in p2 and
p3, while excluding direct JS-to-p3 compilation and I/O-dependent p2 custom
plugin extensions. Connecting the command workload to HTTP requires a new
adapter design; merely returning precomputed TypeScript output would not
exercise the transpiler per request.

## Recommended approach

Compose a Javy command with small Rust components, all inside the same
Wasmtime component instance:

1. A bounded I/O component owns the request input, stdout and stderr buffers.
   It exports the preview2 stdin/stdout/stream interfaces needed by the
   preview1 command adapter, plus buffer setup/result functions for the HTTP
   wrapper. Instantiate it before either consumer to avoid cyclic imports.
2. The existing TypeScript transpiler, compiled with Javy, reads the requested
   TypeScript source from stdin and writes the actual transpilation result to
   stdout. Reuse the pinned plugin and preview1 command adapter without edits.
3. Separate p2 and opt-in p3 Rust HTTP wrappers buffer the incoming body,
   populate the I/O component, invoke the Javy command once, and return its
   output as the HTTP response. Use one request per component instance, also
   for p3, since this is a command entrypoint rather than a reusable service.

Proposed fixture bounds are 64 KiB input, 1 MiB output and 64 KiB stderr,
two concurrent requests and eight connections. These are fixture settings,
not runtime defaults. Qualify the memory cost at 224 MiB before expanding
the request matrix. Existing hello/echo tests retain streaming coverage;
this adapter deliberately buffers a bounded transpilation request.

The initial patch would prove composition with a tiny stdin/stdout JavaScript
program. Only after that works should the 9 MB TypeScript workload be added.
Verify exact results from distinct requests, over-limit rejection, p2/p3
shutdown and measured memory under both VMMs on both images at 224/256 MiB.

Proposed tree locations are `src/tests/wasm-http-typescript/` for guest
components and a pinned Rust composition helper,
`src/build-scripts/build-wasmtime.sh` for fixture construction, and the
existing `wasmtime-smoke` HTTP modules for execution. External source inputs
remain under `external-sources/`. The composed artifact runs through installed
`wasmtime-rt serve`; compilation remains build-time work.

## Alternative

Explicitly defer TypeScript-over-HTTP, retain TypeScript command and p2/p3
hello/echo qualification, and continue with the remaining hermetic TLS work.
That leaves milestone 3f incomplete rather than treating the current command
test as equivalent HTTP coverage.
