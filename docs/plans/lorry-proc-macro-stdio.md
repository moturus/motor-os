# Native Motor procedural macros over stdio

Designed and authorized 2026-08-16. Implementation may proceed without a
separate review pause. This plan changes the Motor Rust fork and Lorry; it does
not add dynamic-library support to Motor OS.

## Problem

Rust procedural macros are compiler-host programs. On Linux rustc builds each
macro as a host dynamic library, loads its registration table, and calls it
through the `proc_macro` bridge. A Linux compiler targeting Motor therefore
works, but a compiler running natively on Motor cannot produce or load the
dynamic library because the Motor target deliberately has
`dynamic_linking = false`.

The Rust language does not specify a proc-macro artifact format. It requires
only compile-time execution of the macro and the `proc_macro` token/span API.
The original procedural-macro RFC explicitly left an independent executable
and IPC as an alternative implementation.

## Decision

For a compiler whose host is Motor, `--crate-type proc-macro` produces a
statically linked executable instead of a dynamic library. The executable
contains the ordinary generated proc-macro registration table plus a compiler-
generated `main`. It remains a proc-macro crate semantically and retains rustc
metadata in its ELF image.

The consuming rustc reads that metadata as it does today, but creates external
proc-macro clients instead of calling `dlopen`. The client starts the artifact
and exchanges versioned, bounded binary frames using the child's stdin and
stdout. This is IPC in the general operating-system sense, but its transport is
only standard process I/O: no sockets, shared memory, named service, or dynamic
loader is required.

Linux and every non-Motor host keep the existing dynamic-library path exactly.
Linux-to-Motor builds also keep that path because the compiler host is Linux.

## Artifact and compiler changes

The Motor Rust fork will make four narrowly scoped changes:

1. Permit `proc-macro` output for the Motor host despite the target's lack of
   dynamic linking, and link that output using the target's ordinary static PIE
   executable mode.
2. Extend the proc-macro harness with an internal `#[rustc_main]` entry point on
   Motor. It calls a hidden `proc_macro` client runner with the generated macro
   registration slice.
3. Represent a loaded proc-macro client as either the existing in-process
   function or a Motor executable path plus registration-table index.
4. In rustc metadata loading, construct executable clients on Motor and retain
   `dlopen` clients elsewhere.

The executable may retain the conventional proc-macro filename selected by
rustc even though it is an executable ELF file. Its format is internal to the
exact rustc toolchain and is included in Lorry's existing rustc/cache identity.

## Stdio protocol

The protocol is private to one rustc build and its matching `proc_macro`
library. It is not stable and does not need cross-version compatibility.

Each frame contains:

- a fixed magic and protocol version;
- a one-byte message kind;
- a little-endian 64-bit payload length; and
- a payload bounded to 256 MiB.

Parent-to-child messages are `invoke(index, bridge-input)` and
`dispatch-response(buffer)`. Child-to-parent messages are
`dispatch-request(buffer)` and `result(buffer)`. The buffers are the existing
proc-macro bridge serialization; this avoids introducing a second token/span
format.

The child inherits rustc's working directory, environment, and stderr. Stdout
also retains its observable proc-macro behavior: the parent scans for framed
messages and forwards bytes outside frames to its own stdout. The runner holds
Rust's stdout lock while emitting each frame, preventing ordinary `print!`
output from interleaving with a frame. Deliberate raw descriptor writes can
still corrupt the protocol; procedural macros already execute trusted
arbitrary code with compiler access, so this transport is not a security
boundary.

Malformed frames, oversized payloads, premature EOF, spawn failure, or abnormal
child exit become ordinary human-readable proc-macro diagnostics. They must not
be compiler panics or missing-artifact errors.

## Lifetime and re-entrancy

Rustc keeps one child per proc-macro artifact and serializes invocations for
that child. This preserves process globals across normal invocations and avoids
one process launch per derive.

The existing `TokenStream::expand_expr` API can cause a nested proc-macro
expansion while the first child is waiting for a bridge response. Re-entering
that same stdio conversation would deadlock. Rustc therefore tracks the active
artifact on the current compiler thread and uses a temporary child for a nested
invocation of the same artifact. Different artifacts use their independent
children. EOF shuts a child down; no explicit daemon or persistent OS service
is introduced.

## Lorry changes

Lorry's unit graph, host/target feature separation, capability admission, and
cache model do not change. Only native-Motor artifact naming/verification and
the temporary unsupported-feature rejection change. Once the matching compiler
is present, Lorry treats the proc-macro executable as the host artifact passed
through `--extern`.

The existing explicit `allow-proc-macro = true` policy remains mandatory.
Stdio process separation is not yet a sandbox: the executable inherits rustc's
authority. Documentation must not claim isolation.

## Validation

Implementation is complete only when all of these pass:

1. Linux Lorry tests cover derive, attribute, and function-like macros, macro
   helper dependencies, host/target feature separation, clean/rebuild cache
   reuse, and Linux-to-Motor compilation.
2. A direct Motor rustc smoke builds and consumes a local proc-macro executable.
3. Native Lorry in the dev-image VM builds and runs the same fixture, including
   ordinary macro stdout and a separate expected macro-panic diagnostic.
4. Transport failures produce an error naming the proc-macro executable and
   failure, without an internal compiler error or Lorry panic.
5. The focused Rust compiler checks and complete Lorry suite pass. Because the
   generated native compiler/image changes, the repository debug and release
   gates apply before the final Motor OS commit.

## Non-goals

- General Motor dynamic-library loading.
- A stable public proc-macro wire protocol.
- Proc-macro sandboxing or permission reduction.
- A generic remote proc-macro service.
- Changing Linux proc-macro artifacts or Cargo behavior.
- Supporting a compiler and proc-macro artifact built from different Rust
  revisions.
