# Native Rust unwinding required by rust-analyzer

## Evidence and authorization

The 2026-09-10 Helix failure is an ordinary Salsa cancellation compiled for
Motor's abort-only Rust runtime. A diagnostic kernel captures this call chain:
`ZalsaLocal::unwind_pending_write` -> `Cancelled::throw` -> `resume_unwind` ->
`__rust_start_panic` -> `__rust_abort` -> `abort_internal` -> `exit(-1)`.
Evidence is `/tmp/motor-helix-user-abort-symbolized.log`. It reproduces on a
fresh image, on the console and SSH, with 8 GiB RAM. The earlier editor test
did not exercise cancellation and was insufficient to claim a usable server.

The existing Motor target defaults to `panic=abort`; its `panic_unwind` selects
the dummy abort implementation, and std has no Motor exception personality.
Even a nine-line `catch_unwind(resume_unwind(...))` program fails to compile
with `-C panic=unwind` against the selected sysroot. Changing an editor option
or extending a timeout cannot provide the missing language-runtime support.

The original user request explicitly says to record stop conditions and
continue. The normal stdlib review stop and larger-task plan review are
recorded here. Start with an isolated prototype before production changes.
Do not alter the managed Rust checkout, installed toolchain, or selected
assembly. Temporary kernel exit-stack instrumentation must be removed.

## Proposed implementation and gates

1. Copy the selected Rust library sources into `build/helix-unwind/` and
   prototype Motor support in `library/unwind`, `library/panic_unwind`, and
   std's existing exception-personality selection. These are toolchain-source
   changes in an isolated local copy, not editor changes.
2. Evaluate the pure-Rust `unwinding` crate already present in the selected
   library lockfile. Use static executable unwind metadata; Motor binaries
   are static PIE. Preserve the default abort strategy and enable unwinding
   only for applications requesting it. Add no libc dependency or boot work.
3. First prove `catch_unwind`, cancellation payload preservation, destructor
   execution, thread isolation, and ordinary abort behavior with small native
   programs. Reject any design that skips destructors or merely suppresses
   Salsa cancellation.
4. Integrate the proven implementation through the repository's toolchain
   identity/build workflow, then build rust-analyzer with real unwinding.
   Add a deterministic native cancellation gate before semantic acceptance,
   and editor coverage for opening files after starting `hx` and for edits
   while background analysis is active.
5. Run appropriate compiler/runtime, main-image, and release developer-image
   gates, then commit small patches and deliver a freshly rebuilt image.
   Preserve the reported image and investigation logs. Do not count the old
   passing editor sequence as proof that this defect is resolved.

## Selected scope after the native prototype

The pure-Rust implementation passed 128 cancellations on four native threads,
including nested cleanup and payload recovery. A server built with it survived
the previously fatal initial workspace analysis and resolved `ANSWER` in Helix.

Keep this opt-in implementation private to the native rust-analyzer build.
`src/patches/rust-analyzer-unwind.patch` changes four files in a temporary copy
of the selected Rust library, never the managed checkout or installed sysroot.
The patch and recipe are assembly identity inputs; the native recipe advances
to v2-unwind. Cargo rebuilds std and panic_unwind with `panic=unwind`, using
the pinned Cargo's `__CARGO_TESTS_ONLY_SRC_ROOT` source-directory override.
This internal Cargo interface is version-specific and must be checked on a
toolchain upgrade. Both library and analyzer dependency locks stay unchanged.
The pure-Rust unwinder is already locked at 0.2.10; its selected features use
static ELF unwind tables and require no OS API or libc call. LLD supplies
aliases for the unwind table finder. The default Motor target remains abort.

This adds no boot work, kernel/runtime change, or native compiler capability.
General opt-in unwinding for other native Rust applications remains a separate
toolchain change. The private library is a build input, not shipped rust-src:
analysis still uses sources matching the installed native compiler.

## Regression evidence during integration

The maintained native test (`src/tests/rust-analyzer-unwind`) passes against
the patched private library: four threads perform 128 cancellations with
nested catch/rethrow, preserve every payload, run 256 destructors while
panicking, and leave each thread's panic state clear. Cancellation invokes no
panic hook; an ordinary caught panic invokes it once. A child explicitly
calling abort exits with Motor status -1. The native log is
`/tmp/motor-ra-unwind-gate-native.log`. The developer branch of `full-test.sh`
compiles and runs this test with the same library preparer and linker flags
as the analyzer. Source and host analyzer gates also pass; the first source
gate needed sandbox access to its existing sibling generated-crate cache.

The expanded Helix helper passes against the prototype in a disposable image
overlay: empty `hx`, `:o src/main.rs` in the shipped project, unsaved edits
and undo during loading, and `gd` on `ANSWER` after the initial check. It also
passes the existing copied-project hover/completion, saved-error clearing,
Motor std navigation, and shutdown sequence. Evidence is
`/tmp/motor-helix-lsp.hhltHo/`, including `shipped-project.log`. This validates
the regression sequence; final acceptance must still use the packaged server
in the rebuilt image with its unmodified default configuration.

The first stripped prototype is 37,280,224 bytes, above the previously
approved 32 MiB limit. Compared with the old 29,245,528-byte server, it adds
about 4.6 MiB of exception tables and 3.4 MiB of cleanup-capable machine code.
Investigate ThinLTO before accepting the final build. The size, memory, image
growth, and timing limits remain unchanged. Incomplete assemblies from recipe
development are not selected or reused as validated artifacts.
