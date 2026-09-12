# Native Rust unwinding required by rust-analyzer

The decision to retain a private analyzer-only Rust library is **superseded**
by the [unified toolchain and rustfmt plan](rustfmt.md). That plan is the current
implementation. Its local standard-unwind candidate builds std, rustc, rust-analyzer,
and rustfmt with standard Motor unwinding and passes the generic Rust/C++
unwind and analyzer gates. The private build and regression were removed from
the candidate producer. Publication and the managed `.dev.2` cutover remain pending; the
selected `.dev.1` image still uses the private build described below. This
document preserves the earlier repair's evidence and authorization, which do
not authorize new work.

Complete and gated on 2026-09-10. The release developer image now uses the
unwinding-enabled analyzer; the packaged SSH workflow, a fresh console run,
and the full release developer-image suite pass. Initial loading/indexing
must finish before semantic navigation; the first compiler check alone does
not establish readiness.

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

## Historical scope after the native prototype (superseded)

The pure-Rust implementation passed 128 cancellations on four native threads,
including nested cleanup and payload recovery. A server built with it survived
the previously fatal initial workspace analysis and resolved `ANSWER` in Helix.

The repair kept this implementation private to the native rust-analyzer build.
That production-isolation choice is superseded by the unified toolchain plan.
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

That repair added no boot work, kernel/runtime change, or native compiler
capability. General unwinding for other native Rust applications was deferred
and is now included in the unified toolchain plan. The deployed private library
is a build input, not shipped rust-src:
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

ThinLTO increased the stripped prototype to 40,221,936 bytes and was rejected.
Release `opt-level=s`, without ThinLTO, produces 29,772,208 bytes: below the
unchanged 32 MiB bound and only 526,680 bytes larger than the abort-only server.
Apply that profile only to the native analyzer and its runtime regression.
The full native semantic/resource gate must still establish that this code
generation choice meets the existing latency and memory limits. Evidence:
`/tmp/motor-helix-unwind-ra-{thin,size}-build.log` and the corresponding
stripped binaries under `build/helix-unwind/`.

Provisioning explicitly fetches the selected library lock's dependencies for
all platforms, including the existing Xous unwinder dependency. This avoids
depending on a warm Cargo cache. The native build and its tests remain offline;
acquisition failure is fatal and the original library lock stays unchanged.

The size-optimized runtime regression passes. Its first editor run exposed a
preexisting test readiness error: the first flycheck can finish before source
loading/indexing. The server stayed alive and returned null to hover in 3 ms;
it completed loading about four seconds later. Evidence is
`/tmp/motor-helix-unwind-size-hover-failure.log`. The editor helper now observes
completion of the project and std source scan and all active progress work,
as well as a completed check, before semantic assertions. A host regression
tests initial project-only scans, reloads, active indexing, and partial logs.
The original 60-second observation and 20-second response bounds are unchanged;
the semantic request is issued once, after readiness, rather than retried.

## Final packaged validation

The clean assembly is
`f64cef43ac5451f87829bf0c45595b2d44ae1ae83eb25671161ce1707019abcc`,
with recipe `motor-native-rust-analyzer-v2-unwind`, produced at `a4d3f412`.
The installed host toolchain remains
`50df587e90f781a28d420f9b5e47135ea78508dd83bdac9f487a410fcd330500`.
The complete build log is `/tmp/motor-helix-unwind-packaged-build.log`.

`src/tests/full-test-dev.sh --release` passes completely:
`/tmp/motor-helix-unwind-full-dev-release.log`. This includes the repository
suite, native dependency and cancellation regressions, the actual Helix
workflow, native developer-source builds, and the complete Lorry product
suite (513 seconds; native self-build gate 259.928 seconds). No test retries,
deadline extensions, or resource-limit increases were used to obtain this
pass. The repair changes no production `src/sys` code; the earlier child-pipe
patch's six core gates remain recorded in the integration plan.

Packaged Helix evidence is `/tmp/motor-helix-lsp.viKpQf/`. Its
`shipped-project.log` records opening the file after empty startup, editing
during loading, then one definition response pointing to
`file:///devtools/src/helix-rust-demo/src/greeting.rs`, line 2, column 11.
Hover, completion, saved diagnostics and clearing, Motor std navigation, and
shutdown all pass using the default packaged configuration.

The native analyzer's two-project case uses four CPUs and 8 GiB RAM. Evidence
is `/tmp/motor-ra-native.4aUvWY/case/`; sizes are in
`build/ra-image-growth.eGJJLs/sizes`.

| Measurement | Observed | Existing bound |
|---|---:|---:|
| Complete native case | 26.552 s | 90 s |
| Stripped server | 29,767,376 bytes | 32 MiB |
| Rust sources | 71,952,945 bytes | 80 MiB |
| Fresh image growth | 121,896,960 bytes | 128 MiB |
| Sampled server virtual memory | 914,612,224 bytes | 2 GiB |
| Server threads | 26 | 32 |
| Sampled whole-VM physical memory | 1,369,657,344 bytes | 3 GiB |

String hover took 916.5 ms; completion 1.37 ms; saved-error checking 1.752 s;
clearing 1.728 s; shutdown 192.5 ms. These remain measurements, not extra
thresholds. The new runtime test also passes host Clippy with warnings denied.

After the gate, a refreshed image was copied and booted on the serial console
with eight CPUs and 8 GiB RAM. Empty `hx`, `:o src/main.rs`, and a single `gd`
on `ANSWER` after loading opened `greeting.rs:2:11`. The actual response is
in `/tmp/motor-helix-unwind-final-console-lsp.log`; the terminal recording is
`/tmp/motor-helix-unwind-final-console.log`. Shutdown/exit completed and no
analyzer process remained. The final image refresh also corrects the shipped
guide to wait for source loading/indexing (the LSP spinner), not merely the
first compiler check. Refresh evidence is `/tmp/motor-helix-unwind-final-image.log`.

The original reported disk is preserved as
`vm_images/release/motor-os-dev-user-reported-20260910.qcow2`; the reproduction
overlay points to that backup. The final delivered image is
`vm_images/release/motor-os-dev.qcow2`, booted with `vm_images/release/run-dev.sh`.

Repair commits: `63b92a79` (diagnosis/plan), `fd5176dc` (private unwinding build
and native regression), `559830f9` (reported editor workflow), `468814d2`
(bounded binary size and dependency provisioning), and `a4d3f412` (readiness
regression and corrected integration records), followed by this validation
and shipped-guide update.
