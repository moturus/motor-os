# New image layout follow-ups

Findings deferred while completing milestone 5 of
[the image-layout plan](new-image-layout.md).

The user authorized this policy on 2026-11-14: preserve existing coverage,
record failures from tests newly run on Motor, disable only those cases on
Motor, and continue the layout gate. Linux coverage remains enabled. Make
only test and documentation changes, do not commit, and stop when the full
gate passes or progress requires production-code or out-of-workspace changes.
This instruction supersedes the earlier requirement to fix each newly exposed
Motor defect before completing the migration. It does not authorize disabling
checks that already ran on Motor, weakening their assertions, or adding retries.

After validation and the cleanup correction in NLF-015, the user authorized
committing the completed changes in eight parts. No tests were rerun while
assembling that series; the validation results below remain the evidence.

Each entry records the previous execution scope, failure evidence, precise
exclusion, and the work needed to re-enable it. Exclusions are temporary and
must not be treated as successful validation of the deferred behavior.

## NLF-001: Gix closed stdout is reported as success on Motor

Status: deferred; `closed_stdout_reports_broken_pipe` in
`src/bin/gix/tests/cli.rs` is ignored only on Motor. It remains enabled on
Linux through both Cargo and Lorry.

Previous scope: `src/tests/test-gix.sh` used Python's `os.pipe()` to run the
host Gix binary with a closed stdout reader. It did not run this assertion on
Motor. Milestone 5 newly included it in the Motor native CLI suite.

Failure: Motor's `std::io::pipe()` is unsupported. A direct captured-child-pipe
setup with a 64 KiB commit title also exits successfully after dropping the
reader. Both Interactive and None diagnostics show raw `moto_rt::fs::write`
returning `BadHandle` (17), while Rust stdout `write_all` returns success.
Motor's `is_ebadf` hook classifies the raw error as a closed local descriptor,
so the shared Rust stdout wrapper suppresses it. Gix propagates its write and
flush errors correctly but receives success.

Evidence: `build/milestone5/continue-native-github.log`,
`continue-native-gix-direct.log`, and `gix-stdout-diagnosis.log`. Linux's five
CLI cases pass in `gix-cli-cargo-direct.log` and `gix-cli-lorry-direct.log`.
Temporary production instrumentation was removed before this exclusion.

Follow-up: distinguish a disappeared pipe reader from an invalid local
descriptor. The existing design in
[future-work.md](future-work.md#pipe-closure-is-not-reported-as-brokenpipe-2026-10-09)
adds a pipe-closure error and maps it to `io::ErrorKind::BrokenPipe` through
the Motor runtime and stdlib port. A smaller runtime-only `NotConnected` fix
would prevent silent success but would not complete that classification work.
Preserve successful discarded writes when a process closes its own standard
descriptor. Strengthen the existing native reader-drop test to check Rust
stdout, then re-enable this Gix case with the appropriate Motor diagnostic.
Do not apply either production fix as part of milestone 5.

## NLF-002: rnetbench peer close returns ConnectionReset on Motor

Status: deferred; `tests::a_truncated_flow_is_an_error_rather_than_a_short_read`
in `src/bin/rnetbench/src/main.rs` is ignored only on Motor.

Previous scope: the old `full-test.sh` and `full-test-networking.sh` ran
rnetbench's Cargo tests on Linux. Their Motor coverage ran the benchmark
binary against network peers, not its unit-test harness. Existing benchmark
coverage remains enabled.

Failure: after accepting a loopback connection and dropping the peer without
sending data, `read_exact_pattern` returns `ConnectionReset`. The test expects
`UnexpectedEof`, produced when the socket read returns zero. This first Motor
unit run passed six other cases and failed this assertion as Interactive.
Evidence: `build/milestone5/continue-native-followups.log`.

Follow-up: determine why this close is reported as a reset, whether that matches
Motor's intended TCP close behavior, and whether the test should explicitly
arrange a graceful close. Retain the assertion that a truncated flow fails.
Do not change networking code or relax the error assertion during this migration.

## NLF-003: rnetbench blocked write outlives its shutdown deadline on Motor

Status: deferred; `tests::timed_write_interrupts_blocking_io` in
`src/bin/rnetbench/src/main.rs` is ignored only on Motor. Its previous scope is
the Linux-only Cargo unit harness described in NLF-002.

Failure: a non-reading loopback peer is held open, and a cloned socket is shut
down by `IoDeadline` after 100 ms. The measured write operation took
2.00118333 seconds, exceeding the unchanged one-second assertion and matching
the peer's two-second fallback lifetime. The read and round-trip deadline
cases passed. Evidence: `build/milestone5/continue-native-followups.log`.

Follow-up: trace shutdown wake-up, the blocked writer, and its final flush to
locate the wait that lasts until peer teardown. The exact production cause has
not been established. Re-enable the existing deadline assertion once fixed;
do not extend it or the peer fallback. Linux's test remains enabled.

## NLF-004: host unit-test RNG dependencies do not build on Motor

Status: deferred; `full-native-test.sh` runs the Frusa, MotorFS, and netstack
crate unit suites only on Linux and reports each named exclusion on Motor.
Allocator, filesystem, and networking coverage inside existing native system
and cross-system tests remains enabled.

Previous scope: the old `full-test.sh` explicitly described the Frusa suite as
host-tested and MotorFS's suite as testing a host file-backed block device.
Both ran with Cargo on Linux, as did the netstack unit suite with sys-io's
feature closure and its optional SLAAC variant. Their full release stress and
concurrency counts, MotorFS's `image-admin` coverage, and both netstack variants
remain unchanged on Linux.

Failure: the native unit harness cannot compile its `rand = "0.8"`
development dependency: `getrandom 0.2.17` emits "target is not supported" for
Motor. Production code in these crates does not depend on this test RNG.
Evidence for Frusa:
`build/milestone5/continue-native-followups-2.log`, after both SDK feature
variants passed. MotorFS encountered the same compile error in
`build/milestone5/continue-native-followups-4.log`. Netstack's native harness
encountered the same dependency failure in `continue-native-followups-7.log`,
after the installed toolchain, Javy, and Wasmtime suites passed.

Follow-up: provide a Motor-compatible test RNG or a suitable deterministic
test-only RNG configuration without changing allocator, filesystem, or networking
behavior, then validate these crate suites on Motor. This compile failure prevents
per-test ignore attributes from being sufficient, so the runner excludes each
native unit harness as a whole.

## NLF-005: reported boot time includes opening accumulated test images

Status: timing attribution remains future work; the existing 3,000 ms release
boot assertion is preserved in the fresh-image cross phase. Kernel-log
functional, quiescence, and rotation checks remain in the native systest suite.

Failure: the continued native run's accumulated 9.1 GiB qcow2 image reported
3,655 ms against the boot limit. Its test selected the first preamble across
the previous and current log files, so it also measured a previous boot.
The current console reported 3,712 ms. Reducing guest RAM from 4 GiB to the
old 1 GiB default still gave a current 3,519 ms forwarding milestone.

Diagnosis: Cloud Hypervisor's log places QCOW2 opening between 0.009170 and
3.693512 seconds, before guest execution. As already recorded in
[boot-time.md](boot-time.md), the reported clock starts at vCPU creation and
includes VMM setup. A clean standard-image control with the same boot artifacts,
four CPUs and 4 GiB RAM reached the kernel at 60 ms and forwarding at 77 ms.
This establishes that the accumulated test disk changed the measurement.

Test correction: run the same bound in `cross-test.sh` immediately after the
fresh-image memory-placement check, through `systest kernel-log-boot`. Select
the latest preamble when the installed-image copy contains an older boot log.
Do not raise the bound or disable the original fresh-image coverage.

Evidence: `build/milestone5/continue-native-followups-5.log`,
`boot-milestone-control.log`, `boot-milestone-clean-control.log`, and
`build/cross-test-release.tYCM7V/chv-1/cloud-hypervisor.log`.
Follow-up: investigate the large-disk VMM setup cost and the existing proposal
to attribute guest boot time from kloader entry. No production timing or VMM
code is changed in this migration.

## NLF-006: duplicate Ctrl+C assertion used a nonterminal child

Status: test migration corrected; no production issue or deferred coverage.
The native Crossterm size test had also invoked the `ctrl-c` probe with all
standard streams piped. The second adapter call succeeded, causing the probe
to fail with "a second Ctrl+C handler was accepted".

The pinned Crossterm backend deliberately treats `moto_rt::Error::NotFound`
from handler registration as success: a process without terminal input has no
Ctrl+C source. The old `full-test.sh` ran this assertion through forced-PTY SSH,
and that exact check remains in `cross-test.sh`. Remove the incorrectly copied
native invocation, preserving both the native nonterminal-size assertions and
the original terminal registration check. Neither runtime nor Crossterm code
needs to change.

Evidence: `build/milestone5/continue-native-followups-6.log`; the same run passed
the complete Interactive systest, Mio, and Tokio suites before reaching this
test. The native screen and key-decoding checks also passed.

## NLF-007: sysbox listing test assumed Interactive creation permissions

Status: test migration corrected; no exclusion or filesystem change.
The existing shell-globbing test compared the complete `ls -l *.txt sub`
output against an Interactive-created file's `rwxrw-r--` mode. Running the
migrated command harness as None produced `rwxrwxrw-`, with the same contents,
size, ordering, and successful status.

Both modes follow the creator-relative defaults documented in
[process-roles.md](../process-roles.md): the creator receives `Rw`, higher roles
receive `Rwx`, and lower roles receive `R`. Select the exact expected mode by
the creating process's role, retaining the complete listing comparison.
The Interactive expectation remains `rwxrw-r--`.

The next run reached a second instance in the terminal-color check. Its newly
created file was named `system-only-file`, but a None-created file also grants
execute to Interactive. The old driver explicitly defined `ls` executable
coloring as execute access for either non-System role. Rename the input
`new-file` and require red for None creation and no color for Interactive
creation. The separate uncolored installed-configuration check remains.

Evidence: `build/milestone5/continue-native-followups-8.log` and
`continue-native-followups-9.log`. Before this failure,
the None run passed HTTPd, Gix, enabled rnetbench cases, both SDK variants,
memfs, all six unwind variants, and wasm helper tests.

## NLF-008: positive debugger checks require a privileged role

Status: native test scope corrected; no deferred kernel defect. The None
systest run reached `debugger::test_kill_paused` and failed at `dbg_attach`
with `NotAllowed` (9). The kernel deliberately rejects every debugger attach
from None, including attachment to its own child.

Run this existing positive debugger test only as Interactive or System and
report its required privilege when the native runner uses None. Preserve all
24 mode/race iterations in the Interactive run. The existing
`process_permissions::test_debug_attach_permissions` already spawns None
children and asserts denial for their own children, self, parent, sibling,
and an invalid PID; that coverage remains enabled through Interactive.

The continuation found the same assumption in the zero-capacity debugger-list
assertion inside `test_shared_listener_restart`. Keep the entire listener
restart check enabled for None, assert `NotAllowed` for its attach attempt,
and retain the successful attach/list/detach assertion for Interactive/System.
The other debugger calls belong to privileged boot/OOM cases or explicit
permission-denial tests.

Evidence: `build/milestone5/continue-native-followups-10.log`,
`continue-native-followups-11.log`, and the explicit
role check in `src/sys/kernel/src/uspace/sys_ray_dbg.rs`. The Interactive
paused-debugger test passed in `continue-native-followups-6.log`.

## NLF-009: Wasmtime readonly setup sealed its directory too early

Status: test setup corrected; all readonly WASI cases remain enabled.
The None Wasmtime run passed its 34 scratch-filesystem programs, then failed
with `NotAllowed` while preparing the readonly preopen. Setup had narrowed
the directory to `Rx` before narrowing its file to `R`.

Motor requires the caller's write permission on a file's parent even when
narrowing the file's permissions. Interactive retained write access to the
directory, so the earlier run passed. Set the file's permissions first, then
seal the directory. Preserve the four readonly-program assertions, unchanged
contents check, and directory restoration for cleanup. The documented
`Rx` to `Rwx` transition restores that directory through its writable parent.
No filesystem or Wasmtime production change is needed.

Evidence: `build/milestone5/continue-native-followups-12.log` and the permission
change rules in [process-roles.md](../process-roles.md). The same continuation
passed the complete None system, Mio, Tokio, Crossterm, installed-toolchain,
QuickJS Test262, and Javy suites before this setup error.

## NLF-010: C++ unwind linker settings escaped into later native suites

Status: test-runner correction verified. The first consolidated
release gate exited 101 in Interactive `cold_spawn::test_syscall_buffer`:
the ordinary untouched-page case passed, but `syscall-zero` found address zero
already mapped. This assertion previously ran on Motor and remains enabled.

The native unwind helper exported its C linker and rustflags inside a shell
subshell. Rush explicitly does not isolate general exported-variable changes,
as documented in [caps.md](../caps.md). The settings therefore selected the
C runtime for later Rust-only suites. The failed native `systest` and native
test harness both have the mlibc startup entry; that startup reads the ELF
header at address zero before reaching the test. The cross-built executable
uses Rust startup and passes the same existing child mode in the same VM.

Keep the C++ settings on the actual external Lorry invocations, selected by an
unexported variable scoped to the helper. Preserve explicit test capabilities
and the existing linker flags. This restores the intended separation between
pure Rust and C++ variants without changing Rush, mlibc, the toolchain, or the
page-zero assertion. No test is disabled for this finding.

Evidence: `build/milestone5/full-gate-followups-release.log` (exit 101),
`cold-zero-diagnosis.log`, and the extracted native ELF files. Both native
executables reproduced the assertion in a disposable copy of the failed VM;
the cross-built control returned `syscall-buffer-ok`. The original full-gate
logs remain in `build/cross-test-release.wy0uXP`; its failed native disk is
preserved as `build/milestone5/full-gate-release-failed-native.qcow2.zst`.

`cold-zero-runner-verification.log` confirms that the original helper changes
both variables from unset to the C++ values, while the corrected helper leaves
both unset. The existing C++ unwind case passes with either invocation. The
corrected sequence then passes the complete native Interactive systest,
including both untouched-page assertions and the kernel fault counter.

## NLF-011: repository unit tests assumed an Interactive caller

Status: test setup and diagnostic expectation corrected and verified; both tests
stay enabled.
The second consolidated release gate passed the complete Interactive native run,
then failed two Lorry unit tests as None. The other 448 enabled unit tests passed.

`publishes_only_resolution_data_and_rejects_changed_or_linked_records` configured
only `repositories.user`, so opening its writer failed with "None vendoring
requires repositories.none" before testing index publication. Use an explicit
temporary local repository, which is writable by either caller role and matches
the other repository unit fixtures. Preserve every publication and corruption
assertion. The separate native role tests retain the shared-repository policy
coverage.

`writer_requires_a_configured_writable_layer` correctly received a failure but
expected the Interactive diagnostic. Require the role's specific diagnostic:
None must configure `repositories.none`; Interactive must configure a writable
repository. Linux retains its original expectation. This follows the existing
repository selection policy without changing production code or accepting an
arbitrary error.

Evidence: `build/milestone5/full-gate-followups-release-2.log` (exit 101).
The original VM logs are in `build/cross-test-release.7kvgvu`; the failed native
disk is preserved as `build/milestone5/full-gate-release-2-failed-native.qcow2.zst`.
These general unit tests had not been included in the earlier focused None
integration-test continuations.

## NLF-012: workspace-trust unit tests shared persistent Motor configuration

Status: test isolation corrected and verified; both workspace-trust tests remain
enabled.
The None continuation passed both NLF-011 repository tests, then failed the
initial empty-store assertion in
`workspace_trust::tests::records_round_trip_and_stay_with_their_workspace`.
Its store already contained an invalid path grant with an unknown `version` key.

The test helper supplied a temporary `HOME`, but Motor deliberately ignores
`HOME` when selecting its role configuration directory. Both tests consequently
used the same `/none/cfg/lorry-workspaces/7271bf0ce3963344e942942003cba8a3.toml`
for their fixed `/user/helix` workspace. The preceding full-gate run's
`rejects_malformed_decisions` case left exactly this invalid record in the
persistent configuration copied into the continuation VM. The shared path also
permits the tests to interfere when run concurrently.

Keep the production-generated workspace filename, but put the Motor test store
inside that test's existing temporary directory. Linux retains its temporary
HOME setup. All serialization, policy application, malformed-record rejection,
and copied-record workspace checks stay enabled. No production path selection or
trust handling changes, and no retry or pre-run deletion hides the contamination.

Evidence: `build/milestone5/continue-native-repository.log` (exit 101), VM logs in
`build/cross-test-release.MtdKzU`, and the helper's shared path before this
correction. The preceding complete gate's None run passed these tests once;
that pass did not establish isolation across later invocations. The original
contaminated full-gate image is preserved with NLF-011's evidence.

`build/milestone5/continue-native-trust.log` (exit 0) verifies both NLF-011 and
NLF-012: all 450 enabled Lorry unit tests and its complete integration suite pass
as None. The same continuation passes every remaining native crate, including
the system suite, all unwind variants, QuickJS Test262, Javy, Wasmtime, and HTTPS.
The old persistent malformed record was left in place during this verification.

## NLF-013: analyzer sampling lost the command after five-digit PIDs

Status: test executable path corrected and boundary verification passed; resource
and semantic assertions remain enabled. The third consolidated release gate
passed the complete Interactive phase and all 450 enabled None Lorry unit tests,
then stopped in the analyzer
integration test with "sampler observed no descendant lorry check". Its semantic
checks, including diagnostics on save, had succeeded.

Motor's process catalog keeps 32 bytes of a debug name. When a command is longer,
the runtime keeps 29 bytes plus a three-byte ellipsis. The migrated test copied
Lorry to `/none/tmp/ra-{pid}/lorry`; with a five-digit PID, that path plus ` check`
occupies 30 bytes. The sampler therefore sees `lorry chec…`, which cannot satisfy
the unchanged command classification. The Interactive test's PID was 4655; the
earlier focused continuations ran in newly booted VMs. The original native test
used the shorter installed `/user/bin/dev/lorry` path.

Use a hexadecimal PID and the one-byte executable name `l` in this test's
temporary directory. Even the maximum `u32` PID then leaves the complete
` check` suffix inside the 29-byte prefix. Continue testing the current crate's
executable and preserve sampling cadence, resource limits, descendant checks,
and all editor assertions. No runtime or analyzer change is needed.

Evidence: `build/milestone5/full-gate-followups-release-3.log` (exit 1), the
debug-name formatting in `src/sys/lib/rt.vdso/src/rt_process.rs`, and
`ProcessInfoV1::MAX_DEBUG_NAME_BYTES`. VM logs are retained in
`build/cross-test-release.OjiBxT`; its failed native disk is preserved as
`build/milestone5/full-gate-release-3-failed-native.qcow2.zst`.

`build/milestone5/verify-analyzer-name.log` (exit 0) reruns the existing analyzer
case with controlled path widths. `analyzer-native-five-digit.log` reproduces
the exact failure and records `/none/tmp/ra-00024/lorry chec…` in the sampler.
`analyzer-native-max-width.log` passes the complete analyzer case with
`/none/tmp/ra-000001cc/l check…`, preserving all resource assertions at the
maximum path width. Temporary name logging and padded PIDs exist only in the
ignored diagnostic copies; the crate test contains only the path correction.

## NLF-014: interactive host gate waits for stdin in a checksum stub

Status: test helper corrected; the existing Wasmtime fetch check passes with
terminal input open. No test is disabled.

On November 15, a direct `src/tests/full-test.sh --release` invocation stopped
after compiling `fetch-runtime` in `host_wasmtime_fetch`. The process tree showed
the runner waiting for `cat` for more than 32 minutes. That process had stdin
`/dev/pts/1`, stdout `/dev/null`, and working directory
`/tmp/tmp.qlANk5hawS/image`.

The test inherited `sha256sum() { cat > /dev/null; }` from the removed
`test-wasmtime-fetch.sh`. The producer supplies filenames, but this stub ignores
them and reads stdin instead. It finishes at EOF in noninteractive runs and
waits for terminal input in an interactive run. Replace it with a no-op, matching
the adjacent `install` stub: image staging and checksums are outside this fetch
test. The offline builds and both unchanged-lockfile comparisons remain active.

Verification: source `src/tests/full-test.sh` and invoke `host_wasmtime_fetch`
with an open pseudo-terminal. Both Motor-target workspaces compiled and the
check printed `test-wasmtime-fetch PASS`, exiting 0 in about 0.6 seconds. The
user's existing full-gate process was left running; it already loaded the old
function definition. No new full gate was started and no commit was made.

## NLF-015: successful interactive gate prompts during cleanup

Status: test runner cleanup corrected; no test is disabled. The full gate was
not rerun, as requested by the user.

The user reported both native Motor and full release gate PASS markers on
November 15, followed by removal prompts for write-protected Git objects under
`build/cross-test-release.66C8IQ/gix`. Cleanup was interrupted with Ctrl+C, so
this report confirms the tests passed, not a clean exit of the entire script.

The success-path EXIT trap used `rm -r`, which prompts for write-protected files
when stdin is a terminal. Use `rm -rf --` for the runner's temporary directory
so normal read-only Git objects are removed without prompting. Failed runs
continue to retain their evidence. Validation is limited to shell syntax and
whitespace checks; no tests or builds were run for this correction.

## Gate status

The complete release gate passed on 2026-11-15:
`src/tests/full-test.sh --release` exited 0 and printed
`full-test: PASS (release, chv)`. Evidence is in
`build/milestone5/full-gate-followups-release-4.log` and its `.exit` file.
This includes host checks, native Linux Cargo/Lorry suites, toolchain
installation/reinstallation, the complete cross-system gate, and complete native
Motor runs as Interactive and None. The corrected analyzer resource case passed
in both roles, including None with PID 16307.

This is the first complete consolidated milestone 5 pass. Work stopped at that
point under the user's continuation policy; no commits were made. Validation
covers the ordinary release gate, with the Motor-only exclusions below. The
optional `--full` Helix build and debug/multiple-run matrix were not selected.
Only tests and documentation changed during this continuation; the earlier
milestone implementation and external toolchain integration were preserved.
The original ignored logs under `build/milestone5` were no longer present during
the later NLF-014 diagnosis. Total elapsed time was not recorded in this document;
the single complete pass does not establish a usual release-gate duration.

All consolidated runs used the same command:

| Log under `build/milestone5/` | Result | Last phase reached |
| --- | --- | --- |
| `full-gate-followups-release.log` | exit 101, NLF-010 | Interactive system suite; host, Linux, installation and cross-system phases passed |
| `full-gate-followups-release-2.log` | exit 101, NLF-011 | None Lorry units; complete Interactive phase passed |
| `full-gate-followups-release-3.log` | exit 1, NLF-013 | None analyzer integration; complete Interactive phase and all 450 enabled None Lorry units passed |
| `full-gate-followups-release-4.log` | exit 0, PASS | All phases, including complete Interactive and None native runs |

Focused continuations do not count as consolidated passes. They include both
complete system suites, Mio, Tokio, installed tools, QuickJS Test262, and Javy.
`continue-native-followups-13.log` passed all 141 None Wasmtime commands, including
the four readonly programs, and all ten HTTPS cases. `continue-native-trust.log`
passed the complete remaining None phase from Lorry onward after NLF-011 and
NLF-012. The existing analyzer case then reproduced NLF-013's truncation and
passed at the corrected maximum path width in `verify-analyzer-name.log`.

Motor-only exclusions remain NLF-001 (Gix closed stdout), NLF-002 and NLF-003
(two rnetbench cases), and NLF-004 (Frusa, MotorFS, and netstack unit harnesses).
Their Linux coverage remains enabled. NLF-005 preserves the release boot bound
in the fresh-image cross phase; its timing-attribution follow-up remains open.

An unwind harness migration error was corrected without an exclusion: native
Lorry rejects a build script's system-library search path, so the test runner
now supplies `/user/lib/llvm/lib` through its explicit C++ rustflags. The
cross-Cargo build-script override remains supported. All six Motor unwind
variants pass across `continue-native-followups-3.log` and
`continue-native-followups-4.log`, including C++ exceptions, LTO, and abort.
