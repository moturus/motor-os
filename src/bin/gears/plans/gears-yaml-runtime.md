# Native YAML parser: missing runtime strlen

Status: the approved runtime export and native regression are implemented.
The final patch passed the full core gate three times each in debug and
release. The selected SDK still needs the published runtime update below.
The skills implementation uses the user-authorized `yaml_serde` dependency. Its host
debug and release gates pass, as do host and Motor-target Clippy.

## Evidence

The native release link fails with undefined `strlen` in libyaml-rs's Rust
byte-scanning loop. The original failure is preserved in
`/tmp/gears-batteries-skills-motor-build.log`.

An independent standard-Rust loop, with no YAML dependency, reproduces the
same issue. Debug links; release fails. The reproducer and logs are:

- `/tmp/gears-yaml-strlen-probe.rs`
- `/tmp/gears-yaml-strlen-probe-debug.log`
- `/tmp/gears-yaml-strlen-probe-release.log`

LLVM recognizes the NUL-scanning loop and generates a call to `strlen`.
Rust core lists that symbol among the runtime functions it expects.
Before this fix, `src/sys/lib/moto-rt/src/libc.rs` provided weak mem* exports,
but no strlen. This runtime gap was exposed by the parser; the parser has no
C build dependency.

## Runtime fix

The original proposal is [/tmp/gears-yaml-strlen-moto-rt.patch](/tmp/gears-yaml-strlen-moto-rt.patch).
The implementation adds a weak Rust `strlen` export beside the existing moto-rt memory routines,
with the standard C signature and an explicit pointer safety contract. A
strong mlibc definition can override it, following the existing convention.
The systest covers empty, ordinary, embedded-NUL, non-UTF-8 and longer
strings, including an offset into the buffer, the byte loop LLVM optimizes
and `CStr::from_ptr`. Systest enables the local runtime's `libc` feature so
the regression links its new export. It runs through the existing full gate.

Commits: `660771d7` adds the runtime export and regression;
`f5d5b951` isolates the channel cleanup test described below.

A temporary release probe with that export links. Disassembly shows a byte
loop without a recursive call. The probe and assembly logs are named
`/tmp/gears-yaml-strlen-probe-with-runtime-symbol*`.

[Root AGENTS.md](../../../../AGENTS.md) requires moto-rt changes to be
discussed and vetted; the user explicitly approved this fix. The core patch
must pass the main-image full gate three times each in debug and release
before committing. Formatting, runtime Clippy and focused systest Clippy
with warnings denied pass, as does the native release systest build.

## Core gate diagnosis

The first full debug run passed the new strlen regression, then failed in
`test_disconnect_before_rx_ready_releases_channels`. Its original log is
`/tmp/gears-strlen-full-debug-1.log`. Diagnostic reruns used the existing
native cancellation and networking suites and the full debug gate. The
full gate reproduced the failure: one active client, six channels at the
baseline, then five, four and three channels after the raw clients closed.
The global baseline included earlier connections still finishing cleanup;
waiting for it to return to six was incorrect. The diagnostic log is
`/tmp/gears-strlen-full-debug-diagnostic.log`.

A small test-only patch runs the unchanged exact channel-count check during
systest's initial checks, after logging verifies stats readiness and before
the other networking fixtures. Both native networking subcommands also run
it first, and a focused `test-disconnect-before-rx-ready` command is available.
It stays transitively included in full-test.sh; assertions and deadlines are
unchanged. Temporary instrumentation is removed.

The first placement, at full-test.sh's fresh-VM startup, passed the complete
debug gate (`/tmp/gears-strlen-full-debug-1-fixed.log`) but was too early in
release: sys-io deliberately defers stats registration during boot. The
original release failure is `/tmp/gears-strlen-full-release-1-fixed.log`.
Moving the check after logging's existing metric assertions fixes that test
setup dependency without adding waits, retries or boot work. The final six
core runs started over on this placement. All three debug and three release
runs passed, including the channel assertion and strlen regression in each
run. Logs are `/tmp/gears-strlen-full-{debug,release}-{1,2,3}-ready.log`.
Debug testing took 22.4, 22.8 and 22.4 minutes; release took 10.6, 10.6 and
10.5 minutes. The earlier failures remain preserved and are not counted as
successful final validation.

The release regression also passed in a native VM using a temporary focused
subcommand, removed after that check:
`/tmp/gears-strlen-focused-release-run.log`. Assembly of the actual local
runtime confirms weak linkage and a byte loop without recursion; its build
log is `/tmp/gears-strlen-runtime-assembly.log`.

## Toolchain follow-up

The installed Rust std selects published crates.io moto-rt 0.17.6 through
the Rust fork's library lock. It does not select this working tree. Merely
rebuilding the current declared toolchain would reuse that published crate
and would not pick up this change. This corrects the initial suggestion
that a local runtime rebuild was sufficient.

Updating std's copy requires releasing a runtime version containing the fix,
updating the fork's library lock and the declared Rust revision/lock hash,
and building/selecting the corresponding new toolchain tuple. Follow
[the toolchain procedure](../../../../docs/toolchain.md#5-changing-the-toolchain).
That release and fork update are separate from the approved in-tree fix;
no toolchain or external dependency source has been changed.

After the toolchain update, rerun the batteries native release build and
`src/tests/full-test-dev.sh --release`. Native skills validation remains
incomplete until its runtime dependency also contains the fix.
