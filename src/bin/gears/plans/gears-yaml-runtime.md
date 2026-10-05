# Native YAML parser: missing runtime strlen

Status: diagnosed; proposed runtime change awaits review. The skills
implementation uses the user-authorized `yaml_serde` dependency. Its host
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
`src/sys/lib/moto-rt/src/libc.rs` provides weak mem* exports, but no strlen.
This is a runtime gap exposed by the parser, not a required C dependency.

## Proposed fix

The reviewable patch is [/tmp/gears-yaml-strlen-moto-rt.patch](/tmp/gears-yaml-strlen-moto-rt.patch).
Add a weak Rust `strlen` export beside the existing moto-rt memory routines,
with the standard C signature and an explicit pointer safety contract. A
strong mlibc definition can override it, following the existing convention.
Add a systest covering empty, ordinary, embedded-NUL, non-UTF-8 and longer
strings, including the byte loop LLVM optimizes and `CStr::from_ptr`.

A temporary release probe with that export links. Disassembly shows a byte
loop without a recursive call. The probe and assembly logs are named
`/tmp/gears-yaml-strlen-probe-with-runtime-symbol*`.

No runtime, toolchain or external dependency source has been changed.
[Root AGENTS.md](../../../../AGENTS.md) requires moto-rt changes to be
discussed and vetted, and core patches to pass the main-image full gate
three times each in debug and release before committing. After review,
update the runtime embedded in the selected toolchain, perform those gates,
then rerun the batteries native release build and
`src/tests/full-test-dev.sh --release`. Do not change external source or the
Rust PAL without a separate discussion.
