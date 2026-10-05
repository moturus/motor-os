# Native YAML parser: missing runtime strlen

Status: the approved runtime export and native regression are implemented.
The final patch passed the full core gate three times each in debug and
release. The selected SDK still needs to select published moto-rt 0.17.7.
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

Here, "SDK rollout" means updating the repository-selected Motor OS
compiler toolchain and its target standard libraries through the managed
build procedure. The relevant part is Rust std's bundled runtime dependency:
ordinary native builds must obtain the fixed `strlen` automatically.

The installed Rust std selects published crates.io moto-rt 0.17.6 through
the Rust fork's library lock. It does not select this working tree. Merely
rebuilding the current declared toolchain would reuse that published crate
and would not pick up this change. This corrects the initial suggestion
that a local runtime rebuild was sufficient.

The user has published the fixed runtime as 0.17.7. Updating std's copy now
requires updating the fork's library lock and declared Rust revision/lock hash,
and building/selecting the corresponding new toolchain tuple. Follow
[the toolchain procedure](../../../../docs/toolchain.md#5-changing-the-toolchain).
The fork update and SDK selection remain separate from the approved in-tree
fix and completed publication; no toolchain or external fork source has
been changed by this task.

### Exact proposed external Rust-fork change

The external checkout is `/home/posk/motor-dev/toolchain-src/rust`, backed
by `https://github.com/moturus/rust`. Its `library/std/Cargo.toml` already
declares `moto-rt` version `0.17` with `rustc-dep-of-std`, which enables the
runtime's `libc` exports. That declaration accepts the published 0.17.7
release. The only planned external source edit is the moto-rt entry in
`library/Cargo.lock`:

```diff
 name = "moto-rt"
-version = "0.17.6"
+version = "0.17.7"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "f8e7200c0150f580541a80917e0ade7f91c0e76d2d9f81e3735ebdb7a3862bef"
+checksum = "0a1f77799833534c2aa19be58ab03aee6b60bc203d430ba43a65c97172e06d3f"
```

The checksum above was verified against the published archive. Updating
this lock entry selects the existing Motor OS runtime fix; it requires no
Rust compiler, LLVM or std implementation changes. The external fork gets
a new commit because the dependency selection changed. Its branch must be
pushed before the managed
SDK build, which requires a declared commit reachable from the published
source ref. Compiled SDK binaries are built locally, not published.

### Rollout sequence after approval

1. Completed by the user: bump and commit the in-tree moto-rt version to
   0.17.7 (`1cf8bb9d`), then publish it with the approved `strlen` fix.
   The published package is verified below.
2. Update only the external fork's runtime lock entry with the published
   version and checksum, then commit and push that fork change.
3. Update Motor OS `src/toolchain-versions.sh` with the new Rust revision,
   library lock hash and toolchain lineage identifiers.
4. Run `src/build-motor-os.sh` and select its new toolchain name in
   `rust-toolchain.toml`. Rebuilding the old declaration keeps using 0.17.6.
5. Validate the batteries native release build, all three debug and three
   release main-image full gates, and `src/tests/full-test-dev.sh --release`.

The external-fork and SDK actions remain proposed. The temporary package
and native checks below establish that the fix works, while native
skills validation with the installed SDK remains incomplete until this
dependency selection is updated and the installed-image gate passes.

## Published runtime verification

On 2026-10-05, the user reported publication of moto-rt 0.17.7.
[Registry metadata](https://crates.io/api/v1/crates/moto-rt/0.17.7) confirms
the release is not yanked and was published at 21:23:52 UTC. The downloaded
archive matches its published SHA-256:
`0a1f77799833534c2aa19be58ab03aee6b60bc203d430ba43a65c97172e06d3f`.
Its `src/libc.rs` includes the approved weak Rust `strlen` export, and its
VCS metadata names commit `1cf8bb9ddc9d116b8db7012a120e818a7180177f`.
The archive is `/tmp/gears-moto-rt-0.17.7-published.crate`; metadata is
`/tmp/gears-moto-rt-0.17.7-registry.json`.

## Release candidate and native skills evidence

A temporary archive of commit `8b55c381` packages moto-rt as candidate
version 0.17.7. Comparing its Rust sources against the checksum-verified
published 0.17.6 archive finds only the approved strlen addition. Before
publication, registry metadata checked on 2026-10-05 reported latest
version 0.17.6 and no existing 0.17.7 release. Offline packaging and
Motor-target verification with `libc` enabled pass in
`/tmp/gears-runtime-release-package.log`.

Review artifact:
[/tmp/gears-runtime-rollout.ibHHea/package-target/package/moto-rt-0.17.7.crate](/tmp/gears-runtime-rollout.ibHHea/package-target/package/moto-rt-0.17.7.crate).
Its SHA-256 is
`688432b20875428966db03ed67be13c5f1969538f4c8fa32eb65e04a3515eb7f`.
This temporary package is a review artifact, not the final published checksum:
the final release packages the committed version change with its VCS
metadata. Use the verified published checksum above in the Rust library lock.

The same temporary tree points Gears at the candidate with `libc` enabled.
Native release builds of Gears, batteries and the portable workflow pass.
The existing batteries VM gate passes with uploaded current binaries in a
release snapshot, including the skills workflow and current sibling/config
startup. Build and run logs are
`/tmp/gears-skills-local-runtime-build.log` and
`/tmp/gears-skills-local-runtime-native-gate.log`.

These temporary checks changed no tracked dependency selection, installed
SDK, registry publication or external source. The user has since completed
publication, as recorded above. The checks validate the skills implementation
on Motor OS with the fix; the external Rust fork lock update and push,
SDK rollout and installed-image gate remain outstanding.
