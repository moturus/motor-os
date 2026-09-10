# Native Helix and rust-analyzer integration

## Authorization and baseline

On 2026-09-09 the user requested review of `helix.md` and `rust-analyzer.md`,
native integration on `dev.img`, several committed patches, and completion
without stopping overnight. Record AGENTS.md stop conditions here and continue
under that explicit override. This plan is written before implementation;
the ordinary plan-review pause is overridden. Commits are explicitly requested.

Helix stages 1–3 are complete. Native rust-analyzer stage 2 is now complete,
including the allocator fix that resolved string hover. Helix's old stage 4
proposal for a Lorry-generated project JSON graph is superseded by the working
Cargo-compatible Lorry metadata/check interface. Use that tested interface.

## Design and small patches

1. Package `/user/.config/helix/languages.toml` in the developer overlay.
   Both SSH and console sessions already set `HOME=/user`, and the pinned
   Helix loader already reads this path. Configure the direct native server,
   its `CARGO`, `PATH`, and `TMPDIR` environment, and the exact native options
   in rust-analyzer.md §4.6. Preserve Helix's ordinary project and XDG overrides.
   Include a dependency-free Rust example under `/devtools/src/helix-rust-demo`
   with Motor std usage and locally resolvable symbols. Fix quoted argument
   forwarding in the existing `hx` launcher.
2. Extend `test-tui.sh` through a focused sourced helper that exercises the
   shipped launcher and configuration in the developer VM: health, opening a
   project whose path contains spaces, hover, definition, completion, a rustc
   diagnostic after saving an error, clearing it after saving the fix, and
   clean editor/server exit. The helper runs transitively in `full-test.sh`.
   Reuse the existing SSH/PTY harness and its bounds; retain failure evidence.
3. Document the native workflow in the packaged editor guide and maintained
   Rust/Helix documentation. Record exact validation and commit identifiers.

The initial design needs no external repository, managed toolchain source,
`src/bin/lorry`, `src/sys`, assembly artifact, boot service, or boot-time work.
Native acceptance subsequently exposed the two necessary, bounded Lorry and
runtime corrections recorded below. External sources remain unchanged.
The only native behavior added is loading editor configuration when opening
Helix and starting rust-analyzer for Rust buffers. Project acquisition remains an
explicit Lorry developer operation; the example and tests are offline.

## Validation

Build the release development image, run focused developer TUI acceptance,
and run the complete `src/tests/full-test-dev.sh --release` with its existing
deadlines. Use the repository-selected toolchain for formatting and any host
Rust checks. Check shell syntax and `git diff --check`. Gate each code patch
with its component checks before committing; keep final image and full-gate
evidence. No debug developer-image run is intended for this non-Lorry task.
Core-OS gates become required only if evidence forces a core change.

## Stop-condition record

- Plan review and non-obvious integration choices: continue under the explicit
  overnight instruction. Existing Helix configuration lookup avoids a fork
  change or a new global environment setting.
- Preexisting launcher bug: `/devtools/bin/hx` uses unquoted `$@`, so shell
  splitting loses filename boundaries. Quote it and exercise a path containing
  spaces in native acceptance; no unrelated shell changes are needed.
- The base-image `cp` launcher also forwards unquoted arguments. Leave that
  unrelated launcher unchanged and use `sysbox cp` directly to stage a test
  directory containing spaces.
- Native editor initialization timed out at Helix's unchanged 20-second bound.
  The analyzer reader stack is in `read_exact` for the message body: it received
  the header and only part of the body. Tokio clears its writable readiness
  after a short write, but runtime `ChildStdio::write_data` only rearms the
  source after an error. A full pipe followed by a peer read therefore never
  generates the next writable event. Existing Tokio pipe tests only wait for
  child exit and transfer no data. Preserve `/tmp/motor-helix-ra-probe-lsp.log`,
  `/tmp/motor-helix-ra-probe-process.log`, and the server stack log as evidence.
  Continue under the overnight override: add a real bounded Tokio pipe
  round-trip regression, reproduce on the unchanged runtime, then rearm short
  child-stdin writes. This necessary `src/sys/lib/rt.vdso` correction expands
  scope to core OS and requires three passing debug and three passing release
  `full-test.sh` runs before committing the core patch. No external Tokio or
  Helix source change is planned.
- After the pipe repair, Helix still could not process keyboard or server
  events. Its main-thread stack was blocked in the terminal read claim while
  the server's synthesized fd 3 relay owned that stream. This is the documented
  background-helper contract in `docs/tui.md` (Foreground forwarding), not a
  second runtime defect. Set `MOTURUS_STDIO_NO_TERMINAL=true` in the server's
  launch environment. The VDSO consumes it before the child starts. Evidence:
  `/tmp/motor-helix-input-stacks.log` and `/tmp/motor-helix-input-lsp.log`.
- Saving a binary invokes `lorry check -p <package-id> --bin NAME` even with
  workspace checks enabled. The prior library-only native server fixture missed
  this unsupported command. Continue with exact manifest-ID validation and
  named binary/integration-test selection; details and contract coverage are in
  [Lorry's integration plan](../../src/bin/lorry/helix-integration.md).
  Preserve `/tmp/motor-helix-lsp.4ulIjq/helix.log` as the failing evidence.
- Native rustfmt is absent from the selected assembly. Disable Rust automatic
  formatting and the LSP formatting feature rather than letting every save
  attempt an unavailable tool. Document the limitation; packaging a new native
  toolchain component is outside this editor integration.

## Implementation and validation record

Packaging: release image build passed (`/tmp/motor-helix-ra-build-release.log`).
Existing developer TUI acceptance, including default Rust server discovery,
passed (`/tmp/motor-helix-ra-tui-package.log`). The example was formatted with
the repository-selected `cargo fmt`; shell syntax and diff whitespace pass.
Packaging was committed as `2bab93c5`.

The new framed-pipe regression fails on the original runtime at its five-second
deadline (`/tmp/motor-helix-ra-framed-before.log`) and passes with short-write
rearming (`/tmp/motor-helix-ra-framed-after.log`). Helix then initializes and
finishes native project loading/checking (`/tmp/motor-helix-ra-fixed-lsp.log`).
An initial automated semantic case exceeded its readiness bound while cold
debug compilation was running concurrently; preserve
`/tmp/motor-helix-ra-tui-semantic.log` and `/tmp/motor-helix-lsp.ODuOLi/`.
Review also found the new harness was not consuming terminal redraws while
observing the LSP log, which can block the editor on the harness's output pipe.
Drain terminal output during that wait and run VM gates after compilation,
with all original bounds unchanged.

Native semantic acceptance now passes with the shipped configuration and
launcher (`/tmp/motor-helix-ra-tui-final.log`, evidence directory
`/tmp/motor-helix-lsp.qDGVp8/`). It opens a path containing spaces, renders
server hover documentation, jumps to a local module, requests and accepts a
completion, saves a deliberate type error, displays rustc E0308, saves the fix,
observes empty diagnostics, verifies the exact saved source, navigates into
Motor std, and shuts down the server without leaving a process behind.

Two harness assertions needed correction after successful native operations:
the diagnostics picker redraw styles its padding separately, and the terminal
status bar truncates long std paths before the filename. Wait for restored
source text in both cases and separately assert the full std URI in the LSP
log. Evidence is retained in `/tmp/motor-helix-lsp.A4Bqks/` and
`/tmp/motor-helix-lsp.DXSJxa/`; no deadlines, retries, or failures are relaxed.

The pinned server logs the already-known Lorry version-string warning. It
also requests `workspace/diagnostic/refresh`, which this Helix revision rejects
with the LSP method-not-found response; push diagnostics and their clearing
are proven by the acceptance test. Neither requires a fork change.

Full gates use their existing time limits, with the six main
logs named `/tmp/motor-helix-ra-main-{debug,release}-{1,2,3}.log` and the developer
log `/tmp/motor-helix-ra-full-dev-release.log`. The ordered status record is
`/tmp/motor-helix-ra-gates.log`.

All three debug gates passed (2026-09-10 06:24:46, 06:36:12, and 06:47:33 UTC),
including the new framed-pipe regression. The first release gate failed:
after `test_all_cpu_fault_storm PASS`, the aggregate listener-exhaustion case
did not complete; sys-io exited with status `0xffffffff`, and the enclosing
suite reached its unchanged 900-second deadline. No later gates were started
by that batch. Preserve the failed main image as
`vm_images/release/motor-os-helix-forensics.qcow2` and the release-1 log.

Continue diagnosis under the user override. The existing standalone listener
probe succeeds on a fresh 1 GiB release VM (`/tmp/motor-helix-ra-listener-probe.log`).
A temporary admission-only entry failed its recovery baseline on the otherwise
cold VM; it has been removed. The original native systest sequence is being
run in a separate image with temporary fault-only kernel serial reporting to
capture the crash location. Those diagnostics are not production changes and
must be removed before final gates and commits.

The unchanged native systest sequence passed in the diagnostic image
(`/tmp/motor-helix-ra-systest-diagnostic.log`). Motor's `abort_internal()` exits
with `-1`, which the runtime forwards as `0xffffffff`; this was an explicit
abort, not the kernel's `u64::MAX` main-thread fault status. Temporary abort
stack reporting then covered eight successive cycles of the existing listener
probe, stopping on any failure. All eight completed with clean OutOfMemory
refusals and recovery (`/tmp/motor-helix-ra-listener-soak.log`). The original
abort has not reproduced and its root cause remains unresolved. It is not
counted as a successful gate or dismissed as external networking.

All diagnostic source edits were removed, with exact diffs checked for the
kernel and systest entry point. Continue the required release gates as runs
2–4, stopping on any failure, followed by the developer gate. Their ordered
status log is `/tmp/motor-helix-ra-release-gates.log`. The first failure and
all diagnostic evidence remain visible rather than being overwritten.

The main-image requirement is complete: release runs 2, 3, and 4 passed at
16:26:31, 16:34:46, and 16:43:01 UTC on 2026-09-10, alongside debug runs 1–3.
Every run reports `process::framed_stdio_test PASS` and the full-system PASS
marker. The runtime fix and regression are committed as `69cc04f2`.
The release developer-image gate is now running with the final implementation.

That developer-gate attempt passed the full native Helix scenario again
(`/tmp/motor-helix-lsp.POD32i/`), then stopped in the existing offline patched
`url` tests: the host Cargo cache lacked pinned `bencher 0.1.5`. Prepare the
`url` and `inventory` test dependencies with a separate `cargo fetch --locked`
step. Only `/home/posk/.cargo` is populated; checksums confirm that both managed
manifests and lockfiles are unchanged. Offline fetch checks also pass for the
host target. Tests retain `--locked --offline`; no online test fallback is added.
The restarted developer gate is logged at
`/tmp/motor-helix-ra-full-dev-release-prepared.log`.

The prepared attempt passed the native `url`, `inventory`, and command-format
tests, then found missing `futures 0.3.33` in the native resource sampler's
separate lock graph. Fetch that graph explicitly and preflight the sampler,
Lorry, metadata-schema, native-fixture, and proc-macro-fixture lockfiles with
offline fetch for both Motor and Linux. All resolve without lockfile changes;
the sampler's offline Motor build passes in 5.19 seconds
(`/tmp/motor-helix-ra-native-sampler-build.log`). The complete, unchanged gate
is running again at `/tmp/motor-helix-ra-full-dev-release-final.log`.
