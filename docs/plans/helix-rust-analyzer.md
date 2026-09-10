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

No external repository, managed toolchain source, `src/bin/lorry`, `src/sys`,
assembly artifact, boot service, or boot-time work is part of this design.
The only native behavior added is loading editor configuration when opening
Helix and starting rust-analyzer for Rust buffers. All acquisition remains an
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

## Implementation and validation record

Packaging: release image build passed (`/tmp/motor-helix-ra-build-release.log`).
Existing developer TUI acceptance, including default Rust server discovery,
passed (`/tmp/motor-helix-ra-tui-package.log`). The example was formatted with
the repository-selected `cargo fmt`; shell syntax and diff whitespace pass.
Native semantic integration acceptance and the full release developer gate
remain the next steps.
