# Merge dev into gears and isolate Gears tests

## Scope

Merge local `dev` (currently `99ca2b45`) into `gears` (currently
`63558601`). Preserve dev's build/test refactor and Gears' application changes.
Preserve the existing untracked `external-sources/` directory. Do not edit
external repositories or toolchain sources.

## Implementation

1. Merge without committing, inspect conflicts, and resolve build integration
   using dev's current layout and commands. Keep Gears binaries and configuration
   integrated with the developer image.
2. Move Gears test scripts and Gears-specific assertions out of shared test
   runners into `src/bin/gears/tests`. Remove automatic Gears test invocations
   and preparation from the repository and developer-image suites.
3. Add executable `src/bin/gears/tests/full-test.sh`, callable from the host
   from any working directory, with debug by default and `--release` support.
   Preserve host unit/integration, local mock HTTP, shipped-tool, and batteries
   workflow coverage. Preserve existing VM checks under the Gears directory;
   the standalone runner will build and own a developer VM for those checks,
   using shared VM lifecycle helpers without invoking `full-test-dev.sh` or
   `test-dev-sources.sh`. Move native Gears source-build/test checks alongside
   the other Gears checks, running native source acceptance only in release
   mode per the user's follow-up. Use dev's external-source layout for ripgrep.
4. Update current testing documentation and remove stale Gears test paths.
   Review the resulting merge for accidentally restored obsolete build logic.

## Validation and completion

- Read `docs/build.md` from dev and run `src/build-motor-os.sh` to prepare
  the refactored assembly and images before running tests.
- Check shell syntax and changed-file whitespace; format any Rust changes
  using the repository-selected toolchain.
- Run `src/tests/full-test.sh --release` once.
- Run `src/bin/gears/tests/full-test.sh` once and then with `--release` once.
- Preserve and diagnose failures rather than retrying to obtain a pass.
- Commit the validated merge and test relocation on `gears`; report the merge
  commit and validation results.

The explicitly requested validation replaces the general repeated core-OS
gate for this merge. Gears tests remain manually invoked, as requested, rather
than being transitively included in `src/tests/full-test.sh`.

## Validation status (2026-10-27)

- Merge conflicts are resolved; validation is complete.
- `src/build-motor-os.sh` passed, including all release images and native
  dependency preparation (`build/gears-merge-build.log`).
- The initial system release gate failed on an external Google ICMP timeout.
  A diagnostic host ping and the permitted guest retry to the same IP passed.
  A complete rerun passed (`build/gears-merge-full-release-rerun.log`); the
  original failure remains in `build/gears-merge-full-release.log`.
- The Gears debug host tests and batteries workflow passed. Debug image
  preparation passed. The new VM upload step initially used unsupported Unix
  numeric chmod syntax; it now uses Motor OS's nine-character mode.
- A focused debug VM run exposed an existing approval test's reliance on an
  uninterrupted stderr message. The test now counts actual tool launches and
  stdout approval prompts. The HTTP, approval, and first-run VM checks passed
  with that correction.
- The debug batteries VM workflow exposed a second test-only issue: the debug runtime writes
  filesystem diagnostics to hook stderr, which Gears correctly forwards as
  notices, while the fixture rejects unexpected notices. See
  `build/gears-debug-vm-diagnostic-2.log`. The user approved allowing additional
  informational output. Workflow observers now retain notices for diagnostics,
  reject runtime hook-failure notices, and count expected messages among the
  additional output. State, artifact, execution-count, approval, and provider
  assertions remain. The installed-config check verifies the hook's registered
  command instead of rejecting every `gears:` diagnostic.
- In the corrected full debug run, host tests and the VM HTTP, approval,
  first-run, memory, skills, batteries workflow, and installed-config checks
  passed (`build/gears-full-debug-fixed.log`). The VM stage then hit its 1500s
  limit (exit 124) during native Lorry compilation. Vendoring took roughly
  15 minutes; the build reached the Gears library without a compiler error,
  but native tests and the launch check were not reached. The owned VM and
  overlay were cleaned up; console logs remain in
  `build/gears-vm-debug.MyFyhI`. The user subsequently requested release-only
  native source checks; host and VM workflows remain enabled in both profiles.
- The complete release Gears gate passed (`build/gears-full-release.log`),
  including native build, build-script permissions, native tests, launch,
  and VM teardown. VM logs: `build/gears-vm-release.6ufcGj`.
- Shell syntax, Rust formatting, and diff whitespace checks passed. The
  preexisting kloader `clippy::ptr_eq` warning from dev remains unchanged.
- With the release-only native-source scope implemented, the complete debug
  Gears gate passed (`build/gears-full-debug-final.log`), including host tests,
  VM HTTP and batteries workflows, and VM teardown. VM logs:
  `build/gears-vm-debug.Aihkyu`. The release native commands are unchanged in
  behavior from the passing full release run.
- The merge and Gears test relocation are ready to commit. Earlier failures
  remain recorded above and in their original logs.
