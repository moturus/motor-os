# Lorry contributor instructions

These instructions apply below `src/bin/lorry` and refine the repository-root
Motor OS development guidelines.

- Changes confined to `src/bin/lorry` use the Lorry-local verification matrix,
  not `src/tests/full-test.sh`.
- Use `./test-changed.sh --print` to select the required gate mechanically.
  `./test-fast.sh` is the ordinary Lorry-only gate; use `--warm` while
  iterating. Acquisition, archive, redirect, repository, curl, sandbox, and
  policy changes require `./test-acceptance.sh`. Bootstrap, compiler/cache
  identity, native-tool, and Lorry harness changes require
  `./test-exhaustive.sh`.
- The exhaustive gate owns three clean debug and release local passes, then
  the debug and release repository integration campaigns. Do not multiply
  every deterministic build in the fast or acceptance gates by three.
- Cross-host debug Lorry artifacts must build and execute successfully;
  release Lorry artifacts must also be byte-identical.
- Focused unit or contract tests should be run while developing. A test for
  Lorry behavior belongs below `src/bin/lorry`; `src/tests/full-test.sh` may
  invoke a Lorry-owned driver but must not own its implementation.
- If a change also touches a system component such as the kernel, `sys-io`, a
  shared system library, image construction outside Lorry, or the repository
  test harness, follow the verification rule for the broadest affected scope;
  this normally means the repository full debug and release gates.
- Do not weaken a test with retries, ignored failures, or longer timeouts.
  Diagnose the underlying failure.
