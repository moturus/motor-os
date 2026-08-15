# Lorry contributor instructions

These instructions apply below `src/bin/lorry` and refine the repository-root
Motor OS development guidelines.

- Changes confined to `src/bin/lorry` use `./tests/test-all.sh`, not
  `src/tests/full-test.sh`. The complete Lorry suite has a hard 30-minute
  wall-clock budget and runs each distinct product boundary once.
- Use a focused Rust test or contract while iterating. `./tests/test-all.sh
  --warm` may retain the native fixture's targets between local runs.
- Markdown-only documentation changes below `src/bin/lorry` require no test.
- The release suite must prove Cargo byte identity for a compact native and
  cross-Motor fixture, then prove cross/native Lorry byte identity on Motor.
- Focused unit or contract tests should be run while developing. A test for
  Lorry behavior belongs below `src/bin/lorry/tests`; `src/tests/full-test.sh`
  may NOT invoke a Lorry-owned driver.
- A full system test with lorry is `src/tests/full-test-dev.sh`.
- If a change also touches a system component such as the kernel, `sys-io`, a
  shared system library, image construction outside Lorry, or the repository
  test harness, follow the verification rule for the broadest affected scope;
  this normally means the repository full debug and release gates.
- Do not weaken a test with retries, ignored failures, or longer timeouts.
  Diagnose the underlying failure.
- The native Lorry validation VM image is built via
  `make -j$(nproc) BUILD=release dev.img`; VM/image selection is test
  infrastructure, not Lorry command behavior.
