# Lorry contributor instructions

These instructions apply below `src/bin/lorry` and refine the repository-root
Motor OS development guidelines.

- Changes confined to `src/bin/lorry` are gated by `cargo test` and
  `lorry test` in this crate on Linux, and `lorry test` on Motor OS.
- Use focused Rust tests while iterating. Test workspaces are created by the
  tests; do not add shell drivers or freestanding fixture trees.
- Markdown-only documentation changes below `src/bin/lorry` require no test.
- Prefix the subject of every Lorry-related commit with `lorry:`.
- `src/tests/cross-test.sh` proves Cargo/Lorry byte identity on Linux and
  cross/native byte identity on Motor. Lorry's Rust tests do not invoke Cargo.
- A test for Lorry behavior belongs in this crate. `src/tests/full-native-test.sh`
  runs the crate harness and the ignored curl integration tests, with their
  loopback TLS server, on Linux and in both Motor roles. `--full` also selects
  the ignored native Helix build; it does not select all ignored tests.
- `src/tests/full-test.sh` runs the complete system gate, including Lorry.
- If a change also touches a system component such as the kernel, `sys-io`, a
  shared system library, image construction outside Lorry, or the repository
  test harness, follow the verification rule for the broadest affected scope;
  this normally means the repository full debug and release gates.
- Do not weaken a test with retries, ignored failures, or longer timeouts.
  Diagnose the underlying failure.
- The system gate installs the toolchain and uploads sources and dependency
  objects into a disposable standard image. VM/image selection belongs to the
  runners, not Lorry's crate tests. Native tests remain offline.
- New plan docs about lorry should go not in `docs/plans/` but into `src/bin/lorry/`.
- If a pre-existing lorry issue is found, it is in scope - diagnose it and
  fix it as part of lorry work. Non-lorry issues should follow the workspace
  AGENTS.md.
