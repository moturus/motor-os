# Component tests

Run the CLI regressions on the host with the repository-selected toolchain:

```sh
cargo test --manifest-path src/bin/httpd-axum/Cargo.toml --release --test cli
```

The test executable also runs directly on Motor OS. Cross-compile it with:

```sh
cargo test --manifest-path src/bin/httpd-axum/Cargo.toml --release \
  --target x86_64-unknown-motor --test cli --no-run
```

Upload the server binary and the test executable printed by Cargo to a writable
temporary directory in an isolated VM. Set `HTTPD_AXUM_BIN` to the uploaded
server's absolute guest path when running the test executable. All tests use
local resources; none contact Internet services.

This standalone gate does not build an OS image or invoke the full-system suite.

`--test fs_path` checks the filesystem serving path and reports per-operation
timings, response preparation, and body collection without network I/O. It
compares burst traffic with requests spaced 20 ms apart and reports a batched
filesystem-operation baseline. It uses 64 measured samples after four warm-ups;
latencies are diagnostic and do not determine pass/fail. Run its cross-compiled
executable directly in the VM with `TMPDIR` set to a writable guest directory.
