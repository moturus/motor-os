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

Use fresh guest filenames for each build: Motor's SFTP policy rejects overwriting
an existing executable. Keep the server and its test executable from the same build.

This standalone gate does not build an OS image or invoke the full-system suite.

`--test fs_path` checks the filesystem serving path and reports per-operation
timings, response preparation, and body collection without network I/O. It
compares burst traffic with requests spaced 20 ms apart and reports a batched
filesystem-operation baseline. It uses 64 measured samples after four warm-ups;
latencies are diagnostic and do not determine pass/fail. Run its cross-compiled
executable directly in the VM with `TMPDIR` set to a writable guest directory.

`--test http` launches the server on loopback and checks persistent connections,
GET, HEAD, ranges, conditional requests, traversal rejection, missing files,
immediate visibility of file edits, and default/debug logging. Run it on Motor
with `HTTPD_AXUM_BIN` and `TMPDIR` as above. Startup readiness comes from the
bound-address log, without connection retries. Request timings are available
with `RUST_LOG=httpd_axum=debug`; `prepare_us` excludes body reads and transmission.

The HTTP test also checks two requests on a TLS connection, validating the server
certificate against the bundled localhost test certificate and checking ALPN.
The fixture certificate expires in September 2036. Regenerate it and its DER
copy together with the test-only private key:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout tests/fixtures/key.pem -out tests/fixtures/cert.pem -days 3650 \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost' \
  -addext 'basicConstraints=critical,CA:FALSE'
openssl x509 -in tests/fixtures/cert.pem -outform DER -out tests/fixtures/cert.der
```
