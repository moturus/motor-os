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

`--max-active-connections` defaults to 128 and counts HTTP connections, idle
keep-alive connections, and TLS handshakes. Excess connections close immediately.
The HTTP tests exercise admission, rejection, and release with a limit of one.

`--max-header-deadline-sec` defaults to 10. It limits initial HTTP protocol
detection (after TLS handshaking, if enabled), then each HTTP/1.1 header read.
Tests cover idle clients, incomplete HTTP/1.1 headers, partial HTTP/2 prefaces,
subsequent requests on keep-alive connections, and HTTP/1.1 over TLS. The existing
TLS handshake deadline remains separate. HTTP/2 support is preserved: its
connections count toward admission, but complete HTTP/2 stream-header deadlines
are not exposed by the current Hyper API and are not enforced by this flag.
The HTTP/2 tests check both cleartext and certificate-validated TLS, repeat
requests on one connection (including a cache hit), and verify admission limits.

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
with `RUST_LOG=httpd_axum=debug`; `prepare_us` includes cache-fill reads but excludes
streamed body reads and transmission.

The cache is enabled by default: `--cache-timeout-sec=10`, `--cache-size-mb=4`
(MiB). `--cache=off` restores immediate freshness. Files up to 256 KiB are loaded
on demand; larger files stream. Hits retain a snapshot until its load-start-based
deadline, including after file deletion or permission changes. Queries share the
same path entry. HEAD, conditional requests, and ranges use that snapshot.

The budget charges bytes, keys, headers, and an entry allowance; the cache also
caps entry count at 1,024 and concurrent fills at eight (fewer for small budgets).
Oldest inserted entries are evicted first. This bounds retained cache storage,
not total process RSS: active responses can still reference evicted bytes.
`cache_store` and `cache_response` are standalone host/Motor tests. The HTTP test
also checks default caching, disabled caching, expiry, deletion, and large-file
streaming. No cache is populated at server startup.

Set `HTTPD_AXUM_BENCH=1` when running the HTTP test to also report preparation
and complete loopback-request timings with caching on and off. It measures a
256-byte file, 64 samples after four warm-ups, for both burst traffic and requests
spaced 20 ms apart. It drains each debug event immediately. Timings are diagnostic
only; correctness, cache pressure, and concurrent-fill checks remain assertions.

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
