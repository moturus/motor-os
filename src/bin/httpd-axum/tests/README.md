# Component tests

Run the complete component gate with cached Cargo dependencies:

```sh
bash src/bin/httpd-axum/tests/run.sh
bash src/bin/httpd-axum/tests/run.sh --release
```

Add `--motor` to cross-compile and run all component tests in a disposable
snapshot of an existing Motor image. It uses the repository's VM lock,
network and SSH helpers, and uploads fresh executable paths. It does not
build an OS image. `HTTPD_AXUM_VM_BUILD=release` selects an existing release
image while testing debug component binaries. Motor runs include real ports
80/443, certificate-validated TLS, HTTP/2 and listener isolation. Failed runs
retain their build artifact list and console log under the printed `/tmp` path.

`src/tests/full-test-dev.sh` runs this driver on the host and in a snapshot of
the developer image, using the suite's selected build profile. The core
`src/tests/full-test.sh` does not run the component gate.
The filesystem workload in `src/tests/stress-soak.sh` launches httpd-axum with
`--cache=off` to preserve its per-GET filesystem coverage.

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

`--max-active-connections` defaults to 128 per listener and counts HTTP connections, idle
keep-alive connections, and TLS handshakes. Excess connections close immediately.
The first refusal logs a warning to stdout identifying the listener and limit.
Further refusals are counted and reported at most every five seconds on a new
refusal. The HTTP tests exercise admission, rejection, and release with a limit of one.

`--max-header-deadline-sec` defaults to 10. It limits the first complete request
head (after TLS handshaking, if enabled), then each HTTP/1.1 header read,
including idle keep-alive time before the next request.
Tests cover idle clients, incomplete HTTP/1.1 headers, partial and complete HTTP/2 prefaces without request heads,
subsequent requests on keep-alive connections, and HTTP/1.1 over TLS. The existing
TLS handshake deadline remains separate. For HTTP/2, the same value configures
the keep-alive PING interval and the PING acknowledgement timeout, including
idle connections. A peer that goes silent after a request closes after about
two such intervals (20 seconds by default), releasing its admission permit.
Responsive peers may keep idle connections open by acknowledging PINGs; this
is not a maximum connection lifetime or a subsequent stream-header deadline.
The HTTP/2 tests check both cleartext and certificate-validated TLS, repeat
requests on one connection (including a cache hit), and verify admission limits.
Raw peers additionally verify silent-peer closure and admission recovery after
a successful request, and reuse after multiple PING acknowledgements, over
both cleartext and TLS.

`--http-redirect-url=https://example.com/landing` enables a separate port-80
listener on the same bind IP; it requires TLS credentials and `--addr` on port
443. Every accepted HTTP request receives 308 with that exact URL as `Location`.
Incoming Host/forwarding headers, paths and queries do not affect the destination.
The configured URL may contain its own port, path, query and fragment; it must
be an absolute HTTPS URL without credentials, with non-ASCII characters escaped.
Without the flag no additional listener opens. Both listeners have independent connection
budgets and use the same header deadline setting, and startup fails if either required port cannot bind.

`--test redirect` checks fixed responses without binding sockets. The `http` test
automatically exercises real ports 80 and 443 on Motor OS, including disabled
redirects, occupied port 80, exact Location, HTTPS content, independent admission and
deadlines. Run that test alone in the disposable VM with those ports free. Host
runs can enable the same checks with `HTTPD_AXUM_REDIRECT_TESTS=1` when the process
has permission to bind both ports; regular host HTTP tests use ephemeral ports.

`--test fs_path` checks the filesystem serving path and reports per-operation
timings, response preparation, and body collection without network I/O. It
compares burst traffic with requests spaced 20 ms apart and reports a batched
filesystem-operation baseline. It uses 64 measured samples after four warm-ups;
latencies are diagnostic and do not determine pass/fail. Run its cross-compiled
executable directly in the VM with `TMPDIR` set to a writable guest directory.

`--test http` launches the server on loopback and checks persistent connections,
GET, HEAD, ranges, conditional requests, traversal rejection, missing files,
immediate visibility of file edits, and default/disabled/debug logging. Run it on Motor
with `HTTPD_AXUM_BIN` and `TMPDIR` as above. Startup readiness comes from the
bound-address log, without connection retries. Requests to both listeners log to stdout at info level by default, including
method, URI, status, and preparation time. Use `--no-request-log` to disable
access logs while retaining startup and overload diagnostics. `RUST_LOG` can
also filter logs; `prepare_us` includes cache-fill reads but excludes
streamed body reads and transmission.

The cache is enabled by default: `--cache-timeout-sec=10`, `--cache-size-mb=4`
(MiB). `--cache=off` restores immediate freshness. Files up to 256 KiB are loaded
on demand; larger files stream. Hits retain a snapshot until its load-start-based
deadline, including after file deletion or permission changes. Queries share the
same path entry. HEAD, conditional requests, and ranges use that snapshot.
Cached responses include `Age` in whole seconds from the start of the load.
Requests with `Cache-Control: no-cache`, `no-store`, or `max-age=0`, or legacy
`Pragma: no-cache`, bypass lookup and storage. Bypass requests see the filesystem
immediately; they do not evict the snapshot used by other requests.

The budget charges bytes, keys, headers, and an entry allowance; the cache also
caps entry count at 1,024 and concurrent fills at eight (fewer for small budgets).
Oldest inserted entries are evicted first. This bounds retained cache storage,
not total process RSS: active responses can still reference evicted bytes.
`cache_store` and `cache_response` are standalone host/Motor tests. The HTTP test
also checks default caching, disabled caching, expiry, deletion, and large-file
streaming. No cache is populated at server startup.

`cache_fill` deterministically appends/truncates files between response metadata
and body collection, checks growth beyond the cache limit, and preserves read
errors. A failed fill returns the original response stream without caching or
refetching it. `rejections` checks overload accounting and warning frequency
without timed sleeps.

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
