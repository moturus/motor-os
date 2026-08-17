# Motor curl implementation plan

Status: implementation in progress

## Scope

Implement `src/bin/curl` as the curl-compatible HTTPS transport used directly
by Lorry. `src/bin/lorry/curl-interaction.md` is the normative behavior and
security contract. The implementation remains an independent package so its
Rustls and patched-ring graph does not enter core Lorry.

The supported surface is intentionally closed: public HTTPS GET over blocking
HTTP/1.1, the long options Lorry passes, the four required write-out variables,
curl-style help/version diagnostics, and the documented transport exit codes.
Unsupported options and protocols fail explicitly.

## Incremental patches

1. Package and pure parsing core.
   - Pin the reviewed Rustls, rustls-pemfile, getrandom, moto-rt, and ring
     sources.
   - Add a strict argument parser, HTTPS URL/authority parser, request target
     rendering, redirect URL resolution, and curl exit-status/error model.
   - Cover parser success, malformed URLs, user information, IPv4/IPv6,
     unsupported options, and configuration invariants with unit tests.

2. HTTP/1.1 response and write-out core.
   - Render the fixed GET request and bounded headers.
   - Strictly parse status/header blocks, content-length, chunked bodies,
     connection-close bodies, interim responses, and redirect metadata.
   - Stream body bytes without retaining the response and implement
     `response_code`, `url_effective`, `redirect_url`, `size_download`, and
     `%{stderr}` expansion.
   - Unit-test framing, truncation, malformed responses, write failures, and
     write-out validation.

3. Rustls transport.
   - Load an explicit CA bundle or the platform trust-bundle location, install
     the ring provider, register Motor's random callback, resolve DNS, and
     connect with bounded deadlines.
   - Enforce TLS 1.2/1.3, HTTP/1.1, hostname verification, total timeout, and
     low-speed stall timeout.
   - Map URL, DNS, connect, local-write, timeout, TLS, certificate, CA-file,
     send, and receive failures to the documented curl-compatible statuses.

4. Deterministic host conformance.
   - Run a local Rustls server with fixed test credentials.
   - Exercise content-length, chunked, close-delimited, empty, redirect,
     malformed, truncated, timeout, certificate, hostname, stdout/stderr, and
     write-out cases.
   - Compare the supported normalized behavior with installed upstream curl
     where both clients accept the same operation.

5. Motor build and full-test integration.
   - Add curl to the root build, clippy, image, and full-test paths.
   - Reuse the verified Stage-2 ring seed to provide the manifest's logical
     `.lorry/vendor/ring-0_17_14/source` path for host/cross Cargo builds;
     native Stage-2 builds use Lorry's materialized path directly.
   - Run the same protocol fixtures against `/system/bin/curl` in Motor, including a
     verified HTTPS request and failure classification.

6. Stage-2 closure.
   - Rename the bootstrap lock graph from `lorry-fetch` to `curl` and verify
     the exact reviewed lock identities.
   - Extend Lorry's native gate to build curl on Linux and Motor from the
     system seed and compare clean Cargo/Lorry artifacts.
   - Implement Lorry's direct process/stream invocation, bounded acquisition,
     redirect validation, and fresh-repository curl self-build cycle.

## Validation

Every patch is formatted with nightly rustfmt and introduces no compiler or
clippy warnings. Focused unit/integration tests run in debug and release. Shell
and Python fixtures are syntax-checked where affected. Before each commit,
`src/tests/full-test.sh` and `src/tests/full-test.sh --release` pass three
consecutive times as required by `AGENTS.md`; failures are diagnosed rather
than retried or hidden.
