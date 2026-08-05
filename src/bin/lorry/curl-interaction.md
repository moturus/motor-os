# Lorry and curl Interaction

## Decision

Lorry invokes a `curl` executable directly. There is no Lorry-specific fetch
helper, adapter executable, or private helper protocol.

Linux uses an installed upstream curl. Motor OS supplies the independent
`src/bin/curl` package, which implements the curl command-line subset specified
here with standard Rust, `std::net`, and Rustls. Stage-2 Lorry must be able to
build that package natively on Motor OS.

The compatibility target for Linux is curl 7.63.0 or newer. That is the first
release with the `%{stderr}` write-out variable used to keep response metadata
off the body stream. The Motor implementation need not reproduce unrelated
curl features, but every supported option, stream, status, and relevant exit
code below must behave like upstream curl. Unknown or unsupported options fail;
they are never silently ignored.

References:

- <https://curl.se/docs/manpage.html>
- <https://curl.se/docs/optionswhen.html>
- <https://curl.se/mail/archive-2018-12/0012.html>

## Executable selection

- `[network].curl`, when present, is an absolute executable path.
- On Linux, the default is `curl` resolved once through the invoking process's
  `PATH` and converted to an absolute path before the environment is cleared.
- On Motor OS, the default is `/bin/curl`. Curl is a general network utility,
  not part of the Rust toolchain installation.
- Lorry invokes the resolved executable directly with `Command`; it never
  constructs a shell command.
- An upstream curl older than 7.63.0 is unsupported. A compatible
  implementation is accepted based on the behavior of the command below, not
  a Lorry-specific version or capability exchange.

## One request

Lorry issues one HTTP request per curl process. It deliberately omits
`--location`, so Lorry—not curl—owns redirect policy and validates every new
URL before another request starts.

The argument vector is:

```text
curl
  --disable
  --silent
  --show-error
  --globoff
  --http1.1
  --proto =https
  --noproxy *
  --disallow-username-in-url
  --tlsv1.2
  --tls-max 1.3
  --connect-timeout 30
  --max-time 300
  --speed-limit 1
  --speed-time 30
  --user-agent lorry/<lorry-version>
  --header "Accept-Encoding: identity"
  --output -
  --write-out <control-trailer>
  [--cacert <absolute-ca-bundle>]
  --url <validated-url>
```

These are separate arguments; the display above is not shell syntax.
`--disable` is the first option so user and system curl configuration files
cannot affect acquisition. Lorry clears the child environment and supplies
only a deterministic locale. In particular, proxy, netrc, credential, curl
home/config, and TLS environment variables are not inherited.

On Motor OS, Lorry passes
`--cacert /sys/cfg/ssl/ca-certificates.crt` unless
`[network].ca-bundle` supplies another absolute path. On Linux, an explicit
configuration value is passed; otherwise upstream curl uses its compiled-in
system trust configuration.

There is no automatic retry. A failed request fails the transaction, which the
user may restart. This keeps error reporting and transaction behavior
unambiguous.

## Redirect trust

The canonical `index.crates.io` and `static.crates.io` request URLs are initial
destinations, not redirect approvals. Redirect trust is recorded separately as
HTTPS sites. A site is a lowercase host plus a non-default port when present;
HTTPS port 443 is canonicalized away. User information, non-HTTPS schemes,
fragments, malformed hosts, and malformed ports are rejected before trust is
consulted.

Persistent redirect decisions live in a dedicated user state file, never in a
repository-controlled `lorry.toml`:

- Linux: `$HOME/.config/lorry/redirect-sites.toml`
- Motor OS: `/user/cfg/lorry-redirect-sites.toml`

The versioned file contains sorted `allow` and `deny` site lists. Both lists
are initially empty. Conflicting or malformed entries are a hard error. Lorry
locks the file, merges with the latest contents, and replaces it atomically
when an `always` decision is saved.

For an unknown redirect site, Lorry shows the redacted source and destination
URLs and accepts exactly one of four decisions: allow for this operation,
allow always, deny for this operation, or deny always. Operation decisions
remain in memory only. An allow applies to redirect URLs on that HTTPS site;
download limits, index parsing, archive checksums, policy, and transaction
rules still apply. A deny fails the transaction.

Redirect trust is independent of package approval. `lorry vendor --accept-all`
does not approve unknown redirect sites. If prompting is required without a
controlling terminal, Lorry fails before starting the redirected request and
explains how to make an interactive decision. EOF or invalid input defaults to
deny for the operation.

## Streams and control trailer

Curl's stdout contains only the response body. Lorry reads it incrementally
into a privately created, nonexistent staging file and computes the required
digest while reading. Lorry, not curl, owns the file, its permissions, its
limit, and its lifecycle.

The write-out argument begins with `%{stderr}` and emits a trailer of this
form, where the same per-process nonce appears in both marker lines:

```text

LORRY-CURL-1 <nonce>
status=<response_code>
url=<url_effective>
redirect=<redirect_url>
size=<size_download>
END-LORRY-CURL-1 <nonce>
```

Ordinary curl diagnostics precede the trailer on stderr. Lorry drains stderr
concurrently so neither pipe can block, retains at most 64 KiB for a
diagnostic, and requires exactly one well-formed final trailer. Control values
containing control characters, invalid UTF-8, or invalid decimal values are
rejected rather than repaired. The final marker must terminate stderr; bytes
before the opening marker are the bounded human-readable diagnostic and are
not parsed as control data. The reported download size must equal the body byte
count observed by Lorry.

Lorry terminates the child and rejects the response as soon as an
acquisition-specific body limit is exceeded. It does not rely on
`--max-filesize`: older supported curl releases cannot use that option to
bound a response whose size is not declared in advance. Sparse-index and
archive limits remain Lorry policy, and a redirect response body is staged
separately and discarded.

## Result interpretation

- A nonzero curl exit status is a transport failure. Lorry reports the
  bounded curl diagnostic and does not interpret a partial body as a response.
- A zero exit status means that curl completed the transfer; it does not mean
  that the HTTP status is acceptable. Lorry validates the status itself.
- A final successful sparse-index or archive response must be HTTP 200.
- HTTP 301, 302, 303, 307, and 308 may be followed only when the trailer
  contains one valid redirect URL. Other 3xx responses fail.
- Redirects are followed with another GET, up to five hops. Every hop must be
  a valid HTTPS URL without user information or a fragment. Its canonical site
  must be allowed for the current operation or in the persistent allowlist.
  Protocol downgrade, authentication, a redirect loop, a sixth redirect, or a
  denied site fails before curl sees the new URL.
- Other HTTP statuses fail with a diagnostic that names the status and redacts
  URL query data.

Lorry remains responsible for sparse-index parsing, archive checksums, safe
extraction, dependency policy, approval, and repository transactions. Curl
does not receive or interpret a Cargo manifest, lockfile, repository path, or
policy document.

## Required Motor curl subset

The Motor executable implements only what Lorry and its own conformance tests
need:

- the options and long-option argument forms shown above;
- public HTTPS GET over blocking HTTP/1.1;
- CA-file loading, certificate-chain and hostname verification, TLS 1.2 and
  TLS 1.3, DNS, IPv4/IPv6 as supported by Motor, and response bodies framed by
  content length, chunked encoding, or connection close;
- upstream-compatible stdout/stderr separation and write-out expansion for
  `response_code`, `url_effective`, `redirect_url`, and `size_download`;
- upstream-relevant exit codes, including malformed URL (3), name resolution
  failure (6), connection failure (7), local write failure (23), timeout (28),
  TLS connection failure (35), and certificate verification failure (60);
- `--help` and `--version` for ordinary curl-style diagnostics.

Proxying, authentication, netrc, cookies, uploads, compression, HTTP/2,
curlrc files, FTP and other protocols, curl's own redirect following, and
general libcurl compatibility are outside the Stage-2 package. If Lorry later
needs one of them, its addition requires an explicit design and conformance
update.

## Bootstrap and acceptance

The Stage-2 bootstrap acceptance cycle is:

1. A seed curl in the Linux installation and Motor image populates a fresh
   writable dependency repository.
2. Stage-2 Lorry builds `src/bin/curl` on Linux and natively on Motor using
   only the seeded repository and approved native compiler/archiver roles.
3. The produced curl passes Lorry's complete request contract against local
   TLS fixtures. A fail-closed Cargo-cache fixture then serves the canonical
   crates.io URLs while Lorry populates a second fresh repository.
4. Stage-2 Lorry builds the same curl package again from that repository.

The Rustls, `ring` 0.17.14 path patch, Motor entropy callback, and native-tool
graph previously assigned to `lorry-fetch` become the `src/bin/curl` graph;
they do not enter core Lorry.

Repository integration tests use a deterministic local TLS server to cover success, every supported
body framing, malformed HTTP, truncation, body limits, stalls/timeouts,
certificate and hostname failures, redirects, stream separation, trailer
parsing, and exit codes. The same fixtures run against the native Motor
executable. Registry acquisition tests extract only reviewed sparse records
and archives from Cargo's local cache; requests outside that prepared set fail
without attempting Internet access.
