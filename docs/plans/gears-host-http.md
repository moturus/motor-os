# Gears access to a host llama.cpp server over HTTP

Status: implemented; not yet committed.

## Problem and intended behavior

A llama.cpp server normally exposes an HTTP chat-completions endpoint. Gears
can serialize that API, but its network policy permits plain HTTP only for an
explicit loopback test exception. The VM host at 192.168.4.1 is not loopback.
Motor OS curl also accepts only HTTPS and always establishes TLS. Changing
Gears' configuration alone cannot make this connection work.

The Gears README already documents an HTTPS path to a local server using the
in-tree test certificates and `provider.ca_cert`. That path does not cover
this case: the test certificates cover loopback, so users would need to
provide and trust a certificate for their TAP address. llama.cpp can serve
HTTPS directly when built with OpenSSL; a separate TLS terminator is optional
(see [upstream SSL build documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md#build-with-ssl)).
Certificate setup is still more work than the feature is worth for a link
that never leaves the host.

Allow the user to explicitly enable HTTP to their host, then run Gears against
`http://192.168.4.1:8080/v1` without certificates or a TLS proxy. Keep HTTPS as
the default and preserve the existing host egress checks.

## Proposed configuration and security boundary

Add an empty-by-default `net.plain_http_allowlist` containing exact host names
or IP literals, using the existing host validation and matching rules. An
HTTP destination must appear in both this list and `net.egress_allowlist`.
Require the HTTP list to be a subset of the egress list when parsing config;
the error names both keys. A runtime egress grant alone cannot authorize
plaintext transport. Listing the host twice is deliberate: widening reach and
dropping encryption are two separate, visible config edits.

Matching is by host only, as for the egress list. Listing 192.168.4.1 permits
plaintext to any port on the host, not just the llama.cpp port. Document this
in the README next to the setting.

Example `/user/cfg/gears.toml`:

```toml
version = 1

[provider]
base_url = "http://192.168.4.1:8080/v1"
model = "local"
key_file = "/user/cfg/gears/local-llama.key"

[net]
egress_allowlist = ["192.168.4.1"]
plain_http_allowlist = ["192.168.4.1"]

[context]
window_tokens = 32768
output_reserve_tokens = 4096
recent_tail_tokens = 8192
```

Remove the existing `allow_plain_http_loopback` setting and its test helper.
It was inert on Motor OS only because Motor curl refused HTTP; once curl
speaks HTTP it would be a second, undocumented plaintext gate, and
`plain_http_allowlist = ["127.0.0.1"]` says the same thing through the one
documented list. A plaintext `base_url` whose host is not on both lists is
refused when the config loads. No TLS failure may trigger an HTTP fallback.
HTTP sends prompts and any configured bearer token without encryption; the
new host list is the explicit user choice to permit that transport.

Credentials need care because Gears falls back to
`/user/cfg/gears/openrouter.key` when neither the environment nor the config
selects a key. After enabling HTTP to the host, changing `base_url` without
selecting local credentials could send a real OpenRouter key in the clear.
Therefore:

- Gears refuses implicit default-file fallback over plain HTTP. The error
  tells the user to set `provider.key_file` or
  `OPENROUTER_API_KEY`. A key from an explicitly configured file or from the
  environment is sent, including a file explicitly naming the default path.
  This guard distinguishes how the key was selected, not its contents.
- `OPENROUTER_API_KEY` takes precedence over `provider.key_file`, including
  when inherited from the parent shell. The guard does not prevent an
  inherited cloud credential from being sent over HTTP. The README's local
  key-file setup must explicitly run `unset OPENROUTER_API_KEY`; its one-off
  alternative must override the variable for that invocation.
- For an unauthenticated local llama.cpp server, document a non-secret
  placeholder in a separate key file, or `OPENROUTER_API_KEY=local-llama`
  for one-off runs. If server authentication is enabled, supply the matching
  key the same way.

Adding a separate authentication configuration is outside this fix.

Gears passes no `--proto` today, so upstream curl on the host accepts every
protocol it was built with. From this series on, Gears passes `--proto`
matching the scheme of the already-authorized request to both backends. For
HTTPS requests that is a hardening of the host backend independent of the
new feature.

## Incremental patches

Aim for 100–300 changed lines per patch, including tests. Keep all changes
local until a commit is requested.

1. Generalize the Motor curl URL and protocol handling.
   - Rename its URL type to reflect HTTP and HTTPS support. The type is
     public but has no callers outside the curl crate; Lorry's `HttpsUrl` is
     a separate type in its own redirect module and is untouched.
   - Parse both schemes with ports 80 and 443 respectively. Preserve strict
     host, user-information, control-character, and fragment validation.
   - Preserve the current scheme for relative redirect metadata. Curl still
     performs one request and does not follow redirects.
   - Support the explicit protocol sets `--proto =http`, `=https`, and
     `=http,https`. Default to HTTPS only, and reject a disallowed request
     before DNS or TCP work. Cover these cases with unit tests.

2. Add plaintext transfer to Motor curl.
   - Reuse the existing TCP connection, bounded I/O, HTTP request writing,
     response framing, output streaming, and transfer metadata.
   - Perform TLS setup and certificate loading only for HTTPS. Share the
     request/response exchange between the TCP and TLS paths.
   - Add hermetic TCP integration tests for GET, POST, chunked streaming,
     protocol refusal, and truncated responses. Keep the existing TLS and
     certificate-failure tests as regression coverage.
   - Update curl help, version protocols, and crate description.

3. Enable explicitly configured HTTP hosts in Gears.
   - Parse and validate the new host list, wire it into `EgressPolicy`, and
     retain default refusal and exact matching.
   - Pass `--proto` matching the request scheme to both upstream curl and
     Motor curl.
   - Refuse implicit default-file fallback over plain HTTP, as described
     above.
   - Test default refusal, the host address 192.168.4.1, unlisted hosts,
     subdomains, inconsistent lists, implicit default-file refusal, and
     existing loopback behavior. Test that an environment key overrides an
     explicit key file and that unsetting the variable selects that file.
     Use non-secret fixture keys and verify the credential actually sent.
   - Add a provider regression that streams a completion through the actual
     in-tree curl binary built for the host, rather than an argv-only stub.

4. Add a plain-HTTP mode to the mock provider.
   - `src/bin/gears-mock-provider` already serves deterministic SSE
     scenarios, verifies the request path and model, and is installed in the
     development image under `/devtools/tests/gears/`. Extend it rather than
     writing a second fixture.
   - Add an explicit plain mode that serves the same scenarios without
     `--cert`/`--key`, a flag that permits non-loopback connections, and an
     `--expect-model` option so the guest gate checks configuration too. The
     flag must cover all three existing checks: bind address, accepted
     connection destination, and client address. Both flags stay off by
     default so the current loopback-only TLS behavior is unchanged. Refuse
     plain mode on a non-loopback address unless both flags are given.
   - Test the plain mode over a real TCP connection alongside the existing
     TLS test. Cover refusal at each of the three address checks without the
     non-loopback opt-in; the developer-image check must demonstrate that
     both flags permit the guest client and host TAP destination.

5. Document and gate the complete path.
   - Add a short llama.cpp setup to the Gears README: development image,
     host bind address, model alias, context settings, config, placeholder
     key file, explicit environment-key clearing or override, the port
     caveat, and diagnostic/interactive commands.
   - Add a component test entry point called directly or transitively by
     `src/tests/full-test.sh`. The full test currently runs host tests only
     for red, rmux, rush, and russhd; neither curl nor Gears is exercised.
     The new entry point runs `cargo test` for curl, Gears, and the mock
     provider, plus the in-tree curl/provider regression, without external
     network access.
   - Include a release developer-image check that runs guest Gears and guest
     curl against the mock provider in plain mode on the host TAP address.
     It does not require llama.cpp, model files, Python, or Internet access.
     Hook this into the existing developer-image phase of the full test.

## Scope and validation

Implementation is limited to `src/bin/curl`, `src/bin/gears`,
`src/bin/gears-mock-provider`, component test fixtures/harnesses under
`src/tests`, and documentation. There are no changes to `src/sys`,
`src/bin/lorry`, sibling repositories, Rust stdlib, or moto-rt, and no
additional boot work or dependencies.

Use the repository-selected toolchain for formatting, affected-crate host
tests, and clippy. Cross-build curl, Gears, and the mock provider in debug
and release. Run the component regression gate, then
`src/tests/full-test-dev.sh --release` for the actual guest-to-host path and
existing consumers of curl. Developer-image testing remains release-only, as
required for this non-Lorry task.

Tests use local deterministic fixtures. Preserve and diagnose any original
failure; do not add retries, longer timeouts, or weakened assertions. A real
llama.cpp check can supplement these tests if a local model/server is already
available, but is not required for the automated gate.

Acceptance: an explicitly configured guest can stream a completion from the
host over HTTP; unconfigured HTTP remains refused; implicit default-file
credential fallback is refused over HTTP; the documented setup clears or
overrides an inherited environment key; existing HTTPS validation continues
to pass; and the documented user setup requires no certificates.

