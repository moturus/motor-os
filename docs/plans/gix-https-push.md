# gix push over HTTPS

Plan, 2026-11-05. Reviewed once: gix keeps no secrets and always asks for the
password or token. Follows `AGENTS.md`: 100–300-line patches with tests, no
commits unless asked. All changes stay in `src/bin/gix`, `src/tests` and
`docs`. Nothing changes in the gitoxide fork, curl, moto-rt, std or
`src/sys`.

## 1. Problem

`gix push` refuses every HTTPS remote, whether it is named on the command line
or configured:

```text
$ gix -r src push https://127.0.0.1:1/repo.git HEAD:refs/heads/main
gix: only SSH URLs are accepted
```

Three pieces are missing:

1. **Transport selection.** `push_policy::remote()` checks the push URL with
   `ssh::Prepared::new()` (`push_policy.rs:138`), which accepts only SSH.
   `push::run()` always builds an SSH transport (`push.rs:37`).
2. **Receive-pack over HTTP.** The curl-backed client admits only the
   upload-pack endpoints and media types (`http_request.rs:18-21`). It also
   caps a request body at 8 MiB, while a push pack may be 128 MiB.
3. **Credentials.** Every HTTPS request is anonymous. Hosted servers such as
   GitHub answer the receive-pack discovery request with 401 when it carries
   no credentials, even for public repositories.

The gix/jj plan lists "HTTPS push" and "Token HTTPS" as separate M4 slices
([jj-gix-workflow.md](jj-gix-workflow.md), section 4). This plan covers both.
It keeps that plan's decision D4: the secret reaches curl through the child's
environment, never through argv, URLs or logs.

## 2. Scope

In scope:

- `gix push` to an `https://` remote, with the same contract as over SSH: one
  explicit ref, the lease rules, `--dry-run` and the same outcome reporting.
- Asking for credentials. When an HTTPS server answers a command's first
  request with 401, gix asks on the terminal for a user name and a password or
  token. It repeats that one request with them and sends them with every later
  request of the same command. Nothing is stored or read from anywhere else,
  so the next command asks again. Clone and fetch ask too: a private
  repository has to be fetched before gix can prove that a push is a
  fast-forward.

Out of scope: credential files, helpers and askpass programs, credentials in
environment variables or URLs, `http.extraHeader`, answers piped into stdin,
prompts in Linux builds, `Bearer` and other auth schemes, a server that asks
for credentials only on the update request, plain HTTP, proxies, chunked
uploads, side-band progress, report-status-v2, push options, and retries of
any other kind.

## 3. Design

### 3.1 Receive-pack through the existing HTTPS client

- `http_request.rs` replaces its four upload-pack constants with one entry per
  Git service. Each entry gives the discovery suffix and media type, the
  request suffix and result media type, and the request-body limit. A `Client`
  serves exactly one service and refuses any URL outside that service's two
  endpoints, as it does today. The redirect policy does not change: same
  origin only, at most 5 redirects, on the discovery GET only.
- Request-body limits: upload-pack keeps 8 MiB. Receive-pack allows the
  128 MiB pack plus one command packet and the flush, 65,524 bytes in all.
- `network::Policy` gets a push constructor next to `transport()`. For SSH it
  builds the transport as today. For HTTPS it builds an `Adapter` for
  receive-pack with `Protocol::V1`. Git itself falls back to protocol v0 for
  push. With V1, gix-transport sends no `Git-Protocol` header, and it reads a
  v0 advertisement as V1.
- `push_policy::remote()` returns the push URL instead of an `ssh::Prepared`,
  checking it with `network::validate_url()` before and after URL rewriting.
  `main.rs` builds the `network::Policy` for push as it already does for fetch,
  so `-c http.sslCAInfo=…` also works for push.
- `push_protocol::finish_discovery()` sends nothing when the transport's
  connection does not persist across requests. Today, over HTTPS, it would
  stage a flush packet that is never sent. With the change, `--dry-run`, a
  no-op push and a lease mismatch make only the discovery GET, as Git's
  stateless send-pack does.
- Outcome reporting does not change. Once the first command byte is written,
  any failure is reported as an unknown outcome. Over HTTPS that is
  conservative, because the command first goes to a staging file.
- Limits and timeouts are those of HTTPS fetch: 30 seconds to connect, 300
  seconds per request, and 30 seconds without progress. The last limit
  includes the time the server spends checking the pack before it answers, so
  a slow server can fail a large push. The request body is staged in `.git`
  next to the pack file, and curl holds the whole body in memory for
  `--data-binary @-`. A 128 MiB push therefore briefly needs twice the pack
  size on disk and the pack size in curl's memory.

### 3.2 Asking for credentials

- **When.** Only when the discovery GET, a command's first request to the
  server, answers 401. Gix asks once and repeats that GET once. A second 401
  ends the command with an authentication failure. A 401 on a later request
  is an ordinary error and never prompts. A local `PermissionDenied`, such as
  an unwritable staging directory, never prompts either: gix marks the 401
  itself.
- **Questions.** `Username for 'https://HOST':` shows what is typed.
  `Password or token for 'https://USER@HOST':` shows nothing.
  Backspace and Ctrl+U edit the answer, and arrow and function keys are
  dropped, as in Lorry's prompts. Enter may arrive as CR, LF or CR LF. An empty
  answer, a user name with `:`, a control character, invalid UTF-8, or more
  than 256 bytes of user name or 4 KiB of password ends the command without
  another request. The error keeps the server's 401 as its cause.
- **Where.** The questions go to stderr. Answers come from stdin when it is a
  terminal, otherwise from the terminal stream on fd 3
  (`moto_rt::FD_TERMINAL`) when the command runs in a terminal session. With
  no terminal, the command fails and says that the server wants credentials.
  Linux builds never ask: a Linux terminal echoes typed input, and the Linux
  build exists for tests.
- **Input.** Motor OS terminals deliver raw keystrokes and echo nothing
  ([tui.md](../tui.md)), so gix echoes the user name itself and the password
  is never shown. Gix waits on a `moto_rt::poll` registry with a short
  deadline and checks its cancellation flag in between. Ctrl+C at a prompt
  therefore ends the command with status 130, as anywhere else. Each read
  stops at the end of the line, as crossterm's line-end reads do, so input
  typed for the next program stays queued.
- **Wire.** `Authorization: Basic base64(USER:PASSWORD)`. Redirects never leave
  the origin, so the header never does either. base64 comes from the `base64`
  0.22.1 crate, which gix already compiles through gix-transport. Adding it as
  a direct dependency downloads nothing new.
- **Into curl.** Gix sets `GIX_HTTP_AUTHORIZATION` in curl's otherwise empty
  environment and passes `--variable %GIX_HTTP_AUTHORIZATION` and
  `--expand-header 'Authorization: {{GIX_HTTP_AUTHORIZATION}}'`. Motor OS curl
  supports both options, and so does host curl from version 8.3 (the host has
  8.5). The secret exists only in gix's memory while the command runs and in
  the environment of its curl children. It never appears in argv, files, logs
  or error messages. The header allowlist still refuses an `Authorization`
  header from gix-transport, whose own credential path stays unused.

## 4. Patches

1. **Service-aware HTTPS client** (about 120 lines). The endpoint table and
   body limits from section 3.1, with unit tests for receive-pack endpoints,
   media types and redirects, and for refusing the other service's URLs.
2. **Anonymous HTTPS push** (about 280 lines). Transport selection, the push
   constructor in `network::Policy`, `finish_discovery()`, `main.rs`, the help
   text and `docs/gix.md`. The `tests/https_server.rs` fixture gains
   receive-pack routes backed by host `git receive-pack --stateless-rpc` on a
   separate push repository. One route makes the server reject
   non-fast-forwards. `test-gix.sh` runs a push lifecycle on the host and in
   the VM.
3. **Terminal prompt** (about 220 lines). The answer editor, the Motor OS
   terminal input, and the refusal without a terminal, in a new module with
   unit tests.
4. **Authenticated HTTPS** (about 250 lines). The 401 flow in the adapter, the
   curl environment and arguments, and fixture routes that demand Basic
   credentials and log whether each request carried them. Host and VM test
   cases, plus `docs/gix.md`, `docs/tools.md` and the M4 entries of the gix/jj
   plan.

## 5. Tests

Unit tests run with `cargo test --lib` from `test-gix.sh --host`. They cover:

- the endpoint table and `finish_discovery()` on a stateless transport;
- the answer editor: echo for the user name only, the editing keys, dropped
  escape sequences, every Enter form, the limits, and refused answers;
- the 401 flow with a scripted prompt: one question, one repeated GET, an
  authentication failure on a second 401, no prompt for a local
  `PermissionDenied` or for a 401 on the POST;
- the curl command: the secret appears only in the environment, never in
  argv.

The fixture cases run on the host against `https://localhost:PORT` and in the
VM against `https://192.168.4.1:PORT`. Host Git and `git fsck --strict` check
each result.

- Create, `--dry-run`, fast-forward, no-op, stale lease, leased rewrite and a
  server-side rejection all behave as over SSH. The fixture log proves that
  `--dry-run`, no-op and stale lease made no POST.
- A configured remote with a `pushurl` pushes to the `pushurl`.
- On the host, and in the VM through a plain `ssh` command without a
  terminal, a push to an authenticating route fails before sending anything,
  and the fixture logs a single unauthenticated GET.

In the VM, through `ssh -tt`, the test answers the questions as a user would:

- a push with the right user name and token succeeds; the terminal shows the
  user name but never the token;
- a wrong token ends with an authentication failure after two GETs and no
  POST;
- Ctrl+C at the password question exits with status 130 and sends nothing;
- a clone of an authenticating route asks once and succeeds.

No test reaches the public network.

Gates for every patch: `test-gix.sh --host`, `cargo fmt`, and clippy with no
new warnings. Patches 2 and 4 also run `test-gix.sh --guest` against a booted
developer image, and the last patch runs `src/tests/full-test-dev.sh
--release`.

## 6. Decisions

- **Resolved 2026-11-05.** No secret handling: gix keeps no credentials and
  always asks for the password or token.
- **Made here, open to review.**
  - Gix asks when the server answers 401, as Git does, rather than before
    every push. Servers such as GitHub answer every unauthenticated push with
    401, so every push to them asks.
  - Answers come only from a terminal: not from piped stdin, and not from an
    askpass program.
  - Linux builds never ask.
  - Clone and fetch ask too.
