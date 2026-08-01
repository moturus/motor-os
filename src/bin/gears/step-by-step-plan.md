# gears: step-by-step plan, from zero to self-hosting

2026-07-31. Status: **plan, revised after review round 1** — all thirteen
review questions answered, plus a follow-up provider-targeting decision
(14); everything is recorded in the decision log at the end and
incorporated throughout. Companion to `proposal.md`, which
remains the governing design document; this plan supersedes only its "First
steps" sequencing. Every other proposal decision (no tokio, sub-agents in
v1, key handling option A, permission gate on the UI side of the bus,
context eviction policy, egress allowlist, validate-before-adopt,
restart-not-exec) stands unchanged.

The restructuring principle, per review direction: **every step is built and
tested on the Linux host**, with OS-specific behavior isolated behind trait
seams and cfg islands. On Linux, gears drives *host tools* as subprocesses —
`curl` for HTTPS+SSE, `cargo` for build/test, `git` for version control — and
the final step swaps in their Motor equivalents: the in-tree `src/bin/curl`
crate as a library, `lorry`, and the portable undo log (with the native
git-format tool deferred past v1). The second-to-last step produces a working
gears binary on Linux, proven by gears working on its own checkout; the last
step is the Motor OS port.

Development posture (decisions 1, 11, 13): work proceeds on the **`gears`
branch**. gears is a **standalone crate**, developed and tested with plain
`cargo test`; it stays **out of `src/tests/full-test.sh` at least until the
Motor OS port is done** — the motor-os workspace supplies context and the
general AGENTS.md rules, nothing more, during the host phase. Everything
gears-related — this plan, the code, the mock, fixtures, docs — is
**confined to `src/bin/gears/`**; a future move to a dedicated repo is
possible (undecided), so self-containment is a design goal, with the known
coupling points called out where they arise (step 10). `proposal.md`'s
pointer to `docs/plans/gears-step-by-step.md` gets a one-line fix to point
here in the first housekeeping patch.

## Strategy: four structural decisions

**D1 — develop on the `gears` branch, starting now.** The proposal gated all
gears work on lorry + curl landing on main. Host-first dissolves that gate:
steps 0–9 use host git/curl/cargo and need nothing from the `lorry` branch.
main is currently 0 ahead / 174 behind `origin/lorry` (a strict superset),
so the eventual integration is a merge, not a rebase problem — and it
becomes a prerequisite of step 10 only. The two workstreams decouple
completely.

**D2 — the HTTP seam is push-based.** `src/bin/curl`'s library is
architecturally *push*: `receive_response(stream, url, output: &mut impl
Write)` writes decoded body bytes into a `Write` sink and returns when the
body ends. A pull-shaped gears trait (returning a `Read` body) would force
inverting that control flow at port time. So the seam is sink-shaped from
day one:

```rust
pub trait HttpSink {
    fn on_head(&mut self, head: &ResponseHead) -> std::io::Result<()>;
    fn on_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()>;
}
pub trait HttpClient {
    // Delivers head then body chunks via the sink; returns after the body
    // completes. A sink Err aborts the transfer (host: kill the curl child).
    fn execute(&self, req: &HttpRequest, sink: &mut dyn HttpSink)
        -> Result<ResponseHead, NetError>;
}
```

Both backends fit this exactly; the step-10 curl-crate extension list falls
out mechanically (a request writer with method/headers/body, and a
head-first streaming variant of `receive_response`).

**D3 — no automatic commits; a per-file undo log is the safety net**
(confirmed, decision 9). gears operates on checkouts the user owns —
including the motor-os repo itself — and silently creating commits there is
invasive. Instead: the automatic safety net is copy-before-first-write per
session under `.gears/undo/<session>/`, restored by an `/undo` command. It
is pure `std::fs`, so the same code is the Motor v1 snapshot story — the
port needs zero VCS work. Agent-visible version control (`git_status`,
`git_diff`, `git_commit`, `git_restore`, `git_log`) sits behind a `Vcs`
trait whose host impl shells out to `git`; commit and restore always pass
the permission gate, and commits happen only when the task calls for them.
The native git-format tool (proposal VCS option B) drops out of gears v1
entirely and stays a separate future deliverable; on Motor v1 the git tools
are simply not registered (a `capabilities()` query on the trait) while
undo still works.

**D4 — in-VM self-build is a manual milestone, not an automated-test item.**
full-test.sh runs under a hard `timeout 600s` (line 10) and the VM gets
1024M (run-qemu.sh). Native rustc + lld building gears' dependency tree
inside that envelope is not a CI bet. Step 10's automated gate is a hermetic
in-VM scenario (fs tools + `run` + a lorry hello-world build against the
in-VM mock); in-VM *self*-build with lorry is a documented manual
validation and the concrete probe for platform ask 1.

**Platform seam idiom.** The seam follows rush/rmux exactly:
`platform/{mod.rs, unix.rs, motor.rs}` where `mod.rs` declares the portable
vocabulary and selects with `#[cfg(unix)] mod unix; #[cfg(not(unix))] mod
motor;`, both backends exporting the same names. The discriminator is
`cfg(unix)` / `cfg(not(unix))`, **not** `target_os = "motor"` — Motor sets
no target family, so `unix` is simply never true there (documented in
`rmux/src/sys/mod.rs`). Small inline `#[cfg(target_os = "motor")]` islands
are used only where the diff is a couple of lines (the russhd/red idiom,
e.g. red's three-arm config-path cfg at `red/src/config.rs:38`).

## Crate conventions and layout

Standalone crate (there is no workspace): own `Cargo.toml`, committed
`Cargo.lock`, `.gitignore` with `/target`. Edition 2024, `license = "MIT OR
Apache-2.0"`, the common release profile block verbatim (`panic = "abort"`,
`lto = "fat"`, `strip = true`, `codegen-units = 1`), `lib.rs` + `main.rs`
split so integration tests can `use gears::…` and locate the binary via
`env!("CARGO_BIN_EXE_gears")`.

Dependencies for the entire host phase: `serde` (derive), `serde_json`,
`toml` (decision 3), and unix-only `libc` (the rush precedent). Nothing
else; no clap (hand-rolled args, the red/rmux dependency posture), no
tokio, no crossterm until the post-v1 TUI (decision 4).

Module layout (each module appears in the step that introduces it):

```
src/bin/gears/src/
  main.rs  lib.rs  cli.rs  config.rs  trace.rs
  platform/{mod.rs, unix.rs, motor.rs}
  net/{mod.rs, host_curl.rs, sse.rs, motor_curl.rs (step 10)}
  provider/{mod.rs, types.rs, assembler.rs, openai_compat.rs, key.rs, usage.rs}
  tools/{mod.rs, fs.rs, run.rs, toolchain.rs, fetch.rs, vcs.rs, spawn.rs}
  agent/{mod.rs, bus.rs, turn.rs, gate.rs, session.rs, prompt.rs,
         undo.rs, harness.rs, context.rs, registry.rs}
  ui/{mod.rs, repl.rs, terminal.rs}
  mock/{mod.rs, server.rs, scenario.rs}   # in-VM mock-openrouter in step 10
```

Per-workspace state lives in `<workspace>/.gears/{sessions/, undo/,
permissions.toml, candidates/}` (decision 8) — excluded from the fs tools'
view and from `list_dir`/`grep` by default; user docs say to gitignore it.

### Host ↔ Motor mapping

| Seam | Linux host (steps 0–9) | Motor OS (step 10) |
|---|---|---|
| `HttpClient` | host `curl` subprocess | `src/bin/curl` crate as a path dep |
| `Toolchain` | `cargo` subprocess | `lorry` subprocess |
| `Vcs` | host `git` subprocess | not registered in v1 (undo log covers safety) |
| undo log | `std::fs` copy | same code, unchanged |
| process control | `libc` kill / waitpid | moto-sys (rush `sys/` reference) |
| interrupt | SIGINT → AtomicBool | in-band 0x03 in the stdin reader |
| config path | `~/.config/gears.toml` | `/user/cfg/gears.toml` (red's three-arm cfg) |
| test mock | plain HTTP on loopback | mock-openrouter in the VM: TLS on loopback |

## The steps

AGENTS.md applies as general discipline: patches are 100–300 loc *including
tests*, sparse comments, no retries or workarounds that can conceal
defects. Per decision 11, gears' tests run via `cargo test` in the crate —
**not** via full-test.sh — until the Motor port; full-test integration is
step-10 work. The proposal's hermeticity rule still binds gears' own test
suite from step 1: **`cargo test` never talks to a real model provider**;
real-key paths are manual and documented. Patch counts below are estimates,
honest but not contractual.

### Step 0 — skeleton, config, platform seam, trace (3 patches)

Goal: a buildable, testable crate with the seams everything else hangs on.

* Crate skeleton per the conventions above; hand-rolled arg parsing in
  `cli.rs` (`--version`, `--help`, `--config PATH`, `--workspace DIR`).
* `config.rs`: `ConfigV1` via serde derive + `toml::from_str` — the russhd
  idiom verbatim (`version` field that must be 1, `#[serde(default)]` on
  optionals, a separate validation pass). Config path per red's three-arm
  cfg. The **egress allowlist field exists from day one**, shipping as
  `["openrouter.ai"]`, so later steps extend the schema compatibly.
* `platform/` seam declared with compiling `unimplemented!()` stubs in
  `motor.rs`; the unix backend gets the SIGINT → `AtomicBool` interrupt flag
  (sigaction via libc, the rush `signal.rs` idiom) that the REPL consumes in
  step 4.
* `trace.rs`: a small leveled file logger (`--log-file`/config; no `log`
  crate) with a redaction hook that step 2 registers key material into. An
  agent harness is undebuggable without a wire log.
* Housekeeping: fix `proposal.md`'s plan pointer to name this file.

Patches: (1) crate + smoke integration test (`gears --version` via
`CARGO_BIN_EXE_gears`) + the proposal pointer fix. (2) config + tests
(parse, defaults, unknown-version rejection, allowlist present).
(3) platform seam + trace + interrupt flag + tests.

Exit: `cargo test` green in the crate. Compiling `motor.rs` under the Motor
toolchain is *not* required until step 10.

### Step 1 — HTTP transport and SSE (4 patches)

Goal: `HttpClient`/`HttpSink` per D2, a host implementation over the host
`curl` binary, and a fully unit-tested incremental SSE parser.

`net/host_curl.rs` spawns curl with a fixed argv shape:

* `-q` **first** (ignore `~/.curlrc` — hermeticity), then `-sS -N -i
  --http1.1 --noproxy '*' -H 'Expect:' -H 'Accept-Encoding: identity'
  --connect-timeout N --max-time N --speed-limit 1 --speed-time 90`.
  `--http1.1` pins the head format and matches the Motor crate's
  HTTP/1.1-only behavior; `Expect:` suppresses `100 Continue` interim heads;
  identity encoding matches the crate; curl de-chunks, so the sink sees
  decoded bytes on both platforms. No `--fail`: 4xx/5xx JSON bodies are the
  error taxonomy's input. The 90 s stall window is safe because OpenRouter
  emits `: OPENROUTER PROCESSING` comment keep-alives during long thinks.
* POST bodies stream to the child's stdin via `--data-binary @-`.
* The API key never touches argv or disk: `--variable %OPENROUTER_API_KEY
  --expand-header 'Authorization: Bearer {{OPENROUTER_API_KEY}}'`, with the
  key only in the child's environment. Requires curl ≥ 8.3 (2023); on older
  curl, error out with a clear message — an acceptable dev-host requirement
  for a host-only code path.
* Status line + headers parsed incrementally from the child's stdout until
  the blank line → `on_head`; remainder → `on_chunk`. stderr drained on its
  own thread (pipe-deadlock hygiene). curl exit codes (6 DNS, 7 connect, 28
  timeout, 18 partial…) map to typed `NetError`s carrying stderr text.
  Cancellation = sink returns `Err` = kill the child.

`net/sse.rs` is pure and incremental: blank-line event boundaries, CRLF and
LF, multiple `data:` lines joined with `\n`, `:` comment lines dropped,
`[DONE]` sentinel, partial events and split UTF-8 held across chunk
boundaries. This is the project's highest-value unit-test surface, and its
test corpus is written as a **generic harness over the `HttpClient` trait**
so step 10 reruns the identical corpus against the Motor impl.

`mock/server.rs`: a `std::net::TcpListener` on a thread serving scripted
plain-HTTP responses with paced, deliberately fragmented writes (mid-token,
mid-event, mid-UTF-8 splits). Plain HTTP is permitted by the *host* client
for loopback only, and that carve-out lives in the unix impl so it cannot
leak into the Motor build. **`mock/` stays std-only throughout** — a hard
requirement, since per decision 12 it must build for Motor in step 10.

Patches: (1) `net/mod.rs` types + traits + error taxonomy + head-parser
tests. (2) `host_curl.rs` + child lifecycle + tests. (3) `sse.rs` +
exhaustive tests. (4) mock server + integration tests: happy stream, slow
stream, mid-body disconnect, non-200 with body preserved.

Exit: a fragmented SSE body streamed through subprocess curl reconstructs
the exact event sequence; a mid-stream disconnect surfaces as a typed error.

### Step 2 — provider: the OpenAI-compatible client and keys (4 patches)

Goal: `ModelProvider` (the proposal's trait) producing a typed `Completion`
from a streamed chat request; the manual real-key path.

* The wire target is the **OpenAI-compatible chat-completions dialect, not
  any one vendor** (decision 14). `provider/openai_compat.rs` is a generic
  client over `HttpClient` with configurable `base_url`, key, and model
  string. **OpenRouter is the blessed default endpoint** — the one manually
  validated with real keys; other compatible endpoints (HF router,
  vLLM/Ollama, DeepSeek, …) are config-only and documented as untested.
  Endpoint-specific behavior lives in a small quirk table, not in the
  client: how usage is requested (OpenRouter's `"usage": {"include": true}`
  vs. the generic `stream_options: {"include_usage": true}`) and whether a
  `cost` field exists.
* `provider/types.rs`: `ChatRequest`/`ChatMessage`/`ToolSpec`/`Completion`
  with serde derive; `serde_json::Value` passthrough for provider-specific
  fields (proposal decision 4). Requests set `stream: true` plus the quirk
  table's usage knob. **Parsing is tolerant by rule**: unknown delta fields
  are preserved through the passthrough, and `reasoning` deltas — the
  dialect's leakiest spot — are passed through and rendered when present,
  never required.
* The delta assembler: content deltas, **index-keyed tool-call fragment
  assembly** (id/name in the first fragment, argument strings accumulated,
  parallel calls interleaved), `finish_reason`, the final usage chunk.
  `usage.rs` accumulates tokens and cost per agent (USD when the endpoint
  reports `cost`, token counts otherwise — decision 10); step 7's budgets
  need this, so it lands here.
* Error taxonomy: 401/402/429/5xx with parsed error body, mid-stream
  `error` events, disconnect, stall. **No automatic retry anywhere**
  (decision 7): errors surface in the REPL with manual re-send. A single
  visible reconnect on transient failures is parked for a later revisit.
* Key handling option A: key file at `~/.config/gears/openrouter.key`
  (host) / `/user/cfg/gears/openrouter.key` (Motor), `OPENROUTER_API_KEY`
  env override (decision 5 — the name stays even for non-default
  endpoints); redaction registered with `trace.rs`; the fs tools'
  deny-list (step 3) includes the key path. The key is handed to the
  transport via `HostCurl::with_secret` and injected into the **curl
  child's** environment only: gears must never hold it in its own
  environment, because every other process it spawns — cargo, git, and
  whatever the model asks `run` to execute — would inherit it there
  (established in step 1). Pointing `base_url` at a
  non-default host means adding that host to the egress allowlist —
  enforcement stays in the one `net` layer.
* `gears ask -m MODEL "…"` one-shot subcommand for manual real-key spot
  checks — never part of `cargo test`. There is **no default model**: `-m` or
  `provider.model`, else an error naming both — inventing a model id that may
  not exist at the user's endpoint helps nobody.
* Two things the binary-level redaction test needs, and later steps need too:
  a **`[net] allow_plain_http_loopback` config knob** (loudly documented as
  test-only; the mock endpoint is plain HTTP on loopback, and step 4's and
  step 9's end-to-end tests drive the *binary*, not a library seam), and
  **redaction that does not depend on logging being on** — the secret registry
  moves out of `Tracer` into a process-global one, with `trace::scrub` applied
  to user-visible error text, since an endpoint quoting the key back in a 401
  is the realistic leak.
* Key handling options B and C, plus the config schema so far, are written up
  in `README.md` — the user-facing doc the proposal asks for.

Patches: (1) types + golden-JSON serialization tests + tolerant-parsing
tests (unknown and `reasoning` delta fields survive). (2) delta assembler
(`assembler.rs`, its own file — it is the bulk of the dialect) + `usage.rs`
+ tests incl. parallel tool calls. (3) `openai_compat.rs` + quirk table
against mock scenarios (scripted completions incl. tool calls, plus every
error path). (4) key loading (`key.rs`) + redaction + `ask` + the redaction
test: run a scenario with a fake key and grep **every artifact gears wrote**
(log, stdout, session) for it.

Exit: mock-driven `ask` returns assembled text; two parallel tool calls
survive with argument JSON intact; unknown/reasoning delta fields cause no
breakage; the fake key appears in no artifact.

### Step 3 — fs tools (4 patches)

Goal: `read_file`, `write_file`, `edit_file`, `list_dir`, `grep` as pure,
gate-agnostic library functions, plus the registry/schema machinery.

* `tools/mod.rs`: tool specs with hand-built JSON-schema `Value`s, registry,
  dispatch by name with serde_json argument decoding; malformed arguments
  return to the *model* as error-flagged tool results, not process errors.
  **Byte-capped head+tail output truncation with elision markers exists from
  the first tool** (one `cargo build` stderr can flood the context), with
  per-tool caps.
  Each tool declares `mutates()` next to itself, since only the tool knows,
  and step 4's gate is the consumer.
* `tools/fs.rs`: workspace confinement — `..` refused lexically, then the
  *deepest existing ancestor* canonicalized and prefix-checked, which covers
  a file about to be created as well as one that is already a symlink out;
  deny-list (key file, `.gears/`); `edit_file` is unique-string replace,
  erroring with the occurrence count on 0 or >1 matches; `list_dir`/`grep`
  skip `.git/`, `target/`, `.gears/` by name, so an explicit path into one
  still works; non-UTF-8 content handled lossily with a marker.
* Two things the tests taught, recorded because they generalize: **the
  deny-list must hold for tools that walk the tree themselves**, not only
  for `resolve` — until `grep` consulted it, the key file was greppable
  though unreadable — and a capped result says how much it dropped
  (`[N of M matches shown]`, the elision marker) rather than looking
  complete. `list_dir` still *names* a denied file: its existence is not
  the secret, its contents are.
* `grep` is a literal search, not a regex — the dependency posture — with a
  `*`-only include glob (`*.rs`), symlinks never followed (cycle guard and
  second line of defence at once), and binary files skipped on a NUL scan.
* Not here: copy-before-first-write. The undo log is agent-layer work
  (step 4, per D3), which is also where the permission gate that shares its
  view of "this call mutates path P" lives.

Patches: (1) registry + schemas + dispatch + truncation. (2) workspace
confinement + the symlink- and `..`-escape corpus. (3) read/write/edit/list
+ tests. (4) grep + ignore rules + `tests/tools.rs`: every tool, by name,
against every escape.

Exit: no path outside the workspace is readable or writable through any
tool, including via `..` and symlinks; `edit_file` refuses ambiguity.

### Step 4 — agent core at N=1 (7 patches; the product exists after this)

Goal: a line REPL where a mock-driven (or, manually, real) model reads,
edits, and creates files under permission.

* `agent/bus.rs`: typed events over std mpsc (`Token`, `Reasoning`,
  `ToolStart`/`ToolEnd`, `Permission{reply}`, `Notice`, `Failed`, `TurnEnd`,
  `Exit`); the single UI thread owns stdout. Two things the wiring wanted:
  the bus carries a per-agent **`Cancel` handle** checked alongside the
  process-wide interrupt flag — step 7 cancels a sub-agent without touching
  its parent, and it also makes cancellation testable without signals — and
  `TurnEnd` carries `ok`, which is how the one-shot mode gets an exit code
  without a second channel.
* `agent/turn.rs`: the classic loop — send conversation + schemas, stream
  the reply, if tool calls: gate → execute **all calls in order** → append
  results → repeat; otherwise yield. Two invariants hold however a turn ends,
  because the session is written as it goes and a malformed transcript cannot
  be resumed: **every tool call is answered** — denied, failed and cancelled
  calls included — and a cancelled or failed turn leaves the conversation at
  a point the model can be asked from again (the partial assistant turn is
  dropped). A `max_steps` cap stops a model that calls tools forever.
* `agent/gate.rs`, on the UI side of the bus (proposal decision):
  approve / deny / always-allow, persisted to `.gears/permissions.toml`,
  keyed by tool name plus the command word for `run` — a `permission_key()`
  on the `Tool` trait, since only the tool knows. The gate exposes
  `known()`/`remember()` as well as the closure-shaped `decide()`: the
  terminal cannot lend its renderer to a closure while the gate is borrowed.
  A config `permissions.mode = "auto-approve"` exists **for tests only**,
  loudly documented — without it no scripted end-to-end can run (and neither
  can step 9's hermetic self-host test).
* `agent/session.rs`: JSONL with a `meta` header record (gears version,
  model, workspace) and the rule *unknown record types are skipped* —
  step 9 restarts a new binary into a session written by an old one. Lines
  that are not readable at all are counted too, since an append-only file
  whose writer was killed ends in half of one. Single-writer via an
  `O_CREAT|O_EXCL` pid lockfile with stale detection (flock does not exist on
  Motor), which needed `platform::process_alive` — where the trap is that
  `kill(0, …)` addresses a *process group*, so a lockfile naming pid 0 is
  junk rather than an owner. `--resume <id>`.
* `agent/prompt.rs`: system-prompt assembly — identity, tool guidance,
  workspace path, platform note, and ingestion of the project's
  `AGENTS.md`/`CLAUDE.md` as project context. gears working on motor-os
  must see the 100–300 loc rule and the testing discipline. The prompt is
  *recorded in the session* and replayed on resume rather than rebuilt: what
  was sent is what is sent again.
* `agent/undo.rs`: copy-before-first-write per session (D3) + `/undo`. It
  lives in the agent layer but is called from `Workspace::before_write`, the
  last place that knows a file is about to change; a snapshot that cannot be
  taken **stops the write**, since writing anyway would leave the user with
  no way back and no warning.
* `agent/harness.rs`: the assembly — workspace, session, undo log, tool
  registry, conversation and provider, handed to one agent thread. The UI
  keeps the two ends of the bus and the objects that are the user's rather
  than the model's.
* `ui/repl.rs` (renderer + event loop) and `ui/terminal.rs` (the interactive
  half): prompt, streamed tokens, y/n/a permission prompts, slash commands
  (`/status` with tokens + cost, `/undo`, `/help`, `/quit`), `-p "<prompt>"`
  one-shot non-interactive mode, ^C via the platform interrupt flag — first
  ^C cancels the in-flight turn (sink aborts → curl child killed), second ^C
  at idle exits. A one-shot run has nobody to answer a permission question,
  so it denies and says so; the model is told in the tool result.

Patches: (1) bus + events + renderer + event loop over scripted events.
(2) turn loop wired to provider + tools, tested against a scripted provider.
(3) gate + persistence + `permissions.mode`. (4) sessions + resume + lock +
forward-compat tests. (5) prompt + undo log + the `Workspace` hook.
(6) harness + terminal + `main` wiring + `-p`. (7) end-to-end over the built
binary: create and edit files, assert the tree, the session records and the
undo manifest; a mid-stream cut and a real `SIGINT` both leave a resumable
session; `--resume` picks it up.

One thing the tests taught, recorded because it generalizes: **the smoke
tests had to be made hermetic against the developer's own key**. With a key
in the environment a bare `gears` now opens a session and waits for a prompt
instead of exiting, so a test that ran the binary bare would hang rather than
fail. Every test that runs the binary removes `OPENROUTER_API_KEY` and names
its own config.

Exit: the e2e passes under `cargo test`; manually, gears with a real key
completes a small multi-turn file task.

### Step 5 — run / build / test / fetch tools (3 patches)

Goal: process-running tools and the `Toolchain` seam — everything step 9
needs to build gears with cargo.

* `tools/run.rs`: `std::process::Command` through the platform seam, which
  owns the parts that are genuinely platform-specific — `spawn` (unix: the
  child leads a **process group of its own**, so a timeout reaches the whole
  tree; `cargo` spawns `rustc`, and killing only what gears spawned leaves it
  behind), `kill_tree` (libc `killpg`, the rush idiom) and `status_text`
  (only unix has "killed by signal"). The deadline loop itself is portable
  `try_wait` + sleep and stays in the tool, since duplicating it in
  `motor.rs` would buy nothing. Both pipes are drained by threads as they
  fill — a command whose output nobody reads blocks on a full pipe and never
  reaches its timeout — into a bounded head-and-tail capture with an exact
  elided count, sized so both ends *and* the marker stay under the tool's
  result cap: otherwise the registry elides a second time and reports a byte
  count that is not the one really dropped. Per-call timeout argument with
  config defaults in a new `[tools]` section.

  There is **no shell**: a command is a program plus an argument vector.
  Nothing to quote, no second interpreter between the question the user was
  asked and what runs, and no assumption that Motor OS has a shell at all.
  A non-zero exit is **not** a tool error — a failing build is the feedback
  signal — so `is_error` keeps meaning "the tool could not do its job", and
  the first line of the result says how the command ended.

  Two things this step deliberately does *not* do. A `^C` does not stop a
  running command: the child is in its own process group, so the tty cannot
  reach it, and the process-wide interrupt flag is the wrong thing for a
  tool to poll (it would also race gears' own tests). Killing a running tool
  is step 7's job, where per-agent abort flags arrive and have to work on
  Motor OS, which has no signals to deliver either way. Until then a command
  runs to its timeout and the turn is cancelled when it returns.
* `tools/toolchain.rs`: `Toolchain` trait — `name()` plus the whole argument
  vector for a `Build`/`Test` action over an options struct that includes a
  **target-dir override** (step 9 depends on it) and `offline` (which is what
  keeps the tests hermetic). `CargoToolchain` relays rustc stderr verbatim
  (the proposal's feedback-signal posture, ready to switch to lorry's
  structured diagnostics when that lands) and passes `--color=never`, since
  what reaches the model should be text. `LorryToolchain` is *not* written
  here: its command line cannot be checked against anything until lorry is in
  the tree, and guessing it would be fiction with tests around it. It lands
  in step 10, where `toolchain::host()` grows its Motor arm.
* `tools/fetch.rs`: GET through `HttpClient`; hosts on the config allowlist
  pass, anything else goes through the permission gate. This is the tool that
  made the gate per-call: a `Tool::gated(args)` alongside the static
  `mutates()` (which stays, because it is what step 7's read-only sub-agents
  filter on). `fetch` changes nothing and still asks. Consent then has to
  reach the transport, since egress is enforced in `EgressPolicy` and nowhere
  else — hence `Tool::approved(args)`, called by the turn loop when the gate
  says yes, and `EgressPolicy::grant`, shared by a policy and its clones.
  Without that hook the tool would have to grant every host it was handed,
  which is ceremony rather than enforcement.

Patches: (1) platform process seam + run + timeout-kill + tests. (2)
toolchain trait + cargo impl + build/test tools + a hello-world-crate e2e
against real cargo. (3) `gated`/`approved` + egress grants + fetch +
mock-server tests.

Exit: a mock scenario — "write a hello-world crate, build it, run its
test" — completes against real cargo under `cargo test`.

### Step 5a — expandable tool output (1 patch)

Added 2026-08-01, on review of step 5, at the user's direction. Lettered
rather than numbered on purpose: steps 6–10 are referenced by number from
code comments and from each other, and renumbering them to insert this would
break those references for no gain.

The problem step 5 made plain. Every finished call renders as `* <call>` and
then one indented summary line, computed by `turn::summarize`: a short
single-line result verbatim, an error verbatim (clipped at 200 chars by the
renderer), and **everything else as `1234 bytes`**. A build log is multi-line,
so a failing build reads

```
* build
  2144 bytes
```

with nothing on screen saying it failed. The full result exists only in the
session transcript — `trace` records the byte count, not the content — so
"show me that build error" currently means opening `.gears/sessions/<id>.jsonl`
by hand. This predates step 5 (`read_file` and a multi-hit `grep` have always
rendered this way); step 5 is what makes it matter, because whether the thing
compiled is what a user actually watches for.

The fix, in the line UI and without a TUI (decision 4 stands):

* mark an elided result — `  [+] 2144 bytes` — so the screen says there is
  more rather than implying that is all there was;
* `/+` prints the last elided result in full, `/+ N` the Nth from the end,
  under a header naming the call it belongs to (`--- build (2144 bytes) ---`).
  Expanding is a command, not a keypress: the UI thread is inside `pump`
  during a turn and only reads stdin at the prompt, so this happens after the
  turn — which is when "it failed, show me" is asked anyway. A bare `+` is an
  alias, and does not muddle the `/`-prefix convention: it is the one word
  nobody types as a prompt, and it is what a user reaches for on seeing `[+]`;
* the content has to reach the UI, which today only sees the summary string:
  `Event::ToolEnd` gains the whole result **only when it was elided**
  (`full: Option<String>`), so short results still cost nothing. The UI keeps
  a bounded ring of them — a byte cap rather than a count, since one build log
  is worth more than ten `list_dir`s — and says so plainly when an index has
  fallen out of it. The transcript remains the record; this is a convenience;
* long *error* results are clipped at 200 chars on screen today and should get
  the same treatment rather than a second, quieter truncation;
* `/help` and the README's command list gain the line.

Done as described, with the two open details settled thus. The `[+]` marker
does **not** print under `gears -p`, and nothing is kept there either: the
marker is an offer to type `/+`, and where there is no prompt it would be an
offer nothing can take up — so `Renderer` is told at construction whether
expanding is possible, from the same flag that says whether a permission
question can be asked. ToolStart and ToolEnd are paired by one field on
`Terminal` holding the last call started, which is right at N=1 and becomes a
map keyed by the `agent` the events already carry in step 7.

One thing that fell out of it: eliding now happens in `turn::summarize` and
nowhere else. The renderer used to clip a long line a second time, on its own
authority, which is precisely how a failed build came to read `2144 bytes`
with nothing saying it had failed — only the place that knows there is a
`full` behind the summary can decide how much of it to show.

Deliberately not attempted: changing `summarize` to show a first line plus a
size for every tool. It reads well for `run`/`build`/`test`, whose first line
is the exit status, and as noise for `read_file`, whose first line is whatever
happens to be at the top of the file — a bad trade for the general case.

Exit: a failing `build` shows `[+]`, and `/+` prints the compiler's
diagnostics, asserted end to end through the built binary the way step 5's
tests are.

### Step 6 — VCS tools (2 patches)

Goal: agent-visible version control per D3; undo already exists.

* `tools/vcs.rs`: the `Vcs` trait — `status`, `diff`, `commit(message)`,
  `restore(paths)`, `log` — plus `capabilities()` so an absent backend
  unregisters the tools cleanly (the Motor v1 story). `HostGit` shells out
  to `git -C <workspace>` with argument vectors only, no shell. Commits use
  the repo-local identity plus a `Co-authored-by: gears` trailer
  (decision 6); commit and restore always prompt.

Patches: (1) trait + HostGit + tests against a temp repo with real git.
(2) tool registration + gate wiring + e2e (mock drives edit → diff →
commit; assert `git log`).

Exit: the scenario produces exactly one commit with the trailer in a temp
repo; on a non-repo workspace the git tools are absent from the schema list
(asserted by a mock scenario).

Done as described. What the plan left to implementation, settled thus.

*The tools are bounded by the workspace, not by the repository.* gears may be
working in one directory of a checkout — `src/bin/gears` of this one, for a
start — so every git command carries a pathspec: `status`, `diff` and a
paths-less `commit` are about `.` and nothing above it, and `.gears` is
excluded from all of them rather than left to somebody's `.gitignore`. A
partial commit (`git commit -- <pathspec>`) is what makes this hold even when
something outside the workspace is already staged.

*Committing stages first.* A file the model has just written is untracked, and
`git commit -- <path>` would not find it, so `commit` is `git add` then `git
commit`. The trailer is appended by hand rather than with `--trailer` (git
2.32), and lands in the message's existing trailer block when it has one.

*A restore goes through the undo log.* Discarding a change is changing a file,
so `git_restore` takes each path through `Workspace::before_write` first —
otherwise `/undo` could not put back what a restore threw away. That is also
why it names files rather than directories: a directory has no copy to take.

*`capabilities()` is a probe, not a cfg.* `HostGit::open` asks `git rev-parse
--is-inside-work-tree` once at startup; no git, or no work tree, means no ops
and no tools registered. Motor OS answers by having no git, so the Motor v1
story needs no `#[cfg]` at all.

One thing that fell out of it: `run::execute` was split, with `capture`
underneath it returning how the command ended as a fact rather than as a line
of text. `run` deliberately does not treat a non-zero status as a failure —
a failing build is the signal — and the git tools deliberately do: a commit
that did not happen must not read like one that did.

### Step 7 — sub-agents (3 patches)

Goal: the registry becomes real at N > 1.

* `agent/registry.rs`: agent handles — one thread, conversation, model id,
  and provider connection each. `spawn_agent(task, model, read_only)` and
  `wait_agents` tools; depth (default 1), concurrency (default 4), and
  spend budget caps from config, the budget enforced against step 2's
  accounting; read-only agents get a filtered tool registry; sub-agent final
  answers return to the parent as tool results; per-agent output prefixes in
  line mode; parent ^C cancels children (per-agent abort flags — sinks error
  out, tools are killed).

Patches: (1) registry + lifecycle + spawn/wait tools. (2) caps + budget +
read-only sets + tests. (3) mock-driven concurrency e2e — two sub-agents on
interleaved *paced* streams (deterministic, not sleeps-and-hope); assert
prefix integrity and both results — plus a cancellation test.

Exit: the concurrency e2e passes repeatedly under `cargo test`.

### Step 8 — context management (2 patches)

Goal: long sessions don't die at the context window.

* `agent/context.rs`: per-turn *actual* usage numbers (from the API, not a
  tokenizer guess) drive a high-water policy: first replace oldest tool
  **results** with stubs, calls preserved (proposal decision); then a
  model-generated summarization checkpoint, recorded as a `compaction`
  session record (the step 4 format already tolerates new record types);
  resume honors compactions.

Patches: (1) accounting-driven eviction + synthetic-transcript tests.
(2) summarization checkpoint via a scripted mock summary +
resume-after-compaction test.

Exit: a scripted 50-turn session stays under a configured budget with
correct transcript semantics after resume.

### Step 9 — self-hosting on Linux (3 patches) — SECOND-TO-LAST

Goal: the stated bar — gears works on its own checkout: edit → build →
validate → restart-into-new-binary, fully demonstrable on the host. No new
subsystems; this step is scenario + glue, which is itself the test of
whether steps 0–8 composed.

* Glue: candidate binaries land at `.gears/candidates/gears-<n>`;
  validate-before-adopt — the *old* binary runs the test suite as a tool
  call; `promote` is a separate, explicitly gated step; restart-not-exec —
  write session state, spawn the candidate with `--resume`, exit.
* Hermetic self-host test (mock-driven, runs under `cargo test`): the
  scenario edits a designated cosmetic marker in gears' own source, runs
  `cargo build --offline` with `CARGO_TARGET_DIR=target/self` — a separate
  target dir, or the inner cargo deadlocks on the outer `cargo test`'s
  locks; the dir persists across runs to keep repeated runs fast — runs a
  bounded validation (`cargo test --offline --lib`), spawns the candidate
  with `--resume -p <continuation>`, and asserts that the **new** binary
  answered (marker visible) with a continuous session.
* Manual, documented, not automated: the same loop driven by a real model,
  and full-suite validation before promote.

Patches: (1) candidate/promote/restart glue + tests. (2) the hermetic
self-host integration test + scenario. (3) user-facing self-hosting notes.

Exit — **the working-Linux-gears gate**: under gears' own test suite, old
gears edits its own checkout, builds it, validates it, restarts into the
candidate, and the candidate resumes the session — hermetically. Plus one
recorded manual real-model run of the same loop.

### Step 10 — the Motor OS port (7 patches) — LAST

Prerequisites: lorry + curl available in the tree (currently on
`origin/lorry`; a fast-forward-shaped merge, see D1). This is also the step
where gears joins the Motor OS build and test machinery — until here it has
been a standalone crate (decision 11).

1. **curl-crate extensions**, now ordinary in-tree changes: a request
   writer taking method/extra-headers/body (today's `write_request`
   hardcodes GET + `Connection: close`), and a head-first streaming variant
   of `receive_response` that reports the head to a sink before the body
   copy — the D2 dividend is that the gears trait already fits. Keep-alive
   is deliberately deferred: per-request TLS handshakes are acceptable v1
   and `Connection: close` semantics are already tested.
2. `net/motor_curl.rs`: `HttpClient` over the curl lib as a path
   dependency; CA bundle `/sys/cfg/ssl/ca-certificates.crt`; `HttpsUrl`
   rejects plain HTTP, so the loopback-HTTP test carve-out compiles out
   here by construction. The crate is dual-target, so this impl is
   host-testable: step 1's generic SSE corpus reruns against it under
   `cargo test`. (Self-containment note, decision 13: this path dependency
   is the one hard coupling to the motor-os tree; if gears ever moves to
   its own repo, it becomes a git or vendored dependency.)
3. `platform/motor.rs` for real: spawn/kill/wait-with-deadline via moto-sys
   (rush's `sys/motor.rs` as reference), `/user/cfg` paths, in-band 0x03
   interrupt detection in the stdin reader, `MOTURUS_STDIO_IS_TERMINAL`
   for prompt behavior.
4. `LorryToolchain`: `lorry build|test|run [--release] [--target] [--]`,
   the exit-101 convention, stderr relay — lorry runs on Linux, so this is
   also host-testable.
5. Build wiring: Makefile target (copy the rush block — `CARGO_TARGET_DIR`,
   build, strip into `$(BIN_DIR)`), the `user:` aggregate, `.PHONY`, the
   `clippy:` target, and `/bin/gears` in `src/imager/motor-os.yaml`.
6. full-test integration + the hermetic VM-phase test. The host cargo-test
   loop (full-test.sh line 53) gains gears. Per decision 12,
   **mock-openrouter runs inside the VM**: a Motor-buildable binary over
   `mock/` (std-only since step 1, precisely for this) plus a rustls server
   face, serving TLS on the VM's loopback with a committed test CA and an
   IP-SAN leaf in curl's PEM-fixture style; gears' test config points its
   base URL at loopback and `cacert` at the test CA. Packaging — a
   feature-gated `[[bin]]` in the gears crate vs. a tiny sibling crate
   under `src/bin/gears/` — is decided at implementation; rustls must not
   become a dependency of the gears binary itself. The mock and CA ship
   into the VM via the image or the sftp sync helper (per-file `put` +
   ssh-exec mkdir — russhd's SFTP has no mkdir/rename). VM-phase checks:
   `gears --version`, then a `-p` scenario doing fs tools + `run` + a lorry
   hello-world build against the in-VM mock.
7. Manual milestones, documented with findings feeding the proposal's
   platform-asks section (per D4, not automated): in-VM self-build with
   lorry (VM sizing, motor-fs under compiler load — platform ask 1); a
   real-model run from inside the VM (verifies egress, DNS, and the
   shipped CA bundle against openrouter.ai — platform ask 2's long-lived
   TLS shape).

Patches: (1) curl request writer + tests. (2) curl streaming-head variant +
tests incl. TLS fixtures. (3) `motor_curl.rs` + host-side TLS tests.
(4) `platform/motor.rs`. (5) `LorryToolchain` + tests. (6) build wiring +
full-test host-loop line. (7) in-VM mock-openrouter + sftp sync helper +
full-test VM-phase additions.

Exit: full-test.sh passes debug and release, three consecutive times each
(AGENTS.md), with gears now wired in — host loop and the VM-phase scenario
green; the manual milestones performed and written up.

## Scope summary

| Step | Patches | |
|---|---|---|
| 0 | 3 | skeleton, config, seam, trace |
| 1 | 4 | HTTP + SSE (the best pure-test leverage) |
| 2 | 4 | provider + keys |
| 3 | 4 | fs tools |
| 4 | 7 | agent core — the product exists after this |
| 5 | 3 | run/build/fetch |
| 5a | 1 | expandable tool output (added on review of step 5) |
| 6 | 2 | VCS tools (shrunk by D3) |
| 7 | 3 | sub-agents |
| 8 | 2 | context |
| 9 | 3 | self-host on Linux |
| 10 | 7 | Motor port (incl. 2 curl-crate patches + full-test wiring) |
| **total** | **~40** | steps 0–9: zero lorry-branch dependency, zero full-test footprint |

## Risks

* **curl ≥ 8.3 on the dev host** for the env-only key path — checked with a
  clear error; a documented dev-host requirement, not a runtime one.
* **The head-first curl-crate extension is genuinely new code**; until it
  exists, MotorCurl cannot honestly satisfy `on_head`. It is scheduled
  (step 10 patch 2), not assumed.
* **Cancellation latency on Motor**: killing a subprocess is easy; aborting
  a blocked rustls read is not. Abort fires when bytes arrive or the stall
  timeout trips — cancellation latency ≤ stall timeout, accepted and
  documented.
* **mock-openrouter must build and run on Motor** (decision 12) — the mock
  core stays std-only from step 1 to guarantee it; the rustls server face
  is proven territory on Motor (curl, httpd). If TLS-on-Motor-loopback
  surprises anyway, that is a platform finding, not a plan break.
* **full-test's 600 s cap** constrains the step-10 VM scenario — the in-VM
  lorry hello-world build is the slow part; measured at implementation and
  trimmed if needed (in-VM self-build is already manual-only per D4).
* **Session-format drift** across self-restarts — mitigated by the meta
  record + unknown-type-skip rule from the first session ever written.

## Out of scope for v1 (in likely order afterwards)

crossterm TUI (the Motor port of crossterm has *landed*, but line-mode-first
stands — the TUI is pure UX and must not gate the port); connection
keep-alive in the curl crate; the native git-format tool (proposal VCS
option B); the httpd website demo (a nice optional in-VM demo after
step 10); adopting lorry's machine-readable diagnostics when it exists.

## Decision log (review round 1, 2026-07-31)

1. **Base branch:** work proceeds on the dedicated `gears` branch. Steps
   0–9 need nothing from `origin/lorry`; step 10 requires lorry + curl in
   the tree.
2. **Host HTTP backend:** subprocess host curl — confirmed.
3. **Config parsing:** serde derive + `toml` 0.8 (russhd idiom) —
   confirmed.
4. **TUI timing:** post-v1, even though crossterm landed — confirmed.
5. **Keys:** `OPENROUTER_API_KEY`; key file `~/.config/gears/openrouter.key`
   (host) / `/user/cfg/gears/openrouter.key` (Motor) — confirmed.
6. **Commit identity:** repo-local git identity + `Co-authored-by: gears`
   trailer; commits only on explicit task intent — confirmed.
7. **Retries:** none automatic in v1; the single-visible-reconnect
   exception is *not* adopted for now and may be revisited later.
8. **State location:** `<workspace>/.gears/`, gitignored — confirmed.
9. **D3 confirmed:** per-file undo log, no automatic commits, native
   git-format tool out of gears v1.
10. **Spend budget units:** USD from OpenRouter's usage `cost` field,
    token counts as fallback — confirmed.
11. **Standalone until ported:** gears stays out of full-test.sh at least
    until the Motor OS port is done and is developed as a standalone crate;
    the motor-os workspace supplies context and general AGENTS.md rules
    only. All full-test integration is step-10 work.
12. **Mock placement:** when VM porting happens, mock-openrouter runs
    *inside* the VM (no host-tap mock, no 192.168.4.1 assumption); `mock/`
    stays std-only from step 1 to keep it Motor-buildable.
13. **Confinement:** everything gears-related lives under `src/bin/gears/`
    (this plan, code, mock, fixtures, docs). A future move to a dedicated
    repo is possible but undecided; known extraction couplings are step
    10's path dependency on `src/bin/curl` and the Makefile/imager/
    full-test wiring, called out in place.
14. **Provider targeting (follow-up, same day):** gears targets the
    OpenAI-compatible chat-completions *wire dialect* behind its own thin
    `ModelProvider` seam, not a specific vendor — refining the proposal's
    "OpenRouter first" framing (same wire format, vendor-neutral module:
    `provider/openai_compat.rs` with configurable base_url/key/model).
    OpenRouter remains the blessed default endpoint and the only one
    manually validated; other compatible endpoints are config-only and
    documented as untested. Endpoint quirks (usage-request shape, `cost`
    field presence) are isolated in a quirk table; delta parsing is
    tolerant, with `reasoning` fields passed through, never required.
    Native provider dialects (Anthropic native, OpenAI Responses) stay out
    of v1 — the trait is where such backends would plug in later; the
    Open Responses spec is a watch item; gateway dependencies (LiteLLM)
    are rejected outright (contradicts the self-contained posture; the
    option-C host proxy slot exists if a gateway is ever wanted). Bonus
    this posture enables: a local inference server on the host tap network
    can serve a Motor VM with no cloud egress and no key in the VM,
    composing with key-handling option C. A non-default `base_url` host
    must be added to the egress allowlist.
