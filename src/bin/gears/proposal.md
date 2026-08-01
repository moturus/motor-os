# gears: a native agentic harness for Motor OS

2026-07-31. Status: **proposed, revised after second review round**. No code
exists yet; this document is the only file in `src/bin/gears/`.

Revision notes: the name `gears` is confirmed. The `origin/lorry` branch has
been explored and this proposal is grounded in it — lorry's actual CLI and
dependency policy (`src/bin/lorry/spec.md`, `README.md`), and the existing
`src/bin/curl` HTTPS client, which replaces the previously proposed
hand-rolled HTTP layer. Concurrent sub-agents are in scope for v1. After the
second round: key handling is decided (option A + documented B and C), serde
derive may be assumed (lorry will grow proc-macro support), sub-agent limits
are configurable, machine-readable lorry diagnostics is an **accepted lorry
TODO**, and the VCS question is settled: Motor has no file-backed mmap
(anonymous shared memory only), which firms up the native git-format tool
as the recommended core (see the decision log at the end). Work on gears
starts only after lorry + curl land on main, so all curl-crate coordination
questions are moot — its extensions become ordinary in-tree changes.

## What and why

`gears` is an agentic coding harness — a program in the style of Claude Code
or Codex CLI — that compiles for and runs *on* Motor OS, drives frontier
models over the network (OpenRouter first), and uses local tools (files,
processes, the native toolchain) to do real work on the VM it runs in:

* write and build Motor OS-native Rust software with the native toolchain
  (clang/llvm, rustc, and lorry — `src/bin/lorry` on the `lorry` branch);
* create and operate content served from the same VM (e.g. a website behind
  the in-tree `httpd`/`httpd-axum`);
* read, analyze, and modify its own source tree, rebuild itself, and restart
  into the new binary — a self-hosted improvement loop.

Beyond being useful in itself, gears is a forcing function for the platform:
it is a demanding, real workload that exercises the native toolchain, the
network stack (long-lived TLS streams), the process API, motor-fs under
compiler load, and the terminal story — exactly the surfaces Motor OS wants
hardened. Where the OS is missing something, the gap becomes a concrete,
prioritized work item rather than a hypothetical.

## Ground rules

Per AGENTS.md: standard Rust and native Motor OS APIs (`src/sys/lib`) only,
plus explicitly allowed dependencies. Foundational pure-Rust crates are
allowed when easily portable; the strong preference is to draw from the
dependency set lorry Stage 2 has already reviewed and pinned (spec.md:
serde 1.0.228 and serde_json 1.0.150 without derive, sha2 0.10.8 software
backend, toml_edit parse-only, non-derive clap), plus the rustls/ring/
getrandom combination `src/bin/curl` already uses on Motor. Two constraints
follow:

* **gears must remain lorry-buildable.** Stage 2 supports locked crates.io
  and path dependencies, with build scripts only by explicit allow. Lorry's
  current pin set is derive-free, but proc-macro support is a committed
  lorry work item (per review), so gears may assume `serde` derive: the
  protocol layer uses `#[derive(Serialize, Deserialize)]` types for the
  chat API, falling back to `serde_json::Value` only for provider-specific
  passthrough fields. The dependency tree still stays within reviewed,
  easily portable foundational crates.
* `crossterm` — assumed ported and working per `docs/plans/crossterm.md`
  (the `../crossterm` fork) — is the one larger dependency, for the v2 TUI.

Deliberately *not* used: tokio. The ports exist and work (httpd-axum,
russhd), but an agent loop is a handful of concurrent activities, not ten
thousand sockets. Blocking std I/O on threads (the rush/rmux idiom) keeps
gears std-only and debuggable, and maps naturally onto sub-agents
(one thread + one HTTPS stream each). Revisitable if this stops being true.

## Architecture

```
+---------------------------------------------------------------+
|  ui        line-mode REPL (v1)  /  crossterm TUI (v2)         |
+---------------------------------------------------------------+
|  agents    agent registry: root agent + sub-agents, one       |
|            thread each; event bus to ui; permission gate;     |
|            sessions (JSONL on motor-fs)                       |
+---------------------------------------------------------------+
|  provider  ModelProvider trait; OpenRouter impl speaks the    |
|            OpenAI-compatible chat-completions API + SSE       |
+----------------------------+----------------------------------+
|  tools     fs read/write/  |  net: the src/bin/curl crate     |
|            list/grep,      |  used as a library (it has a     |
|            run, lorry      |  lib.rs for exactly this),       |
|            build/test,     |  extended for POST + streaming   |
|            spawn_agent     |                                  |
+----------------------------+----------------------------------+
|  std + moto APIs: net, fs, process, time  (motor and host)    |
+---------------------------------------------------------------+
```

### Dual-target from day one

Like rush and rmux, gears builds and runs on the Linux host *and* on Motor,
std-only, with `cfg(target_os = "motor")` islands kept minimal. This is not
a convenience: the edit/build/test loop on the host is seconds, unit tests
run everywhere, and the Motor build then only has to prove the OS-specific
seams (TLS handshake, spawn, terminal), not the whole program.

### net: build on src/bin/curl, not beside it

The lorry branch already contains the piece the first draft of this proposal
planned to write: `src/bin/curl`, a curl-compatible HTTPS client in standard
Rust + rustls, with hostname verification, HTTP/1.1 framing including
chunked bodies, connect/total/stall timeouts, and a Motor getrandom hookup —
all tested, and exposed through `src/bin/curl/src/lib.rs` as a library
(`write_request`, `receive_response`, `transfer`, `client_config`).

gears uses that crate as a path dependency and extends it (in place, keeping
`/bin/curl` the CLI face) with what an agent needs and a one-shot fetcher
does not:

* request methods beyond GET, with request bodies (POST of JSON);
* incremental body delivery — `copy_chunked` already writes to a `Write`
  sink chunk-by-chunk, so SSE streaming is a flushing sink plus an
  event-boundary parser on top, not a rework;
* connection reuse (keep-alive) for the chat endpoint.

This keeps exactly one reviewed TLS/HTTP implementation in the tree, shared
by lorry's fetch path and gears' model traffic. Trust roots follow curl's
existing `--cacert` posture: a PEM file on motor-fs (a Mozilla CA bundle
shipped in the full image), not a compiled-in root store — the earlier
webpki-roots idea is dropped.

**Egress policy** follows the same lead. All gears networking goes through
this one layer with curl's strict defaults (HTTPS only, TLS 1.2+, no
proxies, bounded timeouts), and gears' config carries a host allowlist that
ships as `openrouter.ai` plus nothing; the `fetch` tool prompts (through the
permission gate) for hosts outside it.

### provider: driving multiple models

A single trait:

```rust
trait ModelProvider {
    fn complete(&self, req: &ChatRequest, sink: &mut dyn EventSink)
        -> Result<Completion, ProviderError>;
}
```

`ChatRequest` carries messages, tool schemas, and a model id string.
OpenRouter is the first (and possibly only necessary) implementation: it
fronts Anthropic, OpenAI, Google, and open models behind one
OpenAI-compatible endpoint, so "drive multiple models" reduces to a model-id
string plus a per-model quirk table (tool-call support, parallel tool
calls, reasoning params). Streaming deltas flow to `EventSink` so the UI
renders tokens as they arrive. Each agent holds its own provider connection
and its own model id — model choice is per agent, which is what makes
cheap-model sub-agents (below) work.

Config (endpoint, default model, per-role model overrides, egress
allowlist) is TOML under the user's directory on motor-fs, parsed with the
same parse-only toml_edit lorry pins. russhd established the TOML idiom.

### tools: what the model is allowed to do

Tool calls dispatch to native implementations:

* `read_file`, `write_file`, `edit_file` (string replace), `list_dir`,
  `grep` — std::fs plus a hand-rolled search; paths confined (below);
* `run` — `std::process::Command` with captured stdout/stderr and a
  wall-clock timeout (Motor pids and kill via moto-sys, the rush idiom);
* `build` / `test` — wrappers over lorry's now-known CLI:
  `lorry build|run|test [--release] [--target TRIPLE] [-- ARGS]`, build
  output isolated under `target/lorry`, exit code 101 for build and
  operational failures, the program's own status for run/test. The tool
  relays rustc diagnostics from stderr verbatim as the agent's feedback
  signal; `test --bundle` is the natural fit for shipping gears' own test
  harnesses to a VM.

  > **Accepted lorry TODO (per review):** an optional machine-readable
  > diagnostics mode (a `--message-format json` analogue), so the agent
  > can parse build feedback rather than scrape stderr. gears' `build`
  > tool starts on stderr relaying and switches to the structured mode
  > when lorry grows it;
* `fetch` — HTTPS GET through the shared curl layer, allowlist-gated;
* `spawn_agent` / sub-agent results — below.

Every mutating or process-spawning call passes a **permission gate** in the
agents layer: interactive approve/deny/always-allow, decisions persisted
per project. The workspace root given at startup confines all fs tools
(paths canonicalized and prefix-checked); `run` is the deliberate escape
hatch and is gated accordingly. This is policy in gears, not OS
enforcement — honest v1 posture. A later hardening step can put tool
execution in a child process whose capabilities Motor OS actually
restricts; if the OS grows a capability/sandbox surface, gears is its first
consumer (platform ask 3).

### agents: the loop, times N

The core loop is classic and small: send conversation + tool schemas;
stream the reply; if it contains tool calls, gate, execute, append results,
repeat; otherwise yield. **Concurrent sub-agents are in scope for v1**, so
the layer is shaped for N agents from the first patch even though the
first patches run N=1:

* An **agent registry** owns agent handles. Each agent is a thread with its
  own conversation, model id, and HTTPS connection. The root agent talks to
  the user; sub-agents are created by the `spawn_agent(task, model,
  read_only)` tool, run the same loop, and deliver their final answer back
  to the parent as a tool result (parent blocks in `wait_agents` or
  interleaves — its choice via tool arguments).
* One **event bus** (std mpsc) carries typed events — token deltas, tool
  requests, permission requests, agent lifecycle — from all agents to the
  single UI thread. In line mode concurrent output is prefixed per agent;
  the TUI can do better later. The permission gate is centralized on the UI
  side of the bus, so approvals serialize naturally no matter how many
  agents want something.
* Guardrails: sub-agents get a depth limit, a concurrency cap, and a
  token/spend budget — all configurable (decided per review; config
  defaults: depth 1, concurrency 4), plus optionally a read-only tool
  set — the cheap-model-scout, strong-model-builder pattern this exists
  for.

Context-window pressure: drop oldest tool *results* first (keeping calls as
stubs), then model-generated summarization checkpoints. Transcripts append
to a JSONL session file per agent under the project directory, so a session
survives the process and — important for self-rebuild — a restart into a
new binary resumes from disk.

### ui

v1 is a line-mode REPL over plain stdio: prompt, streamed answer, y/n
permission prompts, per-agent output prefixes. This works today over the
serial console, ssh, and inside an rmux pane, and keeps early patches
focused on the loop. v2 moves to crossterm once that port lands: streamed
rendering, a status line (model, token counts, spend, live sub-agents),
visible diffs before write approval. The crossterm plan's constraints
(CPR-based size probe, no blocking first paint) are inherited, not
re-solved.

## API key handling (decided)

The constraint: Motor is effectively single-user and the VM is the trust
boundary; file permissions add little inside it. Decision (per review):
**option A is implemented in v1; options B and C are both documented
deployment practices** in gears' user docs. Option D stays parked.

* **A. Key file + env override (v1 baseline).** `Authorization` material in
  a config-referenced file on motor-fs, overridable by an environment
  variable for one-off runs; never in the main config, never in
  transcripts, redacted from logs and from the model's own view (the agent
  must not be able to `read_file` its own key — the fs tools deny the
  secrets path). Cheapest, honest about the boundary.
* **B. Budget-capped provisioned keys (documented practice on top of A).**
  Use OpenRouter's provisioning API on the host to mint a runtime key with
  a hard spend limit, inject it at VM boot or session start. A leaked key
  is then a bounded loss, which converts "the VM is the boundary" from a
  worry into an accounting line. Costs nothing in gears code — it is
  operational guidance plus a config field.
* **C. Host-side auth proxy (documented practice for dev rigs/CI).** gears
  talks HTTPS to a small forwarder on the host tap network which injects
  the real key. The key never enters the VM. It composes with the mock
  provider used in tests, and needs no gears code beyond the base-URL
  config field that exists anyway.
* **D. OS secret service (platform ask, later).** A sys-service that holds
  secrets and attaches them to approved outbound connections, so no user
  process ever reads key bytes. Worth designing only once B/C prove
  insufficient — parked as platform ask 6.

## Version control: options

There is no git on Motor and a straight port (C, autotools, perl in its
test suite, shell-outs) is indeed unattractive. What self-hosting actually
needs, in increasing order: revert-ability of agent edits; durable local
history with commits and diffs; interop with the host/world (push, pull,
review). Options:

* **A. Snapshot directories (v1 floor).** Copy-before-modify per session,
  restore on demand. Already planned, stays regardless — it is the safety
  net under every other option. No history semantics, no interop.
* **B. A small native tool writing the git object format (recommended
  next).** A lorry-spirited utility (`mvcs` or similar, plausibly a gears
  sibling in `bin/`) that implements content-addressed commits by writing
  git's on-disk format directly: loose objects (zlib via the pure-Rust
  flate2 lorry already pins, SHA-1/SHA-256 via sha2), refs as files, a
  minimal index. Commit/log/diff/checkout is a small, dependency-light,
  auditable surface — squarely in the rush/rmux/lorry/curl tradition. The
  payoff of choosing git's *format* over an invented one: sync the
  repository directory to the host over the existing sftp path and every
  git tool there reads it natively — history, review, push to the world —
  with no protocol code on Motor at all. Interop without porting git.
* **C. gitoxide (gix) subset.** Pure-Rust git implementation; the object/
  ref/index plumbing crates could replace B's hand-rolled core with a
  maintained one. The porting cost is a memmap2 shim (next subsection);
  the review cost is a dependency graph far larger than anything lorry
  has vetted so far.
* **D. jujutsu / pijul.** Attractive semantics, but jj sits on gix plus a
  large graph, and pijul on an mmap-backed database with much stronger
  demands (writable shared mappings, sync ordering). Not v1 or v2
  material.

### What "mmap" concretely means here

gix uses `memmap2` for one access pattern: **read-only, file-backed,
demand-paged mappings of immutable files** — pack files, pack indexes,
multi-pack-index, commit-graph — read at random offsets. The full
requirement list is short:

1. Map an existing file (or a range of it, page-aligned) read-only into
   the address space, paged in on demand — laziness over large packs is
   the entire point versus just reading the file.
2. **The mapping must keep working after the file is deleted or
   replaced.** Git repacks by writing new packs and then removing old
   ones while readers may still hold mappings; unix unlink semantics
   (data pinned until last mapping drops) is what gix assumes. This is
   the one behavior that tends not to fall out of a simple mmap design.
3. That is all: no writable shared mappings, no msync/durability
   ordering, no cross-process coherence — mapped files are immutable by
   format convention.

**Motor OS answer (per review): neither is available.** Motor's mmap is
anonymous shared memory only; there is no file-backed mapping. So the gix
route, if ever taken, requires patching memmap2 to a read-whole-file shim
(open, read into an anonymous buffer, expose `&[u8]`) — semantically
correct, sidesteps requirement (2) entirely since the mapping *is* a
private copy, but gives up demand paging; acceptable at Motor-repo scale,
a real cost on large packs. Option B needs no mmap of any kind, which
firms it up as the recommended core. gears does not ask the platform for
file-backed mmap — nothing in this proposal needs it — but if Motor ever
adds it for other reasons, the gix calculus reopens. Sanakirja-style
writable shared mappings (pijul) remain out of scope either way.

Decision (per review): A now; B as the deliberate VCS investment when
self-hosting starts in earnest (gears step 6), with format compatibility
tested by round-tripping through host git; C (gix plumbing behind the
read-whole-file shim) only as a fallback if B's object/pack core proves
harder than it looks. Long-term, when the VM copy becomes canonical, the
chosen option also grounds pull/push transport (smart-HTTP client through
the shared curl layer — a later, separate proposal).

## The self-improvement loop

* **Source on the VM.** v1 (confirmed): the host checkout is canonical; the
  VM copy is a working tree synced over sftp/russhd, the mechanism
  `src/tests/test-sftp.sh` already exercises with lorry fixtures. Long-term
  the VM copy becomes canonical, which is what elevates VCS option B above.
* **Edit and build.** gears edits its own checkout with its fs tools and
  builds with lorry + native rustc — the same tools it uses on any other
  project; nothing self-referential in the mechanics.
* **Validate before adopt.** The freshly built binary must pass the gears
  test suite (`lorry test`, or a `test --bundle` artifact), run by the old
  binary as a tool call, before anyone runs it interactively. The new
  binary lands at a versioned path; promotion to `/bin/gears` is a
  separate, explicitly approved step.
* **Restart, not exec.** On approval, gears writes session state, spawns
  the new binary pointed at that session, and exits. Supervisor-style
  in-place upgrade can come later; spawn-and-exit needs nothing the OS
  doesn't have.

The website use case needs no new machinery: write files into a directory
served by httpd, then health-check it with `fetch` over loopback — a good
early end-to-end demo.

## Platform asks (Motor OS can evolve; gears makes these concrete)

1. **Native toolchain capacity** — assumed working; the real-world question
   is VM sizing (rustc + lld memory) and motor-fs under compiler-shaped
   I/O. gears will find out.
2. **Long-lived TLS connections** — hours-long, mostly idle HTTPS streams
   with bursty reads; a different traffic shape than rnetbench or httpd
   exercise today.
3. **Child-process resource limits and sandboxing** — kill-on-timeout
   exists; CPU/memory caps and narrowed-capability spawn do not. The
   permission gate wants OS teeth eventually.
4. **File-backed mmap — noted absent, not asked for.** Motor's mmap is
   anonymous shared memory only (per review), and nothing in this
   proposal needs more: the recommended VCS route needs no mmap, and the
   gix fallback works behind a read-whole-file shim. Recorded so a future
   decision to add file-backed mapping knows it reopens the gix calculus
   (see the VCS section).
5. **crossterm port** — already planned; gears becomes its second in-tree
   consumer and a motivating one.
6. **OS secret service** — parked; see key-handling option D.

## First steps

Per AGENTS.md discipline: 100–300 loc patches, tests in each, everything
reachable from `src/tests/full-test.sh`, no retries that conceal defects.
A hermeticity rule from the start: **full-test.sh never talks to a real
model provider.** A `mock-openrouter` binary (loopback HTTPS server
speaking just enough of the API, canned scripted completions including
tool calls and SSE framing, reusing the curl crate's test-certificate
fixtures) ships with the test suite; real-provider runs are manual.

* **Step 0 — skeleton.** `src/bin/gears` crate in the standard bin layout
  (edition 2024, common release profile), dual-target, `--version`, TOML
  config parsing. Wire a trivial smoke test into full-test.sh.
* **Step 1 — curl extensions.** POST with bodies, streaming sink,
  keep-alive in the curl crate, behind its existing test style; gears
  consumes it as a path dependency. Sequencing (per review): gears work
  starts only after lorry + curl have landed on main, so this is an
  ordinary in-tree change, not cross-branch coordination.
* **Step 2 — provider.** OpenRouter request/response + SSE against the
  mock; a manual `gears ask -m MODEL "..."` one-shot subcommand for
  real-key spot checks, proving multi-model early. Key handling option A
  in code; B and C written up in the user docs alongside it.
* **Step 3 — agent loop + fs tools.** Registry-shaped even at N=1: event
  bus, permission gate, workspace confinement, JSONL sessions, tool
  schemas and dispatch. Scripted end-to-end: mock provider drives file
  creation and edits; assert the resulting tree.
* **Step 4 — run/build/test tools + sub-agents.** Process spawning with
  timeouts; lorry integration (host side drives real lorry — it builds on
  Linux); `spawn_agent` with depth/concurrency/budget caps, mock-driven
  concurrency test. End-to-end in-VM: "write a hello-world crate and build
  it with lorry".
* **Step 5 — website demo.** Mock-driven: write a static site, point httpd
  at it, `fetch` it back over loopback. First whole-stack demo.
* **Step 6 — self-hosting + VCS option B.** gears' source staged onto the
  VM; snapshots, then the git-format tool; build-validate-promote-restart,
  mock-driven in tests, real-model driven manually.
* **Step 7 — crossterm TUI.** After that port lands; line mode remains as
  fallback (serial console, dumb pipes).

Steps split further into AGENTS.md-sized patches; the per-patch plan lives
in `src/bin/gears/step-by-step-plan.md` (which also supersedes the step
sequencing above with a host-first ordering).

## Decision log (second review round)

1. **Key handling:** option A implemented in v1; B (budget-capped
   provisioned keys) and C (host-side auth proxy) both documented as
   deployment practices.
2. **VCS:** A (snapshots) now, B (native git-format tool) at step 6.
   Motor has no file-backed mmap (anonymous shared memory only), so the
   gix alternative would need a read-whole-file memmap2 shim; B, which
   needs no mmap at all, is the recommended core, with C as fallback.
3. **Sequencing:** gears starts after lorry + curl land on main; curl
   extensions are ordinary in-tree changes.
4. **serde derive is available:** lorry will support proc macros; the
   protocol layer uses derived types.
5. **Sub-agent limits:** depth and concurrency are configurable (defaults
   1 and 4), alongside the configurable spend budget.
6. **Lorry TODO (accepted):** machine-readable diagnostics mode — on the
   lorry todo list; gears' build tool is designed to switch to it when it
   exists (see the highlighted note in the tools section).
