# gears: step-by-step plan, from zero to self-hosting

Written 2026-07-31, revised after review round 1 (all thirteen review
questions answered, plus the provider-targeting follow-up — see the decision
log), and **compacted 2026-08-01** once steps 0–9 were done: the finished
steps' working instructions are gone, and what remains of them is the record —
what each step left behind that later work still leans on. Companion to
`proposal.md`, which remains the governing design document; this plan
supersedes only its "First steps" sequencing. Every other proposal decision
(no tokio, sub-agents in v1, key handling option A, permission gate on the UI
side of the bus, context eviction policy, egress allowlist,
validate-before-adopt, restart-not-exec) stands unchanged.

## Status, 2026-08-01

**Steps 0 through 9 are done, and step 10 — the Motor OS port — has its first
half done: gears cross-compiles for `x86_64-unknown-motor`, is wired into the
Makefile and the image, and runs inside the VM.** What is not ported yet says
so — every missing capability is present and refuses with an "unsupported"
message rather than being absent or failing strangely; the full list is in
step 10 below.

On the Linux host, gears works on its own checkout: under its own test suite
it edits its source, builds it, validates what it built, and restarts into
the result on the same session.

### Manual runs on record

Everything the automated suite proves, it proves against a scripted mock —
that is the hermeticity rule working as intended, and it is also why the runs
against a real endpoint are worth writing down one by one.

* **2026-08-01 — a real model built a hello-world Rust app.** gears run by
  hand against OpenRouter with a real key, on a real model, was asked for a
  hello-world Rust application and produced a working one. **This is step 4's
  manual exit criterion met**, and the first evidence that the whole provider
  path — key loading, endpoint, streamed deltas, tool calls, the permission
  gate, the file tools — holds up against a model that was not reading from a
  script.
* **2026-08-01 — gears ran inside a Motor OS VM.** The release image (which
  now carries `/bin/gears`), driven over ssh/sftp: `--version` and `--help`
  answer; a `-p` run opens a session, sends the completion request and fails
  it cleanly with the transport's "unsupported" message, exit code 1; the
  interactive REPL serves its prompt and `/help`, `/status`, `/quit`;
  `--resume` picks the earlier session back up (2 messages) across process
  and lock; the trace log lands on motor-fs and records the whole request,
  with `Platform: Motor OS` in the system prompt and all nineteen tools —
  stubs included — in the schema list. This is step 10 part 1's exit
  criterion met.
* **2026-08-01 — lorry built a crate inside the VM, with gears' argv.** After
  part 1a put `/bin/lorry` and `/bin/curl` in the image: both answer
  `--version` in the VM; `lorry --color never build --release` — the exact
  command line gears' `build` tool now produces — compiled a hello-world
  crate under `/sys/tmp` on the image's own rustc, and the binary ran. The
  same argv against the same lorry on Linux builds and runs the same crate,
  which is the host-side half of the toolchain seam checked against the real
  tool.

### What the first real run changed

Asked to add a line to gears' own startup output and restart itself, the
model ran `cargo run --release` over and over instead — twenty-three
requests, and the user's quota. Both causes are fixed:

* **The self-hosting tools are registered whether or not they are enabled.**
  Step 9 had decided the opposite; reversed, because with the tools absent a
  model told to update itself cannot tell "not allowed" from "not a thing
  gears does", so it improvises with the tools it does have. Disabled, the
  three now refuse and name the setting to turn on.
* **A run can be given a budget.** `[limits] budget_usd` / `budget_tokens`
  cap what one gears run may spend, checked before every request and charged
  for sub-agents too; `[limits] max_steps` makes the per-turn round cap
  configurable. Both budgets are off unless set.

The general lesson, recorded because it keeps holding (it shaped the Motor
port too, see step 10): **a capability that is configured off should say so
rather than be absent.** The model is not told what gears' configuration
says, and silence is the one answer it cannot act on.

### What is left

* **Step 10, the second half** — the real network transport (the two
  curl-crate extensions and `MotorCurl` over them), `LorryToolchain`, in-band
  ^C, full-test integration with the in-VM mock, and the two manual in-VM
  milestones. Itemized at the end of step 10.
* **The remaining manual real-model runs**: step 9's self-hosting loop driven
  by a real model with a promotion after full-suite validation; step 10's two
  in-VM milestones; step 2's `gears ask` spot check (a convenience, not a
  gate — the step 4 run covered its substance).
* **The post-v1 list** at the end of this document, none of which gates
  anything.

## Strategy: four structural decisions

**D1 — develop on the `gears` branch, host-first.** Steps 0–9 used host
git/curl/cargo and needed nothing from the lorry workstream. *Resolved:
lorry and the curl crate are now in the tree, so step 10's prerequisite is
met.*

**D2 — the HTTP seam is push-based.** `src/bin/curl`'s library is
architecturally *push*: it writes decoded body bytes into a `Write` sink. So
gears' seam is sink-shaped from day one — `HttpClient::execute(req, sink)`
delivers head then chunks and returns when the body ends. Both backends fit
exactly; the step-10 curl-crate extension list falls out mechanically (a
request writer with method/headers/body, and a head-first streaming variant
of `receive_response`).

**D3 — no automatic commits; a per-file undo log is the safety net.** The
automatic safety net is copy-before-first-write per session under
`.gears/undo/<session>/`, restored by `/undo` — pure `std::fs`, so the same
code is the Motor v1 snapshot story. Agent-visible version control sits
behind a `Vcs` trait whose host impl shells out to `git`; commit and restore
always pass the permission gate. The native git-format tool stays out of
gears v1.

**D4 — in-VM self-build is a manual milestone, not an automated-test item.**
full-test.sh runs under `timeout 600s` and the VM gets 1024M; native rustc +
lld building gears' dependency tree inside that envelope is not a CI bet.
Step 10's automated gate is a hermetic in-VM scenario against the in-VM mock;
in-VM *self*-build with lorry is a documented manual validation and the
concrete probe for platform ask 1.

**Platform seam idiom.** `platform/{mod.rs, unix.rs, motor.rs}`: `mod.rs`
declares the portable vocabulary and selects with `#[cfg(unix)]` /
`#[cfg(not(unix))]` — **not** `target_os = "motor"`, because Motor sets no
target family, so `unix` is simply never true there. Small inline
`#[cfg(target_os = "motor")]` islands only where the diff is a couple of
lines (config and key paths, the prompt's platform note).

## Crate conventions and layout

Standalone crate: own `Cargo.toml`, committed `Cargo.lock`, edition 2024,
`license = "MIT OR Apache-2.0"`, the common release profile block (`panic =
"abort"`, `lto = "fat"`, `strip = true`, `codegen-units = 1`), `lib.rs` +
`main.rs` split so integration tests can `use gears::…` and find the binary
via `env!("CARGO_BIN_EXE_gears")`.

Dependencies: `serde` (derive), `serde_json`, `toml`; unix-only `libc`;
motor-only `moto-sys` (path dependency — see step 10). Nothing else: no
clap, no tokio, no crossterm until the post-v1 TUI.

```
src/bin/gears/src/
  main.rs  lib.rs  cli.rs  config.rs  trace.rs
  platform/{mod.rs, unix.rs, motor.rs}
  net/{mod.rs, host_curl.rs, motor_curl.rs, sse.rs}
  provider/{mod.rs, types.rs, assembler.rs, openai_compat.rs, key.rs, usage.rs}
  tools/{mod.rs, fs.rs, run.rs, toolchain.rs, fetch.rs, vcs.rs, spawn.rs,
         selfhost.rs, unsupported.rs}
  agent/{mod.rs, bus.rs, turn.rs, gate.rs, session.rs, prompt.rs,
         undo.rs, harness.rs, context.rs, registry.rs}
  ui/{mod.rs, repl.rs, terminal.rs}
  mock/{mod.rs, server.rs, scenario.rs}   # std-only; in-VM mock in step 10
```

Per-workspace state lives in `<workspace>/.gears/{sessions/, undo/,
permissions.toml, candidates/}`, excluded from the fs tools' view and from
`list_dir`/`grep` by default.

### Host ↔ Motor mapping

| Seam | Linux host | Motor OS today |
|---|---|---|
| `HttpClient` | host `curl` subprocess | `MotorCurl` stub: refuses as unsupported (real impl pending) |
| `Toolchain` | `cargo` subprocess | `lorry` subprocess (`/bin/lorry`; needs its VM-side config, see part 1a) |
| `Vcs` | host `git` subprocess | `git_*` stubs: unsupported (no git in v1; undo covers safety) |
| undo log | `std::fs` copy | same code, unchanged |
| process control | `libc` kill / waitpid, process groups | moto-sys `kill_pid` / `ProcessInfoV1`, single process |
| interrupt | SIGINT → AtomicBool | none yet: in-band 0x03 not wired |
| config path | `~/.config/gears.toml` | `/user/cfg/gears.toml` |
| key path | `~/.config/gears/openrouter.key` | `/user/cfg/gears/openrouter.key` |
| test mock | plain HTTP on loopback | (step 10, second half) TLS on the VM's loopback |

## The record: steps 0–9, done

AGENTS.md applied as general discipline throughout: patches of 100–300 loc
including tests, sparse comments, no retries or workarounds that can conceal
defects. Per decision 11, gears' tests run via `cargo test` in the crate, not
via full-test.sh, until the port is finished. The hermeticity rule has bound
the suite since step 1: **`cargo test` never talks to a real model
provider**; real-key paths are manual and documented.

What follows is one entry per finished step: what it built, and the
implementation decisions and lessons that later work still leans on. The full
working instructions each step was built from are in this file's git history.

### Step 0 — skeleton, config, platform seam, trace

The crate, hand-rolled args, `ConfigV1` (serde + toml, versioned, unknown
fields tolerated), the platform seam with Motor stubs, the leveled file
logger with a redaction hook. The egress allowlist field existed from day
one. Lesson that generalized (learned late, recorded here): **a
process-global that one test sets and the code under test consumes cannot be
tested in the same process as that code** — the interrupt flag's test lives
in `tests/interrupt.rs`, a process of its own, and must stay the only test
there.

### Step 1 — HTTP transport and SSE

`HttpClient`/`HttpSink` per D2; `host_curl.rs` over the host curl binary
(`-q` first for hermeticity; the API key only ever in the *child's*
environment via `--variable`/`--expand-header`, requiring curl ≥ 8.3; no
`--fail`, since 4xx/5xx bodies are the error taxonomy's input). `sse.rs` is
pure and incremental, and its test corpus is a generic harness over the
`HttpClient` trait so the Motor impl reruns it unchanged. The mock server
speaks plain HTTP on loopback only — a carve-out that lives in config
(`[net] allow_plain_http_loopback`, loudly test-only) and is refused for any
non-loopback host. `mock/` is std-only by rule, so it can build for Motor
(decision 12).

### Step 2 — provider: the OpenAI-compatible client and keys

The wire target is the OpenAI-compatible chat-completions *dialect*, not a
vendor (decision 14); OpenRouter is the blessed default endpoint and the only
manually validated one. Endpoint differences live in a quirk table (usage
knob shape, `cost` presence); parsing is tolerant, `reasoning` deltas pass
through. Index-keyed tool-call fragment assembly; `usage.rs` accumulates
tokens and USD. No automatic retry anywhere (decision 7). Key handling
option A: key file, `OPENROUTER_API_KEY` override, redaction registered the
moment a key is read — and redaction does not depend on logging being on,
because an endpoint quoting the key back in a 401 is the realistic leak.
gears never holds the key in its own environment: it is removed at startup,
before any thread exists, and injected into curl children only.

### Step 3 — fs tools

`read_file`, `write_file`, `edit_file`, `list_dir`, `grep` as pure,
gate-agnostic functions; registry, hand-built JSON schemas, malformed
arguments returned to the *model*; byte-capped head+tail truncation with
exact elision counts from the first tool. Workspace confinement: `..`
refused lexically, deepest-existing-ancestor canonicalized and
prefix-checked; deny-list covering the key file and `.gears/`; `edit_file`
is unique-string replace erroring with the occurrence count. Lessons: **the
deny-list must hold for tools that walk the tree themselves** (until `grep`
consulted it, the key file was greppable though unreadable), and a capped
result must say how much it dropped.

### Step 4 — agent core at N=1

The bus (typed events over std mpsc, one UI thread owning stdout, per-agent
`Cancel` handles), the turn loop (gate → execute all calls in order → append
results → repeat; every tool call answered, denied and cancelled included; a
cancelled turn leaves the conversation resumable), the gate on the UI side
(approve/deny/always, persisted; `permissions.mode = "auto-approve"` for
tests only), JSONL sessions with a meta record and *unknown record types are
skipped* (the self-restart story), the pid lockfile with stale detection
(`platform::process_alive`; pid 0 is junk, not an owner), prompt assembly
ingesting AGENTS.md/CLAUDE.md and replayed on resume, the undo log called
from `Workspace::before_write` (a snapshot that cannot be taken stops the
write), and the REPL with `-p` one-shot mode. Lesson: **smoke tests must be
hermetic against the developer's own key** — every test that runs the binary
removes `OPENROUTER_API_KEY` and names its own config.

### Step 5 — run / build / test / fetch tools

`run`: no shell, a program plus an argument vector; the child leads its own
process group on unix so a timeout kills the whole tree; both pipes drained
by threads into a bounded head-and-tail capture; a non-zero exit is *not* a
tool error — the first line of the result says how the command ended.
`Toolchain` trait (name + whole argument vector; target-dir override and
`offline` are what step 9 leaned on); `CargoToolchain` relays rustc stderr
verbatim with `--color=never`. `fetch`: GET through `HttpClient`; the
per-call gate arrived here (`Tool::gated`/`approved`), and consent reaches
the transport through `EgressPolicy::grant` — enforcement stays in the one
`net` layer.

### Step 5a — expandable tool output

Elided results render as `[+] N bytes`; `/+ [N]` (and bare `+`) prints a
kept result in full under a header naming its call; the UI keeps a
byte-capped ring. Eliding happens in `turn::summarize` and nowhere else —
the renderer clipping on its own authority is how a failed build once read
as `2144 bytes` with nothing saying it failed. No marker under `gears -p`:
an offer nothing can take up.

### Step 6 — VCS tools

The `Vcs` trait with `capabilities()` probing (`git rev-parse
--is-inside-work-tree`, once at startup) — no git or no work tree means no
tools registered, no cfg involved. The tools are bounded by the workspace,
not the repository: every command carries a pathspec about `.`, excluding
`.gears`. Commit stages first (an untracked file would not be found), the
trailer is appended by hand, and `git_restore` takes each path through the
undo log first — discarding a change is changing a file. `run::execute` was
split here, `capture` beneath it returning how the command ended as a fact:
the git tools treat non-zero as failure even though `run` must not.

### Step 7 — sub-agents

One provider, one set of tools, N conversations: a sub-agent owns a thread
and a conversation, everything else is shared. Read-only is inheritance by
construction: `spawn_agent` mutates, so a read-only registry does not
contain it. The sub-agent budget is a pocket inside the run's purse, charged
through one `Budget` seam. The renderer breaks lines between agents and
prefixes `[N]`; with one agent, output is byte-for-byte what it was. An
agent nobody waits for is stopped when the turn ends, told, and not joined.
The undo log holds its lock across the copy, not only the check — two agents
writing one file made that window real.

### Step 8 — context management

The window is the user's to declare (`context.budget_tokens`, default
128000, `0` = off); the rate is measured from the endpoint's own usage
reports, deliberately low. Eviction stubs tool results oldest-first but
never past the last assistant message that asked for tools; a summary is the
second lever because it costs money, and its boundary never separates a
call from its result. A `compaction` record is journaled (an eviction is
not); an older gears steps over it and resumes the whole transcript —
bigger, never wrong. A resumed session is seeded with the last recorded
`prompt_tokens`, so its first request is trimmed like any other.

### Step 9 — self-hosting on Linux

Candidates at `.gears/candidates/gears-<n>`; validate-before-adopt (the old
binary runs the suite as a tool call); promotion is copy-beside-and-rename
(`ETXTBSY`, atomicity, and `previous` kept beside it); the restart is the
interface's, never the tool's — the tool records the request, the model ends
its turn, `main` drops the harness (closing the session and its lock) and
spawns the candidate on the same session, waiting for it (not exec: Motor
has none, and one process owns the terminal). A staged candidate must answer
`--version` as gears does while the old binary is still in charge. The
automated gate passes hermetically under `cargo test`; **the manual
real-model run of the loop is still owed.** Lesson: **a file written and
then executed by the same multithreaded process races its own forks** — the
tests never execute a file they wrote.

## Step 10 — the Motor OS port

Prerequisite met: lorry and the curl crate are in the tree. This is also the
step where gears joins the Motor OS build and test machinery.

### Part 1 — cross-compile, wire, run in the VM: **done 2026-08-01**

gears builds for `x86_64-unknown-motor` (`make gears`, debug and release),
clippy-clean for both targets, host suites green in debug and release. What
landed:

* **`platform/motor.rs` is real**: `spawn` (plain — no process groups),
  `kill_tree` via `moto_sys::SysCpu::kill_pid` (one process, see the
  unsupported list), `process_alive` via `ProcessInfoV1::list` (the rush
  idiom; a list this process may not read answers "alive", the way `EPERM`
  does on the host), `status_text` (no killed-by case),
  `install_interrupt_handler` a truthful no-op (nothing to install — and
  nothing delivered yet either).
* **`net/motor_curl.rs`**: `MotorCurl`, the Motor `HttpClient` — for now a
  stub that validates the request, applies egress policy, and then refuses
  with `unsupported: HTTPS is not supported on Motor OS yet`. Compiled and
  unit-tested on the host too. `main.rs` selects the backend with one
  cfg'd type alias; both constructors have the same shape.
* **`tools/unsupported.rs`**: a tool that refuses and names the reason, in
  its description and in every call — the step-9 lesson as a reusable piece.
  `mutates()` is false, so refusing never costs a permission question.
* **`toolchain::for_platform`** registers cargo-backed `build`/`test` on the
  host and lorry-backed ones on Motor (stubs at first; made real in part 1a
  the same day); **`vcs::for_platform`** likewise
  registers the probe-backed git tools on the host and five `git_*` stubs on
  Motor. The latter deliberately revises step 6's "simply not registered"
  for the Motor case: "no git on this machine" is a *platform* fact, and a
  model that just finds no git tools would misread it as a fact about the
  workspace. On the host nothing changed — an unversioned directory still
  gets no tools, because there the absence is true of the workspace.
* **Motor-only dependency `moto-sys`** (path, `cfg(not(unix))`): with the
  curl crate to come, the second hard coupling to the motor-os tree
  (decision 13). Cargo reads every target's manifest even when building for
  the host, so the self-host test's copied workspace rewrites the relative
  path to an absolute one pointing at the real tree.
* **Build wiring**: `gears:` Makefile target (the rush block), in the
  `user:` aggregate, `.PHONY`, the `clippy:` target, and `/bin/gears` in
  `src/imager/motor-os.yaml`.
* **In-VM smoke run** — see *Manual runs on record* at the top for what was
  seen. Two details worth keeping: the second and third runs in the same VM
  proved the session lockfile creates and releases correctly on motor-fs
  (three sessions, one resumed, no stale-lock complaints), and `gears -p`'s
  exit code came back 1 through russhd, so a scripted VM-phase check can
  assert on it.

### Part 1a — lorry and curl in the image, lorry wired into gears: **done 2026-08-01**

Added the same day at the user's direction: `/bin/lorry` and `/bin/curl` ship
in the image, and gears' Motor `build`/`test` drive lorry for real.

* **Makefile**: `lorry:` is the standard cargo block. `curl:` cannot be —
  plain cargo cannot even resolve curl's manifest, whose `[patch.crates-io]`
  names the reviewed Motor `cc`/`ring` trees under `.lorry/vendor/` that only
  lorry materializes — so its recipe is `src/bin/curl/build-motor.sh`: the
  Stage 2 seed (installed once under `build/lorry/stage2/`, network only on
  a cold download cache), a host lorry, a staged copy of the package with the
  Motor linker and native-tool configs written in (the source tree stays
  pristine), and `lorry build --target x86_64-unknown-motor`. The staged
  `target/` and `.lorry/` persist across runs as the build cache. `make
  clean` wipes the seed cache, so the next curl build re-downloads.
* **`LorryToolchain`** in `tools/toolchain.rs`, used by `for_platform` on
  Motor: `lorry --color never build|test [--release] [--target T]`, program
  named absolutely (`/bin/lorry` — Motor spawns do no PATH search). The
  `Toolchain::command` seam now returns `Result`, because lorry has no
  `--target-dir` and refusing an option beats dropping it; `offline` asks
  for nothing lorry does not already do (`lorry vendor` is the online step,
  builds never touch the network). Unit-tested at the argv level; the e2e
  against a real lorry belongs to full-test integration (part 2), which is
  also where lorry's own gates already exercise these command lines.
* **What the VM can build today, verified 2026-08-01**: the image ships the
  native rust toolchain (`img_files/generated/rustc`), so `/bin/lorry`
  building a dependency-free, stage-1-shaped crate inside the VM **works
  right now** — `lorry --color never build --release` (gears' exact argv)
  compiled a hello-world under `/sys/tmp` and the binary ran. What is still
  missing is the lane for crates with registry dependencies: lorry on Motor
  reads `/user/cfg/lorry.toml` and needs a vendor repository beside it, and
  the production image ships neither (the lorry gates provision their own).
  Until it does, a dependency-carrying build gets lorry's own diagnostic —
  the feedback-signal design doing its job. gears' own dependency tree is in
  that category, so the in-VM *self*-build still waits on provisioning (and
  stays the manual D4 milestone regardless).
* **curl and gears**: gears does *not* drive `/bin/curl` — the binary is
  deliberately GET-only (no POST, no custom headers, no response head on
  stdout; it exists to serve lorry's download boundary), so it cannot
  implement the `HttpClient` seam. The provider transport stays the plan's
  library path: the curl *crate* plus its two extensions (part 2). `/bin/curl`
  in the image is a user tool.

### Unsupported on Motor OS, as of part 1a

Every entry below *runs and refuses with a message containing
"unsupported"*; nothing panics and nothing is silently absent.

1. **The network — model completions, `gears ask`, `fetch`.** `MotorCurl`
   refuses every request after validating it: `transport error: unsupported:
   HTTPS is not supported on Motor OS yet (the curl-crate port, plan step
   10)`. A run starts, opens its session, registers tools — and the first
   completion fails with that message.
2. **`git_status`, `git_diff`, `git_log`, `git_commit`, `git_restore`** —
   stubs: *"Motor OS has no git in v1; the undo log still protects every
   change, and /undo puts files back"*.
3. **Interrupting a running turn (^C).** Motor OS has no signals; a ^C is an
   in-band 0x03 byte, and no stdin reader watches for one mid-turn yet. A
   turn runs to its end (today that end comes fast — the transport refuses).
   Not a tool and so not a stub: recorded here and in `platform/motor.rs`.
4. **`kill_tree` reaches one process.** No process groups: a timed-out
   command is killed, but children it spawned survive it. Accepted for v1;
   it matters now that `build`/`test` run lorry, which spawns compilers.
5. **Self-hosting in the VM.** The three tools are registered and answer as
   on the host, and `build` is now real lorry — a dependency-free crate
   builds in-VM today, but gears' own dependency tree needs the vendor
   repository the image does not ship yet (part 1a), and the in-VM
   self-build stays the manual D4 milestone either way.

(`build` and `test` left this list in part 1a: they run `/bin/lorry` now,
and what an unprovisioned VM gets is lorry's own diagnostic, not an
"unsupported" from gears.)

What *works* on Motor now, for the record: `--version`/`--help`, config from
`/user/cfg/gears.toml`, key loading and redaction, session create/resume and
the pid lockfile (real liveness via moto-sys), the fs tools, `run` with
timeout kill, the undo log and `/undo`, the permission gate, trace, the
one-shot and interactive loops.

### Part 2 — what remains

1. **curl-crate extensions** (2 patches): a request writer taking
   method/extra-headers/body, and a head-first streaming variant of
   `receive_response`. Keep-alive stays deferred.
2. **`net/motor_curl.rs` for real** over the curl lib as a path dependency;
   CA bundle `/sys/cfg/ssl/ca-certificates.crt`; `HttpsUrl` rejects plain
   HTTP so the loopback carve-out compiles out by construction. Dual-target,
   so step 1's generic SSE corpus reruns against it under host `cargo test`.
3. **In-band ^C**: 0x03 detection in a stdin reader feeding
   `platform::note_interrupt`, and `MOTURUS_STDIO_IS_TERMINAL` for prompt
   behavior.
4. ~~`LorryToolchain`~~ — done in part 1a. What remains of it here: lorry
   provisioning in the production image (`/user/cfg/lorry.toml` + vendor
   repository) so an in-VM `build` can actually build, and the
   real-lorry-on-Linux e2e, which belongs to the full-test wiring below.
5. **full-test integration + the hermetic VM-phase test.** The host
   cargo-test loop gains gears. Per decision 12, mock-openrouter runs
   *inside* the VM: a Motor-buildable binary over `mock/` plus a rustls
   server face, TLS on the VM's loopback with a committed test CA; rustls
   must not become a dependency of the gears binary itself. VM-phase checks:
   `gears --version`, then a `-p` scenario doing fs tools + `run` + a lorry
   hello-world build against the in-VM mock.
6. **Manual milestones** (per D4, not automated), findings feeding the
   proposal's platform asks: in-VM self-build with lorry (VM sizing,
   motor-fs under compiler load — ask 1); a real-model run from inside the
   VM (egress, DNS, the shipped CA bundle — ask 2).

Exit for the whole step: full-test.sh passes debug and release, three
consecutive times each, with gears wired in — host loop and the VM-phase
scenario green; the manual milestones performed and written up.

## Scope summary

| Step | | Status |
|---|---|---|
| 0 | skeleton, config, seam, trace | done |
| 1 | HTTP + SSE | done |
| 2 | provider + keys | done; `ask` live spot check optional, not run |
| 3 | fs tools | done |
| 4 | agent core | done, real-key task included |
| 5 | run/build/fetch | done |
| 5a | expandable tool output | done |
| 6 | VCS tools | done |
| 7 | sub-agents | done |
| 8 | context | done |
| 9 | self-host on Linux | automated gate done; manual real-model run owed |
| 10 | Motor port | **parts 1 + 1a done** (cross-compile, wiring, VM smoke, unsupported stubs; lorry + curl in the image, lorry driving `build`/`test`); part 2 open |

## Risks (live ones only)

* **The head-first curl-crate extension is genuinely new code**; until it
  exists, `MotorCurl` cannot honestly satisfy `on_head` — which is why it is
  a refusing stub today, not a guess.
* **Cancellation latency on Motor**: aborting a blocked rustls read is not
  like killing a curl child. Abort fires when bytes arrive or the stall
  timeout trips — latency ≤ stall timeout, accepted and documented.
* **mock-openrouter must build and run on Motor** (decision 12) — the mock
  core is std-only precisely for this; the rustls face is proven territory
  on Motor (curl, httpd). Surprises there are platform findings, not plan
  breaks.
* **full-test's 600 s cap** constrains the VM scenario — the in-VM lorry
  hello-world build is the slow part; measured at implementation, trimmed if
  needed.
* **Session-format drift** across self-restarts — mitigated by the meta
  record + unknown-type-skip rule from the first session ever written.
* **curl ≥ 8.3 on the dev host** for the env-only key path — checked with a
  clear error; a dev-host requirement, not a runtime one.

## Out of scope for v1 (in likely order afterwards)

crossterm TUI (its Motor port has landed, but line-mode-first stands);
connection keep-alive in the curl crate; the native git-format tool
(proposal VCS option B); the httpd website demo; adopting lorry's
machine-readable diagnostics when they exist.

## Decision log (review round 1, 2026-07-31)

1. **Base branch:** the dedicated `gears` branch; step 10 required lorry +
   curl in the tree (now there).
2. **Host HTTP backend:** subprocess host curl.
3. **Config parsing:** serde derive + `toml` 0.8 (russhd idiom).
4. **TUI timing:** post-v1, even though crossterm landed.
5. **Keys:** `OPENROUTER_API_KEY`; key file `~/.config/gears/openrouter.key`
   (host) / `/user/cfg/gears/openrouter.key` (Motor).
6. **Commit identity:** repo-local git identity + `Co-authored-by: gears`
   trailer; commits only on explicit task intent.
7. **Retries:** none automatic in v1; the single-visible-reconnect exception
   not adopted for now.
8. **State location:** `<workspace>/.gears/`, gitignored.
9. **D3 confirmed:** per-file undo log, no automatic commits, native
   git-format tool out of gears v1.
10. **Spend budget units:** USD from OpenRouter's usage `cost` field, token
    counts as fallback.
11. **Standalone until ported:** gears stays out of full-test.sh until the
    Motor OS port is done; developed as a standalone crate with `cargo
    test`. Full-test integration is step-10 (part 2) work.
12. **Mock placement:** mock-openrouter runs *inside* the VM; `mock/` stays
    std-only to keep it Motor-buildable.
13. **Confinement:** everything gears-related lives under `src/bin/gears/`.
    A future move to a dedicated repo is possible but undecided; the known
    extraction couplings are the `moto-sys` path dependency (step 10 part
    1), the coming `src/bin/curl` path dependency (part 2), and the
    Makefile/imager/full-test wiring.
14. **Provider targeting:** the OpenAI-compatible chat-completions *wire
    dialect* behind gears' own `ModelProvider` seam, vendor-neutral;
    OpenRouter the blessed default and only manually validated endpoint;
    endpoint quirks in a quirk table; tolerant delta parsing with
    `reasoning` passthrough; native provider dialects out of v1; gateway
    dependencies rejected. A non-default `base_url` host must be added to
    the egress allowlist.
