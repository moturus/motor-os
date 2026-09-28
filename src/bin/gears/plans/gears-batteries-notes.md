# Gears batteries: engineering notes behind the plan

These are the parts specific to Motor OS and to Gears of the assessment of
2026-09-25/26: the platform experiments, the prototypes, the defects found
in Gears, the design detail, the phased plan as first drafted, the user's
questions, and the size measurements. They were moved here on 2026-09-28,
when the assessment was rewritten as a research paper on self-improving
agents that does not mention Gears, now `docs/self-improving-agents-review.md`. The plan itself is
`gears-batteries.md`; it supersedes the phases and questions below, which
are kept as the record of how its numbers were arrived at.

Section numbers are those of the original assessment: §1 is its summary,
§4 to §8 and Appendices A to D follow. Its §2 and §3, on Hermes's size
and architecture, are now §11.1 and §11.2 of that review, and references
below point there. E0 to E13 and Q1 to Q18 use the original
numbering; the plan has its own, G1 to G19 and Q1 to Q38 in milestone
order, and its milestones A to J plus G′ replace the six phases of §7.

No code changes accompany this document. The prototypes live outside the
repository.

Provenance. Findings were gathered against:

* Hermes Agent (`github.com/NousResearch/hermes-agent`, MIT) at
  `d0288be5b3` (2026-09-26 03:51 UTC), checked out at `../hermes-agent`.
  Two historical snapshots were also read: `30ca282594` (2025-11-22, the
  research-agent era) and `69aa35a51c` (2026-02-15, the first product
  shape with gateway, cron and skills).
* Motor OS at `2ff1400c` (2026-09-25), in particular `src/bin/gears`,
  `src/bin/curl`, `src/bin/rush`, and the plans in `docs/plans/`.

Unless stated otherwise, "LOC" and "lines of code" mean non-blank,
non-comment lines as counted by `tokei`, while a bare "lines" means raw
lines. Paths without a prefix are relative to the Hermes checkout.

Method:
* Code-level reading of the agent loop, providers, tools, state, memory,
  skills, compression and host layers. Five parallel read-only reviews,
  with detailed notes and `file:line` evidence, were spot-checked by hand.
  Independent fact-check passes then re-verified the document's claims
  against both code bases.
* Git history mining, and surveys of Hermes's skills and regression tests.
* Experiments on Motor OS for the questions that decide the port (§4.3):
  * SQLite with FTS5;
  * `rush` as a terminal backend;
  * process and hook costs, and session-search throughput;
  * Monty for code execution;
  * prototypes of the batteries' hook, file tools, delegation, session
    search, an MCP client, an HTTP and a Telegram front end, and chat
    approvals.
* Scratch prototypes of the three Gears fixes and of thirteen other Gears
  changes, to test the size estimates (§6.3).
* For the research review (Appendices E to G): two passes over the Awesome
  Self-Improving Agents collection, the survey it accompanies and the
  Stanford CS329A readings, about a hundred papers in all, read in
  parallel groups with each paper's method, best result, ablations and
  limits recorded before any conclusion was drawn; the results that carry
  the most weight were re-read directly; Hermes's learning loop was read
  from its code.

## 1. Summary of the Hermes review and its recommendation

**What Hermes is.** A Python "personal agent" by Nous Research. One
synchronous tool-calling loop runs behind several hosts: a REPL, a
messaging gateway for ~32 platforms, a TUI, an Electron desktop app, an
editor protocol, and a cron scheduler. What distinguishes it is a small
set of mechanisms:
* frozen, prompt-cache-friendly system prompts;
* native file tools;
* two budgeted memory files;
* agentskills.io skills with progressive disclosure;
* a post-turn "review" fork that writes memories and skills;
* structured context compaction;
* subagents, MCP, and Python "code mode".

**(a) Why the repository is so large (review §11.1).**
* The 1.03 GiB of history is 44K commits in 14 months. About half of it
  is Python history, concentrated in thousands of rewrites of a few
  0.7–1.7 MB "god files". About 200 MB is stray binaries.
* The 190 MB of tracked files hold 1.66M lines of Python, 57% of them tests
  (~42K test functions), and ~670K lines of TypeScript, 544K of them in
  the desktop app and installer.
* The code grew from 30K non-test Python lines in February 2026 to ~705K
  now. Breadth (platforms, providers, backends, UIs) was expanded
  on purpose. Nearly every incident was answered with more code. An
  in-process multi-tenant design created whole bug classes. By September
  the pace was ~670 commits a day, with heavy AI assistance.

**(b) Core architecture (review §11.2).** The essential core is about 30K lines of
the ~705K non-test Python lines. It consists of:
* the loop;
* three wire formats (Chat Completions, Anthropic Messages, OpenAI
  Responses);
* a tool registry with parallel batches for read-only and path-disjoint
  file tools;
* a spawn-per-call terminal that carries shell state;
* native file tools;
* two tables of session history;
* compaction, memory, skills and the review fork.

Checked against the code, the README's "self-improving" learning loop
is a review fork started by two counters every ten turns or tool rounds,
running a fixed prompt. Its "LLM summarization" of past conversations
no longer exists: session search returns stored messages (review §11.2.19).

Its best ideas are invariants, not code (review §11.2.17):
* persist tool calls before side effects;
* give every tool call a result;
* never re-stream text the user has already seen;
* keep the prompt byte-stable and put changes in messages;
* disclose skills and tools progressively;
* keep memory tiny and budgeted.

**(c) What a Rust/Motor OS port takes (§4–§7).**
* Running the Python on Motor OS is not realistic (§5.1).
* Motor OS already has most of a Hermes-shaped core in Gears: streaming
  provider, loop, JSONL sessions, compaction, process control, hooks,
  UIs, and a hermetic mock provider.
* The recommendation is to port Hermes's *capabilities* onto Gears as
  batteries, an extension of hooks and tools, rather than port its loop
  (§5.4, §6). This takes:
  * ~16.5K lines of Rust, plus ~1.4K for the separately planned external
    tools (E1), and tests of about the same size again. That includes
    ~2.7K of Gears fixes and targeted Gears improvements: Anthropic
    wire, reasoning echo, cache markers, JSON event output, after-turn
    jobs, a lock-free read fork, hook re-initialization on session
    switch, compaction, and parallel read-only tools;
  * about 180 small patches in six phases, each leaving a usable agent:
    roughly 6 to 13 weeks at 2 to 4 reviewed patches a day (§7).
    Phase 1 alone is a useful minimal stopping point: about 4.7K lines as
    phase 0 recommends (E1's steps 3–5 later, E3a and E4 added), or
    5.3K with all of E1;
  * no `src/sys`, std, moto-rt or sibling-repository changes on the
    recommended path.
* Three of the changes to Gears help today's users whatever is
  decided about the port:
  * prompt-cache markers on the Chat Completions wire (E4), for Claude
    and Kimi models through OpenRouter, Gears' default;
  * reasoning echo (E3a), without which DeepSeek, Kimi and MiMo thinking
    modes reject a tool round's second request;
  * keeping apart parallel tool calls that a server sends all at index 0,
    as Ollama does, which Gears merges into one invalid call today.

  The prototypes were about 50, 50 and 15 lines.

Experiments for this document, most of them on a live Motor OS VM, settled
the riskiest technical questions. All of them used scripted mock
providers, so how real models behave with the batteries' terse tool
descriptions and ported prompts is still untested (§8.3).
* SQLite with FTS5 runs today with two runtime workarounds and a one-line
  header stub, though the recommendation is to avoid it.
* `rush`'s `export -p` round-trips shell state, so the terminal tool can
  carry `cd` and `export` between calls.
* Monty, a Rust Python-subset interpreter, runs Hermes-style "code mode"
  on Motor OS without CPython.
* Process-per-call designs are cheap. A whole `gears -p` turn costs
  ~36 ms against a local mock, a command hook 2–20 ms per turn (it sees
  every event), and a `rush` spawn ~1.2–1.4 ms.
* A 31-line prototype memory hook on unmodified Gears keeps the prompt
  byte-stable across processes (resume, fork) while memory changes on
  disk. A ~200-line Rust prototype of the batteries' multiplexing hook (a
  partial version) ran six tool rounds with Gears inside a Motor OS VM in
  0.12 s: memory, skills, todo, `read_file`, and a shell tool whose `cd`
  and exports persist. That is
  Hermes's prompt-cache discipline without Hermes's machinery. Switching
  sessions inside one process needs a small Gears change (E12).
* With the E11 read-fork and E7 after-turn prototypes, a review fork's
  first request repeated the parent's system prompt, tools and messages
  byte for byte, and memory written meanwhile stayed out of it. That held
  even while the interactive parent was alive and held the session lock.
  This is Hermes's learning loop with full cache reuse. E7 took ~60
  lines.
* Delegation as a nested `gears -p` ran in 0.085 s on Motor OS, and a
  timed-out child's process tree was killed.
* A scripted edit-and-test loop ran in the dev VM through prototype file
  tools: read, write, `lorry test` failing, a fuzzy `patch`, and
  `lorry test` passing. It took 4.1 s. The minimal option then ran end
  to end in the VM, at 2.2 s including a compilation, with:
  * the file tools, `rg` search and the shell as E1 tool directories
    (each tool a directory with a manifest and a program);
  * the policy floor, a deny list of `sh` commands built from Hermes's
    patterns that no approval overrides;
  * the `AGENTS.md` context.
* An MCP client made one POST per tool call at ~2 ms, and it survived an
  expired server session.
* Two small daemons ran in the VM on top of the E6 JSON-events
  prototype. One was an OpenAI-compatible HTTP front end at ~35 ms per
  turn; it detached and outlived its ssh session. The other was a
  Telegram front end against a mock Bot API. Both keep a session per
  conversation and serialize its turns, and both relayed tool approvals
  to the user through a stdin channel added to E6.

**Pre-existing defects found.** Applying Hermes's lessons to Gears, and
running the prototypes on Motor OS, exposed defects in existing code. All
were reproduced; none was fixed in the repository, since each needs the
user's decision:
* **Gears, unpaired tool calls (§4.4).** A tool round that ends early
  leaves tool calls without results in the session: a plain Ctrl+C
  during any tool call once a hook is configured, a multi-call batch cut
  short, or a crash. Strict providers reject such requests, according to
  Hermes's records; the malformed requests were reproduced here but not
  sent to a real provider.
* **Gears, hooks after a cancel (§4.4).** After a cancelled turn, every
  lifecycle hook is killed at spawn until the next turn starts. Hooks
  never see the cancelled turn's `turn_end`, the `session_end` and
  `session_start` of a session switch (`/new`, `/resume`, `/fork`,
  `/clone`), or the `session_end` at exit.
* **Gears, the compaction wedge (§4.4).** One oversized tool result can
  wedge a session for good. Compaction sends the summarizer an unbounded
  input, so every later turn fails with the provider's context-length
  error.
* **Gears, smaller issues (§4.4, §6.3):**
  * an interrupted round leaves the next user message directly after a
    tool result, which models read as part of the interrupted turn;
  * parallel calls sent at index 0 merge into one invalid call;
  * `finish_reason` is ignored, so a reply that announces a tool call
    but carries none ends the turn;
  * a reasoning-only reply is stored as an empty assistant turn.
* **The base image (§4.4).** 26 command wrappers pass `$@` unquoted, which
  breaks any argument that contains a space.
* **Elsewhere (§8.2):**
  * rmux accepts any loopback client and publishes its port where the
    None role can read it, so a sandboxed process can drive an
    Interactive shell (diagnosed in the VM); the E10 sandbox is only a
    real boundary once this is fixed;
  * `opendir` in the runtime succeeds on a directory the caller may not
    list, and only reading its entries fails;
  * rush fails on `>&-`;
  * mlibc has no fork-less `popen`;
  * Lorry cannot build as a None-role process.

The Gears fixes are E0 and parts of E3a and E5. They were prototyped in
about 12 to 80 lines each, with regression tests that fail on today's
Gears (§6.3). The plan does not depend on the others.

**Main risks (§8.3):**
* No real model was used, so whether models follow the batteries' terse tool
  descriptions and ported prompts is untested (Q18).
* Injected text can persist: the review fork turns conversations into
  memory and skills that reach every later prompt. Threat scans,
  untrusted-content wrapping and user review of writes from tainted
  sessions reduce this; they do not remove it. A red-team review of
  the design found further gaps, addressed by rules in §6.7 for phases 1
  to 6 (~700 lines). The worst were an auto-allowed read tool that could
  read keys, and a search tool whose path argument could run commands
  through `rg`.
* Long-lived gateway sessions turn any of the §4.4 defects into a
  permanent failure, which is why E0 comes first.
* ~18K lines of code, plus tests, need a user after they land.

**Decisions needed before any code (§7, phase 0):**
* Q1 (packaging), Q4 (which image), Q10 (names) and Q14 (missing
  commands);
* whether to approve E0, the ~220 lines of Gears fixes for §4.4;
* whether E1 lands whole or with only the ~500 lines the port needs
  first, and whether its plan takes two rules the port relies on
  (argument handling and grants in unattended runs, §6.7);
* whether E3a and E4 (~250 lines) move into phase 1;
* Q18, whether phase 1 may end with real-model sessions, which need
  Internet access (for a local model, once).

The rest can wait for the phase that needs them: Q2 and Q6 for phase 2,
Q3 and Q7 for phase 3, Q5 and Q9 for phase 4, Q8, Q13 and Q15 for phase
5, Q11, Q12 and Q16 for phase 6, and Q17 after v1 (§8.1).


## 4. What Motor OS offers an agent today

### 4.1 Gears is already a small Hermes-shaped core

`src/bin/gears` (12.5K lines of Rust, 11K of them code and ~8.5K outside inline unit tests; `MIT OR
Apache-2.0`) is an agent harness that runs on Linux and Motor OS. Its `redesign.md` deliberately
limits its core to:
* provider streaming;
* one agent loop;
* cancellation;
* sessions;
* a line UI and a TUI;
* versioned command hooks;
* one built-in tool, `sh`.

Mapped against review §11.2:

| Hermes core piece | Gears today |
| --- | --- |
| Tool-calling loop | `src/runtime.rs` (903 lines). Sequential tools; the assistant message is persisted before tools run; bounded round count. |
| Provider | OpenAI-compatible streaming only (`src/provider/`, 1.8K). SSE parser (`src/net/sse.rs`), no automatic retries by design, no reasoning replay, no Anthropic wire, no caching markers. |
| HTTP | A curl subprocess (`src/net/`): upstream curl on Linux, the in-tree Rust curl on Motor OS. Egress allowlist; plain HTTP only when explicitly allowed. |
| Sessions | Append-only JSONL trees with fork/clone/resume and a single writer (`src/session.rs`, 1K). |
| Compaction | Summarize older context with the same model, keep a token-sized tail, append a compaction entry (`runtime.rs:618`). |
| Terminal | `sh` via `sh -c` or `/system/bin/rush -c`, with bounded capture, timeout, cancellation and process-tree kill (`src/process.rs`, `src/platform/motor.rs`). |
| Approvals | Permission hooks (deny beats allow beats ask), then y/n/a at the prompt. No command parsing, by design. |
| Extensions | Command hooks: one JSON event on stdin, one bounded JSON result on stdout (`hook-protocol.md`). Hooks can add prompt fragments and tools, keep namespaced state that follows conversation branches, and receive every event. `initialize` runs once per process. |
| Hermetic tests | `gears-mock-provider` scripted SSE scenarios, gated by `src/tests/test-gears-http*.sh` on the host and in a dev-image VM. |
| Not present | File/search/patch tools, memory, skills, todo, session search, delegation, MCP, web tools, cron, gateway, context files, the learning loop. External tool directories are planned (`src/bin/gears/plans/gears-external-tools.md`). |

The design philosophies differ on purpose. Gears keeps the core minimal and
pushes policy into hooks and prompt resources, and it rebuilds the prompt
from current resources on resume. Hermes ships a large built-in toolset
and pins the prompt byte for byte across restarts. §5 turns on this
difference.

### 4.2 Platform facts that shape the port

From the Motor OS survey behind this document, with paths in `docs/`, the std
port, and `src/sys/lib`:

* **Images.** Three are built:
  * the base image (`motor-os-base.img`), the minimal system that the
    other two contain;
  * the standard image (`motor-os.qcow2`);
  * the developer image (`motor-os-dev.qcow2`, "dev image" below), which
    adds Gears, the Rust and C toolchains, Lorry and the Helix editor
    under `/devtools`, and curl at `/system/bin/curl`.

* **Processes.**
  * `std::process::Command` works with pipes, cwd, `env` and `env_remove`,
    `kill` and `try_wait`.
  * There is no `fork`, no signals, no process groups and no PTY. `kill`
    only terminates.
  * Descendants are killed by walking `moto_sys` process stats, as Gears
    does.
  * Ordinary (non-System) children die with their parent unless spawned
    detached, which needs `CAP_SPAWN_DETACHED`.
  * Environment values over 4,092 bytes panic in `moto_rt::process::setenv`.
* **Files.**
  * No symlinks, no settable times, no file-backed `mmap`.
  * Whole-file advisory locks work via `File::lock`.
  * The `tempfile` crate returns "unsupported"; use `create_new` plus
    `rename`.
* **Network.**
  * TCP and UDP over IPv4 and static IPv6 work (no DHCPv6 or SLAAC), with
    DNS through a resolver service on the standard and dev images.
  * Outbound Internet works through the host's NAT.
  * Networking was declared production-ready on 2026-08-23.
* **TLS and HTTP.**
  * rustls 0.23 with the `moturus/ring` fork works; a CA bundle ships at
    `/system/cfg/ssl/ca-certificates.crt` in every image.
  * The only HTTP client is the in-tree Rust curl, which ships **only in
    the dev image**. It speaks HTTP/1.1, with no HTTP/2 and no websockets.
  * Building ring needs host Perl, so anything linking TLS in-process
    cannot be built natively by Lorry today.
* **Async.**
  * Forks of tokio 1.47 and mio work (net, process, time, sync), used by
    `httpd-axum` and `russhd`.
  * There is no `tokio::signal` and no Unix sockets.
  * `parking_lot` must be pinned to the Motor OS fork.
  * Most user-space programs, Gears included, use std threads; system
    services use the in-tree `moto-async`.
* **Shell and commands.**
  * `rush` is a capable POSIX-ish shell (§4.3).
  * The base image's `/system/bin` has 29 small command scripts (cat, cp,
    find, ls, wc, ...), and the standard image adds `rg`.
  * There is **no `grep`, `head`, `tail`, `diff`, `patch`, `env`, `git` or
    Python**. The dev image adds `sed`, `gix`, clang, `rustc`, and Lua.
* **Time.** UTC only; there is no time-zone database.
* **CPython.** A plan exists (`docs/plans/cpython.md`) but no code. The
  `ssl` module needs a separate OpenSSL port.

### 4.3 Experiments run for this document

All experiments used scratch code outside the repository. Motor OS runs used
fresh `-snapshot` boots of release images under QEMU:
* the standard image (`motor-os.qcow2`, 4 vCPUs, 1 GiB) for SQLite, rush and
  Monty;
* the dev image (`motor-os-dev.qcow2`, 4 vCPUs, 4 GiB) for:
  * the Gears turn costs and the session scan;
  * the prototypes of the batteries' hook, file tools (edit and test),
    delegation, MCP, HTTP and Telegram;
  * the Gears prototypes' VM runs (E1 in the minimal option, E3b, E6
    under delegation, E10, and the learning loop with E7).

The memory-hook prototype, the first review-fork parity check and the
§4.4 Gears reproductions ran on the Linux host; the base-image `$@`
reproduction ran in the standard image, and the minimal option (E1, E2,
E13) in the dev image. Mock providers and the mock Bot API
ran on the host, reached from the VM over the TAP interface. No test
contacted the Internet.

#### Platform probes

**SQLite with FTS5.**
* **Setup:** a probe using `rusqlite 0.39` with `bundled` (SQLite 3.51.3,
  FTS5 enabled).
* **Build:** cross-compiled with the `motor-clang` recipe from
  `src/bin/curl/build-motor.sh` and linked with `motor-rust-cc`, plus a
  one-line stub `sys/ioctl.h` (mlibc has none; SQLite includes it but only
  calls `ioctl` on Linux).
* **Unpatched:** the process died in mlibc: "`__ensure(!"Cannot continue
  without sys_geteuid()") failed`".
* **With one workaround:** overriding `geteuid` through SQLite's own
  `sqlite3_vfs.xSetSystemCall` hook, the `unix-none` VFS works in both
  `journal_mode=TRUNCATE` and exclusive-mode WAL. Measured:
  * 5,000 inserts with FTS5 triggers in one transaction: 285–293 ms
    (105 ms on the host);
  * 100 single-row commits: 17–24 ms;
  * an FTS5 `MATCH` with `snippet()`: 0.3–0.4 ms;
  * `PRAGMA integrity_check` after reopening: `ok`.
* **The default `unix` VFS fails** with "disk I/O error" after
  "`mlibc/motor: fcntl(6) is unsupported`" (`F_SETLK`).
* **Conclusion:** SQLite is usable today for a single-writer process
  without any Motor OS change. It adds a C build dependency. It also rules out
  native Lorry builds unless its build script is patched:
  the bundled `libsqlite3-sys` build emits `cargo:include` and
  `cargo:lib_dir` directives, and Lorry fails on unknown directives
  (`src/bin/lorry/spec.md:951`).

**rush as the terminal backend.**
* **Constructs that work:** functions, `eval`, `.`, aliases, arithmetic,
  `pipefail`, `$(...)`, here-docs, `trap ... EXIT`, and background jobs
  with `jobs`/`kill`/`wait`.
* **Snapshot round trip:** `export -p` output that includes a value with
  quotes, `$` and an embedded newline is re-sourced correctly. This is the
  mechanism behind Hermes's environment snapshot (review §11.2.6), so Hermes's
  per-command state carry-over maps onto rush.
* **Spawn cost:** 50 sequential `rush -c true` spawns took 68 ms in total,
  ~1.4 ms each. Spawning a process per command or per tool call is cheap.
* **Missing commands:** `head`, `env` and similar are not present in the
  image (see §4.2).
* **No `/dev/null`:** redirecting to it fails with
  "`rush: /dev/null: NotFound`". Models write `2>/dev/null` constantly,
  so the `sh` tool's prompt fragment must say so (Q14).
* **`mkdir` takes one directory and no `-p`** ("usage: mkdir [$DIR]").
  Models write `mkdir -p a/b` constantly. The same prompt fragment must
  say so, or the batteries' file tools can create parent directories
  themselves.

**Process-per-turn cost.** These runs used the dev image with 4 vCPUs and
4 GiB, against a host SSE server replaying the `gears-mock-provider`
"streamed-text" body over the TAP interface. 20 consecutive runs each:
* a complete `gears -p` turn (process start, configuration, session file,
  curl spawn, HTTP request, SSE parse) takes **~36 ms**, with or without
  `--ephemeral`;
* the same turn with three no-op `rush` hooks configured costs more.
  Every hook receives every event, sequentially: nine events per `-p`
  run, 27 hook spawns here, confirmed by a logging hook. The cost was
  noisy: +5 to +17 ms per run over 20 back-to-back runs (five
  repetitions), but +10 to +65 ms in single runs. That is 0.2–2.4 ms per hook
  invocation, or 2–20 ms per hook per text-only turn. Each tool call adds
  a `permission`, a `tool_result` and an `entry` event per hook;
* a spawn plus wait costs ~1.2 ms for `rush -c true` and ~0.85 ms for
  `sysbox echo`, measured from a Rust harness. A blocking `wait()` and a
  `try_wait` poll cost the same;
* a bare `/system/bin/curl` POST takes ~3 ms.

Designs that run a `gears` process per delegated task, review, cron job
or chat message (§6.4, §6.5) therefore add tens of milliseconds to calls
that take seconds.

Memory is similarly small. In the dev VM, `ps` showed:

| Process | Memory |
| --- | --- |
| An interactive `gears` with the batteries' hook, waiting at its prompt after a turn | 6.0 MB |
| The batteries prototype's `review` process, waiting on its fork | 2.9 MB |
| The detached HTTP gateway prototype | 5.4 MB |
| The whole guest, kernel and services included | 117 MB |

**Session-search scale.** Scanning Gears-style JSONL session files, with
read, ASCII lowercase and substring count, runs at 90–100 MB/s on Motor OS
FS. That is 21 MB in 500 files in 0.21 s and 85 MB in 2,000 files in
0.95 s, against ~2.1 GB/s on the host. For that raw scan, reads through
sys-io dominate. A linear scan is adequate up to roughly 100 MB of
history.

A 128-line prototype of the real tool confirmed this. It searched
Gears-format session trees for all query words, case-folded, over the
messages and compaction summaries on every branch. It marked hits off
the active branch, which is the path from a file's last entry to its
root. Files that fail a raw-text prefilter are never parsed. On
synthetic history of 500 sessions, 41 MB in three workspaces, it took:

| Query | In the VM | On the host |
| --- | --- | --- |
| Rare (3 hits; 3 files parsed) | 0.24 s | 0.014 s |
| Common (285 hits; 464 files parsed) | 0.44–0.53 s | 0.12 s |

A hit planted on an abandoned branch came back marked off-branch. At
171 MB the host took 0.05 s and 0.5 s for the same two kinds of query.
So on Motor OS a common query pays for JSON parsing on top of the reads,
roughly doubling its time, and 100 MB of history costs about a second.
That is the point to add the index of Q2 (d).

**Monty for code mode.**
* **What it is:** Monty (`github.com/pydantic/monty`, MIT, v0.0.21,
  "experimental") is a Rust interpreter for a Python subset, built for
  running LLM-written code. It reaches the host only through host-provided
  functions.
* **Probe:** a script calling two host "tools" (`list_dir`, `read_text`)
  five times, using `re` and `json`.
* **Build:** it cross-compiled for Motor OS unchanged except for one thing.
  `ahash` pulls in `getrandom 0.3`, which has no Motor OS backend, so the
  probe used `getrandom`'s documented custom backend
  (`--cfg getrandom_backend="custom"` plus a 5-line
  `__getrandom_v03_custom` calling `moto_rt::fill_random_bytes`).
* **Result on Motor OS:** correct output, ~0.15 ms to compile the script,
  ~0.8 ms end to end, a 7.7 MB release binary.
* **Conclusion:** Hermes's `execute_code` can be ported without CPython.

**Tool schema size.** A static AST extraction of Hermes's tool schemas
resolved 25 of the 59 core tools; they total 43,885 JSON characters (about
11K tokens). The rest are built dynamically. This is consistent with
Hermes's own figure of about 26K tokens for the default toolset.

#### Prototypes of the batteries

**Prototype: memory as a Gears hook, on unmodified Gears.** Host Gears
(release build of `2ff1400c`) was run against a recording mock provider
with one command hook: a 31-line Python prototype of §6.4's memory hook.
At `initialize` the hook reads `MEMORY.md` unless its namespaced state
already holds a snapshot. It returns the snapshot as a prompt fragment,
stores it as state, and registers a `memory` tool that appends to the
file. The sequence:
1. a new session A whose model call adds a memory entry;
2. resuming A in a new process;
3. `--fork` of A;
4. a fresh session B.

Recorded request bodies show:
* A's system prompt was byte-identical before the write, after it, on
  resume and in the fork (one hash across three processes). The `tools`
  array was identical too.
* Every later request's `messages` extended the earlier request's
  exactly.
* Session B's prompt carried the new entry.

This is Hermes's frozen-snapshot behaviour and the review fork's cache
parity, achieved through hook state. It needs no Gears change as long as
each process opens one session, which covers `-p` runs, delegation, cron
and the gateway. Hooks initialize once per process, so an in-process
`/new` or `/resume` keeps the previous session's fragments. E12 fixes
that. The fork was written as a third saved session file, which is why
E11 exists.

**Prototype: the batteries' multiplexing hook, on Gears and on Motor OS.** A
~200-line Rust prototype of §6.4's single hook (`serde_json` only) was
built as `pack-proto hook` ("pack" was the working name then), 684 KB on
Linux and 413 KB for Motor OS. At
`initialize` it contributes the frozen memory snapshot and the skills
index, both kept in hook state. It registers five tools: `memory`,
`skill_view`, `todo` (list kept in hook state), `read_file` (numbered
lines), and `run`, a shell tool that carries `cd` and exports through the
§6.4 state wrapper. It also answers `permission` with a small hard floor.

A scripted mock drove one turn of six tool rounds:
1. `run` with `mkdir sub && cd sub && export FOO=bar`;
2. `run` with `pwd; echo FOO=$FOO`;
3. `memory`;
4. `skill_view`;
5. `todo`;
6. `read_file`.

The session was then resumed. Results:
* **On the host** (Gears `2ff1400c`, `/bin/sh`): every tool result was
  right, and the second `run` printed `…/ws/sub` and `FOO=bar`. The turn
  took 0.11 s wall.
* **On the dev image** (`/devtools/bin/gears`, `rush`, mock over the TAP
  interface): the same results, with the second `run` printing
  `/user/tmp/exp/ws/sub` and `FOO=bar`. The turn took 0.117 s wall. That
  covers seven provider requests, one curl spawn each, a hook spawn per
  event, and the `rush` runs: roughly 17 ms per provider request.
* **Prompt stability:** in both places, all eight requests, including the
  resumed turn after the memory write, carried a byte-identical system
  prompt and `tools` array.

This exercises §6.4's memory, skills, todo, file and terminal-state
designs on current Gears. It needs no Gears change for one session per
process.

**Prototype: an edit-and-test loop on Motor OS.** The batteries prototype gained
`write_file` and `patch`, about 110 lines together:
* `write_file` refuses to replace a file the session has not read, and
  writes through a temporary file and `rename`.
* `patch` tries, in order: an exact match; `\n`/`\t` unescaping; a
  line-wise match on trimmed lines; and a line-wise match on collapsed
  whitespace. It accepts only a unique match and re-indents the
  replacement to the matched lines.

In the dev VM, a scripted model worked in a crate made by `lorry new`,
through the batteries' tools and the `rush` state wrapper:
1. read `src/main.rs`;
2. wrote `src/lib.rs` with an `add` that subtracted and a unit test;
3. ran `lorry test`, which failed with exit 101 and
   "`left: -1`, `right: 5`";
4. patched with an `old_string` indented by 8 spaces where the file had
   4, which matched through the trimmed-line strategy and was re-indented;
5. ran `lorry test` again: "1 passed".

The whole turn took 4.1 s, most of it two compilations; a bare
`lorry test` of a fresh crate takes about 1 s. This is phase 1's exit
criterion in miniature. One Motor OS detail matters for the tool-output
budget: every compilation printed rustc's "hard linking files in the
incremental compilation cache failed" warning, about 300 bytes each time,
because Motor OS FS has no hard links. Lorry could turn incremental builds
off on Motor OS, or silence the warning. That is a Lorry change, not part
of this plan.

**Prototype: delegation as a nested `gears -p`.** The same hook gained
a `delegate` tool, about 25 lines. It runs
`gears --config <cfg> --ephemeral -p "<goal>"` in the workspace with
`PACK_CHILD=1` set and returns the child's stdout. A later version read
E6's JSON events instead (§6.3). Because `PACK_CHILD` is set, the
child's hook does not offer `delegate`, which gives Hermes's depth-1
rule. The child reads the provider key from the same
key file, so no key passes through the environment. On the dev image a
parent turn that delegated once took 0.085 s wall. That covers three
provider requests, two `gears` processes and their hook spawns. On the
host it took 0.08 s. The recorded requests showed:
* the child was offered every tool except `delegate`;
* the parent's follow-up request carried the child's answer as the
  `tool` result.

A second run gave the hook a 2 s timeout and made the mock stall the
child's reply for 8 s. The parent got `timed out after 2s` as the tool
result after 2.07 s and finished its turn. `ps` in the VM then showed no
surviving `gears`, hook or `curl` process. Gears' Motor OS `kill_tree` walks
the descendants of the hook process (`platform/motor.rs:146-163`), so
cancellation reaches the grandchild. The run also exposed a design
constraint: a hook has one timeout for all of its events (§6.3).

**Prototype: MCP over Streamable HTTP, one process per call.** A
135-line client on the Gears library's `net` module keeps the server's
`Mcp-Session-Id` and its tool list in a small state file. Its first run
does three POSTs: `initialize`, `notifications/initialized` and
`tools/list`. After that, each `tools/call` is a single POST. It reads
JSON and SSE replies. On a 404 for an expired session, it initializes
again once and retries. It also has the `search` half of the §6.4
bridge: a keyword match over the cached tool list.

In the dev VM, against a host mock server with 20 tools that answered
`tools/call` as an SSE stream, times measured inside the process were:

| Step | Time |
| --- | --- |
| First run: three POSTs and a search, where "pull request merge" ranked `pr_merge` first | 9 ms |
| Each of three tool calls | ~2 ms |
| A call after the server dropped all sessions (404, re-`initialize`, retry) | 11 ms |

So Q8's "per-call Streamable HTTP" costs a curl spawn per call and no
Gears change. What remains for MCP is OAuth.

**Prototype: the minimal option, end to end.** The last run put phase 1's
pieces together on the Gears prototypes (§6.3), with no hook tools for
files or the shell. It also used E2 and E13, which belong to later phases
and were present but not required. Its parts:
* **Tool directories (E1):** `read_file`, `search_files` (over
  `/system/bin/rg`), `write_file` and `patch`, each running
  `pack-proto tool NAME` with the arguments on stdin, plus the rush `sh`
  state wrapper. The two read-only tools were marked `parallel_safe`
  (E2).
* **The batteries' hook:** limited by E13 to `initialize`, `permission` and
  `tool_execute`. It contributed the `AGENTS.md` chain and applied the
  hardline floor built from Hermes's 12 patterns.

A scripted model then drove the calc crate of the edit-and-test loop:
1. `search_files` and `read_file`, as one parallel batch;
2. `patch`;
3. `sh` with `lorry test`: "1 passed";
4. `sh` with `ls; rm -rf /`, which the floor refused. The user saw
   "blocked by the hard floor: recursive delete of root filesystem"; the
   model got only "tool call denied" (`runtime.rs:502`), since Gears
   has no channel for a deny reason.

The request showed:
* the `AGENTS.md` text in the system prompt;
* the directory tools and the batteries' hook tools, with no duplicate shell.

The whole turn, a compilation included, took 2.2 s in the VM.

The floor's quote-aware pass passed Hermes's own examples. Quoted prose
such as `echo 'rm -rf /'`, `git commit -m "rm -rf / is bad"` and
`grep '(safe|rm -rf /)' log` did not match. `sudo rm -rf /etc`, the
fork bomb and `ls | cat > /dev/sda` did.

One contract detail showed up. E1 returns every tool's output in the
`sh` representation, "exit status 0, stdout: …", which for file tools is
token overhead the model has to read past. A manifest option such as
`output = "stdout"` could fix it: plain stdout on success, stderr on
failure. It is a suggestion for the E1 plan.

#### Prototypes of the daemons

**Prototype: an HTTP front end as a detached daemon.** A 191-line
`std::net` server (`serde_json` only) served `POST /v1/chat/completions`
in the dev VM. Each request ran
`gears --workspace <ws> [--session <id>] --output jsonl -p "<last user message>"`
with the E6 prototype and the batteries' hook. It returned the `result` record's
text as a chat completion, or the `text` records as SSE chunks when
`stream` was set. Checks, driven from the host with `curl`:
* **Sessions.** A request without `X-Gears-Session-Id` started a new
  session, whose id came back in that response header. Requests that
  sent the id continued it: the mock provider saw 2, 4, 6, 8, 10 and 12
  messages on successive turns.
* **Latency.** A turn took 31–36 ms inside the gateway and 34–38 ms at
  the host `curl`. That covers the gateway, `gears`, its hook spawns,
  `curl` and the host mock.
* **Serialization.** Two concurrent requests for one session were
  serialized by a per-session lock in the gateway (0.033 s and 0.065 s),
  so neither hit the Gears session lock.
* **Large prompts.** A 100,000-character message reached the provider
  intact through `argv`. Motor OS's 4,092-byte limit applies only to a
  process setting its own environment (`setenv`). Environment values given
  to a child at spawn go through the same unbounded path as arguments
  (`create_remote_args` in `rt.vdso`).
* **Refusals.**
  * a wrong bearer key got 401;
  * prior history without a session id got 400;
  * a session id outside `[0-9a-f-]` got 400.
* **Daemon lifetime (Q12).** The server started itself detached
  (`MOTOR_OS_DETACHED=true`) after `gw-proto` was added to `spawn-detached`
  in `/user/cfg/rush.toml`. It kept serving after the ssh session that
  started it had exited. One trap: the start must come from the login
  shell itself, either typed or sourced with `.`. Run as `rush start.sh`,
  the inner `rush` is not on the list, so it holds no
  `CAP_SPAWN_DETACHED` to pass on, and the detach fails with
  `PermissionDenied`. The dead launcher chain (`rush -c` and the first
  `gw-proto`) stays in `ps` as `DEAD` while the daemon lives, and holds
  no memory. `kill <pid>` from a later ssh session stopped the daemon,
  so a pid file is enough for a `stop` subcommand.
* **Approvals.** With E6's stdin channel (Q9), the gateway kept each
  streaming turn's stdin. It forwarded `permission_request` records as an
  `event: permission_request` SSE event, and a `POST /v1/approvals` call
  wrote the answer back. For a turn whose model called `sh`:
  * answering `once` ran the command in the VM, and its output reached
    the model;
  * answering `deny` returned "tool call denied";
  * a non-streaming request, whose stdin is closed at once, was denied
    as unattended.

  The question reached the client 16–17 ms after the request, and the
  whole approved turn took 34 ms. The gateway grew to 218 lines.

**Prototype: a Telegram front end.** A 215-line adapter used the Gears
library's `net` module, so its Bot API calls went through Motor OS's
`/system/bin/curl` under an egress policy. It ran in the dev VM against
a host mock of the Bot API (`getUpdates` long polling with a 20 s
timeout, `sendMessage`, `editMessageText`) and the E6 Gears prototype
with the batteries' hook. What it did:
* It kept one Gears session per chat in a small `sessions.json`.
* It ran one worker thread per chat, so a chat's turns ran in order.
* It streamed a reply as one `sendMessage`, then edits at most once a
  second, then one final edit with the complete text.
* A `permission_request` became a chat question, and a `/approve` or
  `/deny` message from the same chat answered it.

A scripted conversation checked:
* **Continuity:** chat 100's turns saw 2, 4, 6 and 8 messages.
* **Order:** two messages sent back to back were answered in order.
* **Separation:** chat 200 got its own session.
* **Access:** a user outside the allowlist was ignored.
* **Approval:** a `sh` call waited for `/approve`, then ran in the VM,
  and its output streamed back.
* **Edge case:** `/approve` with nothing pending got a short notice.

One detail is specific to Motor OS. The Bot API puts the token in the URL
path, and Motor OS's curl has `--expand-header` and `--variable` but no
`--expand-url`, so the token is in curl's argv. Inside the VM that
exposes nothing: a process's visible name is its first 32 bytes
(`MAX_DEBUG_NAME_BYTES`), and `ps` showed only
`/system/bin/curl --disable --…`. On a Linux host the token would be
readable in `/proc/<pid>/cmdline`, and the adapter must keep URLs out of
its own traces.

The prototype leaves out the following. All but pairing are in §6.5's
~1,800-line estimate:
* splitting replies over Telegram's 4,096-character message limit;
* Markdown escaping;
* backoff on API errors and 429s;
* a policy for messages that arrive mid-turn;
* approval timeouts;
* pairing, which §6.5 defers past v1;
* starting the reviewer after a turn.

### 4.4 Pre-existing Gears issues found by applying Hermes lessons

Hermes guarantees that every `tool_call` in a persisted assistant message
gets a result, synthesizing one on interrupt. It has helpers for that
(`_append_skipped_tool_results` and `_skip_remaining_sequential`,
`agent/tool_executor.py:319, 1703`) and stubs any still-missing result
before each request (`sanitize_api_messages`,
`agent/agent_runtime_helpers.py:3035`). Its regression tests include
`tests/agent/test_tool_call_incremental_persistence.py`. Gears persists
the assistant tool-call message first (`src/runtime.rs:295`) and then
executes calls one at a time. Nothing adds the missing results
when that loop ends early. The early exits are:
* cancellation after any call but the last (`runtime.rs:306-315`);
* with any hook configured, cancellation during *any* call, including a
  single one. The `tool_result` hooks then run under the already-cancelled
  token and fail, usually reported as a stdin "Broken pipe" (see the
  second defect below), and the `?` at
  `runtime.rs:527` exits before the result is appended at `:535`;
* other errors inside `execute_call` (`runtime.rs:470, 496, 527`) or from
  the observer after the assistant message is appended (`:296-302`);
* the process dying mid-call.

Neither `Session::context_messages` nor `wire_messages` in
`src/provider/openai_compat.rs` repairs the unpaired calls.

Reproduced on the host build of `2ff1400c`:
1. A mock provider answered "run two commands" with two `sh` calls, the
   first being `sleep 5`.
2. Gears ran with a permission hook that allows everything, and was killed
   during the first call.
3. `gears --session <id> -p "next question"` then sent:

```text
system; user "run two commands"; assistant tool_calls=[call_a, call_b]; user "next question"
```

No `tool` message follows the assistant message. OpenAI-compatible
endpoints and the Anthropic API reject requests whose tool calls lack
results. Hermes commit `c7761573f5` records the DeepSeek wording: HTTP 400,
"An assistant message with 'tool_calls' must be followed by tool messages
responding to each 'tool_call_id'". So after such an interruption, every
later turn in the session fails until the user selects an earlier entry.
The mock used here does not validate this, so the failure itself was not
observed against a real provider.

A second run sent SIGINT, which is how Gears sees Ctrl+C, during a
single `sh` call with one hook configured. It produced
`assistant tool_calls=[call_a]; user "next question"`: an ordinary Ctrl+C
in a session with hooks is enough.

Hermes's remedy, applied to Gears, has three parts:
* when a tool round ends early, append an error result ("not executed:
  turn cancelled") for each remaining call;
* when a `tool_result` hook fails because the turn was cancelled, append
  the untransformed result rather than none;
* when building context, synthesize an error result for any call still
  unpaired, which covers crashes.

This is a core Gears change, reported for the user's decision and not
made in the repository. The plan depends on it and schedules it as part
of E0, in phase 1 (§6.3, §7). A scratch prototype of parts 1 and 3
(§6.3), about 70 lines of code plus three regression tests, makes both
reproductions produce valid requests. Part 2 needed a ~10-line follow-up
with its own test. Without it, a call that ran but whose result hook the
cancel killed was recorded as "not executed: turn cancelled", which
invites the model to run a command with side effects again.

A related shape remains even when every call has a result. Suppose a
turn is cancelled or fails after its tool round, for example on Ctrl+C
while the model streams its next reply. The turn leaves a `turn_error`
entry, which `context_messages` skips (`session.rs:491-521`), so the
next request ends `assistant tool_calls; tool; user`. A host run of
`2ff1400c` reproduced this: SIGINT during the provider call after one
`echo` round gave the next request the roles `system, user, assistant,
tool, user`.
* **Why it matters.** The request is valid. Hermes itself keeps `tool →
  user` for mid-turn steering (`agent/agent_runtime_helpers.py:3498-3512`).
  After an interrupt, however, Hermes appends a closing assistant message
  (`close_interrupted_tool_sequence`,
  `agent/message_sanitization.py:285-297`). Its docstring says Gemini and
  Claude otherwise read the pattern as a continuation of the interrupted
  turn. That claim concerns model behaviour and was not tested here.
* **Remedy in Gears.** Render a short assistant closer from the
  `turn_error` entry when the branch ends in a tool round. The session
  file does not change, and the prompt stays byte-stable.
* **Rejected alternative.** A structural rule that closes every `tool →
  user` is wrong: it would also close E6's mid-turn steering message. The
  steering test caught this in the prototype.
* **Prototype.** About 10 lines plus one test (§6.3).

A second cancellation defect showed up while prototyping E6. After a
cancelled turn, no lifecycle hook runs until the next turn starts.
* **Mechanism.** The token is reset only when `Runtime::turn`
  (`runtime.rs:214`) or `compact` (`:337`) starts. `Cancellation::cancelled`
  also stays true while the process-wide interrupt flag is pending
  (`cancellation.rs:23-25`), so a fresh token would not help. Three
  callers send events under the still-cancelled token:
  * the end of the cancelled turn itself: its `turn_error` `entry` event
    (`:284-289`, `:309-314`) and `turn_end` (`:242-243`);
  * `install_session` (`/new`, `/resume`, `/clone`, `/fork`, `:417-456`);
  * `close` at exit (`:405-415`).
* **Effect.** `process::run` sees the cancellation on its first poll and
  kills each hook as it spawns. Then the stdin writer's `EPIPE` wins over
  the cancelled status (`process.rs:178-183`), so the user usually sees
  `hook … failed during session_end: … stdin: Broken pipe (os error 32)`.
  The `turn_end` payload that `turn()` builds with
  `"status": "cancelled"` (`runtime.rs:235-240`) therefore never reaches
  a hook.
* **Reproduced** on the host build of `2ff1400c`, in the interactive line
  UI with the batteries prototype's hook plus a second hook that logs event
  names:
  1. `sleep please` (the mock answers with a call to the prototype's `run`
     tool running `sleep 5`);
  2. SIGINT during the tool;
  3. `/new`;
  4. `/quit`.

  The log ends at `permission`. The hooks never receive:
  * `turn_end`;
  * the old session's `session_end`;
  * the new session's `session_start`;
  * the final `session_end`.

  Gears reported nine hook failures instead, eight of them as "Broken
  pipe" and one as "cancelled". A `-p` run cancelled
  the same way loses `turn_end` and `session_end`. This path writes no
  `turn_error` entry at all: the hook failure at `:527` returns through
  the `?` at `:307` before `:309`. Where one is written, after a cancel
  during the provider stream (`:284-289`) or during a call with no hooks
  (`:309-314`), its `entry` event is lost the same way.
* **Why it matters here.** The batteries need these events:
  * memory and learning-loop state is flushed at `session_end`;
  * the gateway ends a chat's session;
  * E12's re-`initialize` on a session switch would be killed in the
    same way.
* **Fix.** About ten lines, plus a small refactor of the turn's error exits:
  * reset the token before the lifecycle notifications in
    `install_session` and `close`;
  * send the cancelled turn's `turn_error` entry and `turn_end` under a
    reset token, since hook timeouts still bound them. The four error exits
    of the turn loop become one helper that records the error, remembers
    whether the turn was cancelled, resets the token and notifies;
  * in `process::run`, report cancellation or timeout ahead of a stdin
    `EPIPE`.

  It is reported, not made, like the first defect. A scratch prototype
  of the fix is 12 lines of code with one regression test (§6.3). A
  second prototype commit covers the `turn_error` entry, which the first
  one missed; the error-exit helper makes that commit net +2 lines.

A third defect came from comparing compaction with Hermes's: **one
oversized tool result can wedge a session for good.**
* **What Gears does.** It sends the `older` messages to the model
  unchanged as the summarizer's input (`runtime.rs:674-690`). It fails
  the compaction when the summary plus the retained tail still exceed the
  limit (`:703-711`). Tool results have uneven bounds:
  * `sh` output is capped at 32 KiB per stream (`runtime.rs:19, 595`);
  * a hook tool's result is capped only by that hook's `max_output_bytes`,
    1 MiB by default (`config.rs:265`); larger output is an error, not a
    truncation (`hooks.rs:408-413`);
  * any hook's `tool_result` transform can replace even an `sh` result
    with up to its own `max_output_bytes` (`hooks.rs:268-290`);
  * nothing bounds a round's total.
* **Reproduced** on the host build of `2ff1400c`. The setup:
  * `window_tokens = 8192`;
  * a mock that answers HTTP 400 `context_length_exceeded` above 36,000
    request bytes, as a provider would;
  * one hook tool call that returned 40,007 bytes.

  Results:
  1. The first turn failed with "compacted context still exceeds the
     model limit", because the result sat in the retained tail.
  2. Every later turn on the session failed with
     `compaction failed: provider error 400: maximum context length…`,
     because the result had moved into the summarizer's 40,610-byte input.
     Nothing trims that input, so the session stays unusable until the
     user picks an earlier entry with `/tree`.
* **At the default 128K window** two thresholds apply:
  * A turn *fails* once the retained tail exceeds Gears' hard limit
    (~111.6K tokens): one ~450 KB hook-tool result, or about seven full
    `sh` results in one round.
  * The session *wedges* once the messages to summarize exceed the
    provider's real limit, roughly 500 KB of tool output at 4 bytes per
    token.

  A 32K local model does not wedge on one full `sh` result (~16.4K
  tokens): the first turn fails, but the next summary request fits. The
  default configuration also rejects a 32K window unless
  `recent_tail_tokens` is lowered below 16,384 (`config.rs:338-343`).
* **What Hermes does** (`agent/context_compressor.py`):
  * it serializes turns to redacted text for the summarizer;
  * it truncates each message and each tool-call argument;
  * it caps the whole input at 160,000 characters, keeping head and tail
    (`_SUMMARY_INPUT_MAX_CHARS`, `:834`, `_bound_summary_input`,
    `:3552`);
  * it demotes oversized tail results under pressure
    (`_pressure_demote_tail`);
  * if a separate summary model fails, it retries once on the main model;
    otherwise it arms a cooldown, and a static fallback summary built from
    locally extracted anchors stands in (`_on_summary_failure`, `:4044`;
    `_build_static_fallback_summary`, `:3439`).

  A text transcript also keeps the summary request free of tool-call
  structure, so wire pairing rules cannot fail it. That matters once E3b
  adds a second wire.
* **Fix.** It is the third part of E0 (§6.3); it is recorded here because
  it is a defect in today's Gears. A scratch prototype of about 75 lines, with
  two regression tests, unwedges the reproduction (§6.3).

A related pre-existing issue in the base image affects any agent on
Motor OS. 26 of the 29 command scripts in `img_files/motor-os-base/system/bin`
pass `$@` unquoted: 25 forward their arguments as
`/system/bin/sysbox <cmd> $@`, and `exit` runs `exit $@`. `sh` uses
`"$@"`, and `df` and `uname` take no arguments. Arguments that contain spaces are
therefore split again. In the standard image, `cat "/user/tmp/exp/a b.txt"`
failed with NotFound for `/user/tmp/exp/a` and for `b.txt`, while
`/system/bin/sysbox cat "/user/tmp/exp/a b.txt"` printed the file. Quoted
globs such as `find . -name "*.rs"` are exposed the same way. Models
quote paths with spaces routinely, so the fix (`"$@"` in 26 files) matters
to any agent session. It is an image change outside this plan's scope, reported
rather than made.

Three smaller observations came from the same exercise. The first two
were reproduced with the recording mock:
* **Empty assistant turns (latent, provider-dependent).** A stream that
  carries only reasoning and ends with `finish_reason: stop` is persisted
  as an assistant message with no content blocks and no tool calls, and
  replayed on every later turn as `{"role": "assistant", "content": null}`. Hermes's Anthropic converter notes that
  empty assistant content is rejected
  (`agent/anthropic_message_convert.py:422`), and OpenAI's schema requires
  content when there are no tool calls. Hermes drops such turns or
  substitutes a placeholder.
* **Parallel calls that reuse index 0 (compatibility).** The assembler keys
  tool-call deltas by index and keeps the first id
  (`src/provider/assembler.rs:64-83`). Two calls with different ids at
  index 0, which Hermes's accumulator comments attribute to Ollama, merge
  into one call with arguments
  `{"command": "echo a"}{"command": "echo b"}`, which fails as "invalid
  sh arguments". This is protocol-valid and recoverable. Hermes opens a
  new slot when a new id appears at a seen index.
* **Reasoning is not replayed (compatibility; documented by Hermes, not
  reproduced here).** Gears parses `reasoning` and `reasoning_content`
  deltas (`src/provider/wire.rs:34-37`), but `Completion::message` stores
  only the text and the tool calls (`src/provider/types.rs:241-243`).
  Hermes records that DeepSeek V4, Kimi/Moonshot and Xiaomi MiMo thinking
  modes answer HTTP 400 ("The reasoning_content in the thinking mode must
  be passed back to the API") when a replayed tool-call turn lacks it.
  Hermes echoes the captured reasoning, or pads it with a single space
  (`agent/chat_completion_helpers.py:1682-1690`,
  `agent/reasoning_params.py:163-208`; Hermes #15250, #17400). With those
  models in thinking mode, a Gears tool round would then fail on its
  second request. Testing that needs the real endpoints, so it was not
  tried.

## 5. Porting options

### 5.1 Option 0: run Hermes itself

Running the Python on Motor OS needs:
* the CPython port (§4.2);
* an OpenSSL port for `ssl`;
* statically linked native extensions (`pydantic-core` and `jiter` are
  Rust, `cryptography` is Rust plus OpenSSL, and `psutil` has no Motor OS
  backend);
* SQLite with the §4.3 workarounds.

Past that, Hermes's local terminal backend runs `bash`: its snapshot uses
`declare -F`, `${!PREFIX*}` and `builtin cd`. Its file tools run coreutils
scripts (`sed`, `cut`, `base64`, `mktemp`, `stat -c`, `sha256sum`,
`readlink -f`), and none of these are on Motor OS. `ptyprocess`,
`prompt_toolkit` and the setsid/killpg process control would all need
replacing or stubbing.

The prize would be a 700K-line, 331-package application running degraded
on an OS whose stated priorities are simplicity, boot time and security.
Running Hermes on a Linux host with Motor OS as its SSH execution backend
fails for the same reason: that backend also runs `bash -c` and the same
coreutils scripts in the guest. **Not recommended.**

### 5.2 Option A: module-by-module translation

Translating the Python structure would carry over:
* the mixin facades;
* the reflection-driven phase machine;
* the multi-process SQLite machinery;
* the profile multiplexing;
* the provider folklore.

The result would be well over 100K lines of Rust that encode Python-host
problems Motor OS does not have. **Not recommended.**

### 5.3 Option B: a standalone reimplementation of the core

This means a new Rust binary implementing the ~30K essential lines of review §11.2.16
as ~25–35K lines of Rust, with its own provider, HTTP, session, process and
UI layers. It is feasible and self-contained. However, it duplicates
roughly 9K lines of Gears infrastructure: provider, curl seam, SSE,
sessions, process runner, UIs and mock provider. It also leaves Motor OS with
two harnesses to maintain. It is the right choice only if Gears must stay
frozen or be retired. Appendix B lists its crates and sizes.

### 5.4 Option C: Hermes capabilities on the Gears foundation (recommended)

Most of what makes Hermes useful is not a different loop. It is the
capabilities the loop carries:
* native file tools;
* context files;
* memory;
* skills with a review loop;
* task lists;
* session search;
* delegation;
* MCP;
* code mode;
* scheduled jobs;
* a messaging front end.

Gears already has the loop, and its redesign names the intended homes for
such capabilities: hooks, tool directories (planned) and prompt resources.
Option C ports the capabilities onto that foundation and changes Gears
only where a capability cannot live outside it.

Hermes capabilities, and where each would live:

| Capability | Fits outside Gears? | Mechanism |
| --- | --- | --- |
| Memory (`MEMORY.md`/`USER.md`, frozen per session) | yes, plus E12 for in-process session switches | `initialize` hook adds the snapshot as a prompt fragment and registers `memory`; the frozen snapshot is kept as namespaced hook state so the prompt stays byte-stable across resumes |
| Skills index, `skill_view`, `skill_manage` | yes | `initialize` fragment plus hook tools; files under `/user/cfg/gears/batteries/skills` |
| Project context files (`AGENTS.md` chain) | yes | `initialize` fragment |
| Subdirectory hints | yes | `tool_result` hook with namespaced "already announced" state |
| Todo list | yes | hook tool with namespaced session state; follows branches |
| File tools (read, write, patch, search) | yes | one external tool binary; §6.4 |
| Session search | yes | external tool over the JSONL session files |
| Delegation | yes | external tool running a child `gears --ephemeral -p "<goal>"` with a restricted configuration |
| Web search and extract | yes | external tool using curl |
| Dangerous-command policy, redaction | yes | `permission` and `tool_result` hooks; Gears deliberately keeps these out of the core |
| MCP servers | partly | per-call spawn works for stateless stdio servers and for HTTP servers; long-lived stateful servers need a client owned by Gears |
| Code mode (Monty) | partly | read-only tool subset in an external tool; calling tools that need approval needs Gears |
| Background review (learning loop) | partly | the reviewer is a forked Gears run, but forking a live session needs a lock-free read (E11) and a trigger. A `turn_end` hook could start a detached reviewer only if Gears holds `CAP_SPAWN_DETACHED` (granted per program by `rush.toml`'s `spawn-detached`) and passes it to the hook explicitly, since spawn defaults never propagate it (`docs/caps.md`); a Gears "after turn" job (E7) is simpler |
| Parallel read-only tool batches | no | Gears |
| Anthropic Messages, prompt-cache markers, reasoning replay, retries | no | Gears (provider layer) |
| Cron and messaging gateway | beside it | small daemons that drive Gears; needs a JSON event mode for `gears -p` |

This table suggests two packagings:

* **C1: batteries plus targeted Gears upgrades.** One new crate,
  `gears-batteries`, builds a multi-call binary. Its subcommands
  are the hooks and tools above, plus the reviewer, cron and gateway.
  Gears changes cover the "no" rows, the review row and the process seams
  the batteries need (§6.3), each argued on its own merit. Most are generic provider improvements
  (Anthropic wire, caching, retries) that Gears would want anyway.
* **C2: an in-process distribution.** A new binary links Gears as a
  library and registers the same capabilities as native Rust tools, with
  its own policy for the prompt, review and daemons. It is faster to build
  and more faithful to Hermes, but it creates a second front end whose
  loop behaviour may drift from Gears.

**Recommendation: C1.**
* It matches the direction already chosen for Gears. Gears was a 44.5K-line
  harness with built-in modes, tasks, checkpoints, verification and
  sub-agents until 2026-08-25, when it was rewritten into today's minimal
  core (`d4513477`). Hermes's core would re-grow what that rewrite removed.
* Every capability is optional and reviewable on its own.
* Process isolation contains crashes, and approval identity stays per
  tool.
* Measured costs are negligible next to model latency (§4.3): ~1.4 ms
  per `rush` spawn, 2–20 ms per hook per turn, ~36 ms for a whole
  `gears -p` turn. With one multiplexing hook for all the batteries (§6.3), a tool call
  adds a handful of spawns.

Design every tool behind one contract: JSON arguments on stdin,
model-facing text on stdout, failure as a non-zero exit. Gears shows a
process tool's result to the model as the `sh` representation: exit
status plus bounded stdout and stderr (`external-tools.md`,
`src/process.rs:47-60`). A tool that later moves in-process (C2) keeps its
schema and tests.

C1 still grows Gears. Gears today is 12.5K raw lines of Rust, 11K lines
of code, ~8.5K of it outside inline unit tests. The Gears changes of
§6.3 (E0, E2–E13) add ~2.7K lines, about a third of that
non-test code; with E1's ~1.4K, planned for Gears anyway, ~4.1K, nearly
half. About 2.1K of it would be written under C2 too; only ~560 lines
exist because C1 works through processes, plus a ~30-line optional
filter. §6.3 argues each item, and
§8.1 covers those with real alternatives (E5, E6, E7 with E11, E10,
E12). By group:
* **Required under C1 or C2:** the fixes (E0) and the provider and
  compaction work (E3a, E3b, E4, E5, E8), ~1.6K lines. They would land
  in the Gears library under C2 just the same.
* **Required only by C1:** JSON events and steering (E6), the after-turn
  job (E7), the read fork as a CLI flag (E11) and hook re-initialization
  (E12), ~560 lines, plus the optional event filter (E13, ~30). E1 is in
  this group too, but it is already planned for Gears' own sake.
* **Optional or phase-dependent:** parallel batches (E2), images (E9,
  image input to the model) and the sandbox (E10, opt-in interactively
  but the default for cron jobs from phase 6), ~560 lines.

C2 avoids the middle group and several C1 frictions:
* the single hook timeout, which constrains every hook tool (§6.3);
* a process spawn per hook event;
* state spread over hook state, snapshot files and daemon state files.

In exchange, C2 needs two things:
* a stable Rust API for the runtime, with a seam for native tools;
* a second front end whose loop behaviour can drift from `gears`.

It also gives up crash containment and per-tool approval identity. It
runs against the direction of Gears' redesign, which names hooks, tool
directories and prompt resources as the extension points. C1 remains the
recommendation because its Gears-specific cost is small (~560 lines) and
each piece is reviewable alone. C2 is the fallback if the user rejects
those Gears changes.

There is also a minimal option, available under either packaging:
phase 1 of §7 alone, about 5.3K lines of code with all of E1 (4.7K as
phase 0 recommends), plus as much in tests. It comprises:
* the Gears fixes (E0) and E1;
* the file tools and the policy floor (a deny list of `sh` commands that
  no approval overrides);
* the terminal state, context files, hints and todo;
* phase 1's security hardening (§6.7).

Adding E3a (with the index-0 fix) and E4, ~250 lines, brings the provider
fixes that help any Gears user; phase 0 asks whether to. Phase 1 covers
the capabilities the prototypes exercised most. The remaining ~12.6K
lines (counting all of E1 in phase 1) should wait for evidence from
real-model sessions: ~10.1K of code in the batteries (memory and skills,
the learning loop, delegation, MCP, code mode, the daemons) and ~2.5K of
other Gears changes.

### 5.5 Not evaluated here

Other open-source agent harnesses are already written in Rust, for example
OpenAI's Codex CLI (`codex-rs`) and Block's Goose. Adopting one instead of
porting Hermes's ideas is a separate question and was not assessed for
this document.

## 6. Proposed design

This section describes option C1. Subcommand names such as
`gears-batteries cron` are placeholders (§8, Q10).

```text
             user (line UI / TUI)        chat (Telegram)        schedule
                     │                         │                    │
                     ▼                         ▼                    ▼
               ┌──────────┐     gears-batteries gateway    gears-batteries cron
               │  gears   │◀─ runs `gears --output jsonl -p` per turn ─┘
               └────┬─────┘
     hook events,   │  tool calls (JSON on stdin, text on stdout)
     one process    ├──────────────▶ gears-batteries tool read_file | patch
     per event      │                 | search_files | session_search | web
                    │                 | mcp | delegate ─▶ gears -p
                    ├──────────────▶ gears-batteries hook (memory, skills,
                    │                 context, todo, policy)
                    ├──────────────▶ sh (rush -c, state wrapper)
                    └── after_turn ─▶ gears --read-fork <session> -p (review)

  state: /user/cfg/gears/{sessions, batteries/{memories, skills, cron}}
```

### 6.1 Principles

* **No second loop.** Every model turn, whether interactive, delegated,
  reviewed, scheduled or from a chat, is a Gears turn. Everything else is a
  hook, a tool, or a small daemon that runs `gears`.
* **Pure-Rust dependencies**, so the batteries build natively with Lorry like
  Gears. That means serde, serde_json, regex (with `fancy-regex` for the
  few lookaround patterns), sha2, a YAML crate and jiff (Q11), and the batteries reach
  HTTP through Gears' curl seam. SQLite is optional and deferred (Q2).
* **Threads, not async**, matching Gears.
* **Port Hermes's tuned prompt text as data files**, with the MIT notice
  kept (§6.8). Do not port its recovery folklore; add a behaviour only
  when a test or a real failure demands it.
* **Keep the tool schemas small.** Gears' documented llama.cpp setup uses
  a 32K-token context. Hermes needs 64K and spends ~35K tokens per
  request on its system prompt and schemas (review §11.2.4). The batteries' default
  enabled set should stay under ~6K tokens, measured by a test. Hermes's
  own schemas for 13 of the tools the batteries keep already total ~5.1K
  tokens (20.6K characters; `session_search` and `memory` alone are 7.5K
  characters). Meeting the target therefore means rewriting descriptions
  tersely, not copying them. A draft of all 13 default tools in that style
  is ~1.4K tokens (Appendix C).

### 6.2 Layout

```text
src/bin/gears/                 Gears changes only (§6.3)
src/bin/gears-batteries/
  Cargo.toml                   serde, serde_json, regex, fancy-regex, sha2, a YAML crate, jiff;
                               gears as a path dependency for its public `net` (curl seam,
                               egress policy, SSE), `process` and `session` modules; repeats
                               Gears' `[patch.crates-io]` crossterm entry, since patches apply
                               only at the root
  src/main.rs                  multi-call: gears-batteries {hook|tool|review|curator|sandbox|cron|gateway} NAME
                               (cron may become its own binary for jiff's tz data, Q11)
  src/hook/                    one multiplexing hook: memory, skills, context, hints, todo,
                               policy, redact
  src/tool/                    read_file, write_file, patch, search_files, session_search,
                               delegate, web, mcp, code
  src/cron/, src/gateway/      daemons (phase 6)
  prompts/                     ported prompt text (NOTICE.md carries the Hermes MIT notice)
  tools/<name>/                tool.toml, parameters.json, prompt.md per the Gears contract
  config/                      example gears.toml fragments: [[hooks]] and [[tools]]
```

State lives under `/user/cfg/gears/batteries/` on Motor OS, next to Gears'
sessions, and under `~/.gears/batteries/` on Linux:

```text
memories/{MEMORY.md,USER.md}
snapshots/<sha256>.md             frozen prompt fragments, referenced from hook state
skills/<category>/<name>/SKILL.md
cron/jobs.json
```

Because it sits under `/user/cfg`, None-role processes cannot read it
(§6.7).

### 6.3 Changes to Gears

Each item below is its own series of patches; the text notes where one
depends on another (E2 on E1, E3b on E3a, E8 on E0, E12 on E0's
lifecycle fix). Sizes exclude tests.

| # | Change | Why in Gears | Size |
| --- | --- | --- | ---: |
| E0 | The three §4.4 fixes: close unpaired tool calls, keep a result that ran when its result hook was cancelled, close a tool round that a turn error ended, and never store an empty assistant reply; deliver lifecycle hooks, including the `turn_error` entry, after a cancel; and bound compaction's input (the wedge). | They are defects, and long-lived sessions, E12 and the gateway depend on them. | ~220 (the prototypes' code adds ~230 and removes ~55) |
| E1 | Implement `src/bin/gears/plans/gears-external-tools.md` as planned: manifests, a process executor that replaces the built-in `sh`, enablement state, scoped approval grants, commands in both UIs, and `sh`/`ls` tool directories. | Tool directories, per-tool timeouts and the `sh` state wrapper (§6.4) all need it. | ~1,400 (this document's reading of its seven steps; the plan gives no figure): parsing ~250, the executor with runtime and approval identities ~200, enablement state ~300, scoped grants ~320, UI commands and prompts ~250, the `sh` and `ls` directories ~50. Step 7 is the gate. The port needs steps 1, 2 and 6 (§7), and two rules added to that plan: its `{field}` templates follow `--`, or the executor rejects values that start with `-` (step 2); and, when step 4 lands, saved grants apply only in the interactive UIs (§6.7). A prototype of the core took ~275 lines: loading, templates, and execution replacing the built-in `sh` (§6.3). Suggested addition: a manifest `output = "stdout"` mode, so file tools return plain text rather than the `sh` representation (§4.3). |
| E2 | `parallel_safe` manifest flag for E1 external tools. For a run of consecutive calls to such tools: decide permissions one by one first, then execute the allowed calls concurrently, then run `tool_result` hooks and append results in call order. Hook tools stay sequential, because a hook's reply can update its session state (`execute_tool` takes `&mut Session`, `runtime.rs:505-515`). The batteries' parallel candidates (`read_file`, `search_files`, `session_search`, web) are external tools anyway. | Batch ordering is loop policy. | ~200 (a prototype took ~115 net lines without live output streaming for batches) |
| E3a | Keep reasoning in the stored assistant message and echo it as `reasoning_content` on the Chat Completions wire for the providers that require it (§4.4). A new content block needs a session-format rule (§8.3). With it, the assembler fix for parallel calls that reuse index 0 (§4.4; ~15 lines prototyped). | Message model and wire. | ~100 |
| E3b | An Anthropic Messages adapter behind the `Provider` trait, selected by `provider.api = "anthropic"`. The `Reasoning` block of E3a gains an optional signature, so signed thinking can be replayed; Gears' content-block messages map onto Anthropic's blocks more directly than Hermes's OpenAI dicts. Native `cache_control` markers come with it. The prototype (§6.3) took ~410 lines without thinking configuration, images or other API extras. | Wire formats live in the provider. `redesign.md` asks for new normalized fields "only when a second real adapter proves they are needed"; this is that adapter. | ~600 |
| E4 | Prompt-cache markers on the Chat Completions wire, Gears' default through OpenRouter: the system prompt and the last two messages that can carry a marker, following the envelope layout Hermes uses for Claude, Kimi and some Qwen routes (Hermes's main loop places four breakpoints, two of them on the system prompt, `agent/prompt_caching.py:296-330`; the prototype places three); and OpenAI's `prompt_cache_key`. For Kimi without markers Hermes records ~1% cache hits, and with them a within-turn climb of 1% → 67% → 84% → 97% (`agent/agent_runtime_helpers.py:1635-1718`, #25970). Native Anthropic `cache_control` is part of E3b, so E4 does not depend on E3b. | Request assembly. | ~150 |
| E5 | Opt-in bounded retry: jittered backoff for 429, 5xx and transport errors, honouring `Retry-After`, only before visible output, and never for an error caused by our own cancellation. With retries on, a reply that ends as `tool_calls` but carries none gets a runtime note asking for the call, at most three times in a row (Hermes's dropped-call recovery). Today Gears ignores `finish_reason` and ends the turn with the narration as the answer. | Gears deliberately does not retry today (Q7). | ~120 |
| E6 | `--output jsonl` for `-p` runs: runtime events as JSON lines on stdout. A `session` record first (a protocol version, and the id and path so a gateway can resume the chat later); then `text`, `reasoning`, `tool_start`, `tool_output`, `tool_end`, `permission`, `notice`, `usage` and `turn_end`; and a final `result` record with `ok`, `error`, the final answer text and usage. A `permission_request` record is answered by a JSON line on stdin; a closed stdin denies (Q9). A `{"type": "steer"}` line on stdin queues guidance for the running turn. It is delivered after the current tool round as its own user message, wrapped in Hermes's out-of-band marker. The system prompt carries Hermes's short note that only this exact marker is a genuine user message (`STEER_CHANNEL_NOTE`, `agent/prompt_builder.py:571-584`, ~0.8K characters). Hermes added the note in #40240 after models refused bare mid-turn guidance as injection. The prototype has the marker but not yet the note. | Needed by delegation, the reviewer, cron and the gateway. | ~300 |
| E7 | An `after_turn` job: run one configured command after a delivered turn while the prompt waits; the next input cancels it, as Hermes cancels its review when a live turn starts ("self-improvement work must never block a user-facing turn", `agent/background_review.py:120-143`). For `-p` runs, the gateway starts the reviewer itself between messages. The runtime owns the job: it starts it after a completed turn and kills its process tree when the next turn starts, on a session switch, and at `close`. No UI changes. | The learning loop without detached spawns (Q5). | ~80 |
| E8 | Compaction (`runtime.rs:618-730`, estimate at `:836-850`):<br>• after E0's bounded input: spill oversized tool results to a file with a preview, as Hermes does, rather than only truncating them;<br>• prune old tool results before summarizing;<br>• keep tool groups whole (partly done);<br>• feed the previous summary back in;<br>• use the structured template as a prompt resource;<br>• frame the injected summary as reference only, as Hermes's `SUMMARY_PREFIX` does (`agent/context_compressor.py:252`). Gears injects it as a plain `[Conversation summary]` user message, and Hermes saw models re-run finished tasks from such summaries (#8107, #41607). Its prefix also states that tools remain active, because a stronger framing produced narration-only turns;<br>• anchor token estimates on the provider's last reported `prompt_tokens`, taking the larger of that and JSON bytes ÷ 4, which undercounts CJK text;<br>• force one compaction attempt when the provider reports a context overflow (Hermes `agent/usage_anchor.py`, `agent/turn_overflow.py`). | Compaction belongs to Gears. Hermes's compressor is 5,612 lines in 275 functions. The list here is its essential subset, excluding its image eviction, telemetry and lean-sampling modes. Prototypes of E0's part and of pruning, iterative summaries, framing, the forced compaction on overflow, spilling and anchored estimates took ~255 lines together. | ~400 |
| E9 | Image content blocks (`vision`): read a local image and attach it on the provider wire. Low priority on Motor OS, which has no screenshots, browser or camera, so images arrive only as files. | Message model. | ~300 |
| E10 | Sandbox mode: spawn `sh` with `MOTOR_OS_CAPS` for the None role; in that mode the batteries' file tools do their I/O in a None-role child (§6.7). Opt-in for interactive use, the default for a cron job's `allow` (phase 6). The `/user/cfg` start check and the None-role file I/O are code in the batteries, counted in §6.9. | Spawn policy. | ~60 |
| E11 | `--read-fork <session>`: without taking the source's lock, copy its active branch into an ephemeral session (§6.4). | Session opening and locking belong to Gears. | ~80 |
| E12 | Re-run hook `initialize` when the runtime switches sessions (`/new`, `/resume`, `/fork`, `/clone`) and after a compaction. Rebuild fragments and tools from the new session's hook state. Today it runs once per process (`runtime.rs:126-138`); `install_session` sends only lifecycle events (`runtime.rs:417-456`), and `after_compact` cannot return fragments. The README already says hook manifests are loaded "when a session is opened". | Session lifecycle. | ~100 |
| E13 | Optional per-hook event filter (`events = [...]`), so a hook is not spawned for events it ignores. | Hook dispatch. | ~30 |

E1 is a hard prerequisite of phase 1: the tool directories, the `sh`
state wrapper and per-tool timeouts all need it (§7). After that, E12
unlocks phase 2, and E6 and E11 unlock phases 4 and 6.

To test these estimates, a scratch copy of Gears at `2ff1400c` received
prototypes of the three E0 fixes and of thirteen other changes: E1's
core, E2, E3a, E3b, E4's OpenRouter cache markers, E5, E6 with approvals
and steering, E7, most of E8, E10, E11, E12 and E13. E9, the rest of E1,
E8's template resource, and E4's `prompt_cache_key` were not
prototyped. The prototypes are not in the repository.

| Change | Diff, tests included | New tests |
| --- | --- | --- |
| The §4.4 fix: close unpaired tool calls on early exit and when building context; never persist an empty assistant reply | +204/−5 | 3 |
| E11 `--read-fork` | +46/−3 | 1 |
| E12 `initialize` on session switch and after compaction, with a `reason` field in its payload | +121/−35 | 1 |
| E6 `--output jsonl` (a new `ui/jsonl.rs` front end beside `line` and `tui`, 165 lines), with stdin approvals | +298/−1 | 3 |
| The §4.4 compaction wedge, E0's third fix: bounded summarizer transcript, halving the largest retained result until the context fits, a 64 KiB cap on every tool result | +176/−17 (~75 of code) | 2 |
| E7 after-turn job (`runtime.after_turn`, with `{session}` substituted) | +121/−1 (~60 of code) | 2 |
| E3a reasoning echo: a `Reasoning` content block kept in the stored message; a `reasoning_echo` endpoint quirk (DeepSeek and Moonshot hosts) that sends it, or a single space, as `reasoning_content` on assistant tool-call messages | +80/−5 (~50 of code) | 1 |
| E4 on the Chat Completions wire: a `cache_markers` quirk (OpenRouter) that, for Claude and Kimi model names, turns the system prompt and the last two messages that can carry one into marked text parts | +83 (~50 of code) | 1 |
| The second §4.4 fix: reset the token before `turn_end`, `install_session` and `close`, and report a cancel or timeout rather than the stdin `EPIPE` it caused | +67/−3 (12 of code) | 1 |
| Steering for E6: a queue on the runtime, drained after each tool round into a marked user message, and fed by `{"type": "steer"}` lines on stdin | +120/−2 (~48 of code) | 2 |
| E5 opt-in retry (`runtime.retries`, 0 to 5): in the runtime, which knows whether anything was shown; a cancel during the wait returns the error | +175/−7 (~95 of code) | 3 |
| E10 sandboxed `sh` (`runtime.sandbox`): `MOTOR_OS_CAPS` set to spawn-only for the `sh` child on Motor OS; nothing on Linux | +35/−3 | 0 (tested in the VM) |
| E8, three more bullets: the summary framed with a reference-only prefix adapted from Hermes; a previous summary fed back to the summarizer to update; all but the last three tool results in the summarizer's input reduced to one-line stubs | +129/−2 (~60 of code) | 1 |
| E8, one more bullet: a provider's own context-overflow report (a 400 or 413 whose detail names the context length) forces one compaction and a retry of the round | +88 (~38 of code) | 1 |
| E1 core (steps 1–2 of its plan, without display templates or tool prompt fragments): `[[tools]]` directories loaded and validated, whole-field `{field}` templates, execution through the bounded process runner with the tool's own timeout, and a configured `sh` directory replacing the built-in `sh`; fixtures include the `sh` state wrapper for Linux and for rush | +427/−1 (~275 of code) | 4 |
| E1's argument rule (§6.7): before a `--` in the command, a `{field}` value may not start with `-`; after it, it is data | +25/−9 (~12 of code; assertions added to the template test) | 0 |
| E2 on E1's tools: a `parallel_safe` manifest flag; permissions decided one by one, the calls run on scoped threads, results appended in call order | +209/−39 (~115 net of code) | 1 |
| E13 per-hook `events = [...]`: a hook not listing an event is not spawned for it and counts as having no opinion | +58 (12 of code) | 1 |
| The first §4.4 fix, continued: a `turn_error` entry that ends a tool round renders as a short assistant closer, so the next user message does not follow a tool result directly (Hermes's `close_interrupted_tool_sequence`); steering's mid-turn `tool → user` is untouched | +43 (~10 of code) | 1 |
| The second §4.4 fix, continued: the four error exits of the turn loop share one helper that records the error, remembers a cancel, resets the token and then notifies, so hooks receive a cancelled turn's `turn_error` entry | +31/−29 | 0 (the lifecycle test gained two assertions) |
| The first §4.4 fix, part 2: when a `tool_result` hook fails because the turn was cancelled, the call's own result is kept instead of "not executed" | +53/−4 (~10 of code) | 1 |
| E3a's companion: the stream assembler opens a new call when a new id arrives at an index already in use | +37/−6 (~15 of code) | 1 |
| E5, one more bullet: the dropped-call re-prompt, stored in the session as a user message, with the stall count reset by any real tool round | +61/−2 (~19 of code) | 1 |
| A fix to the E8 overflow prototype: its `continue` on the last round fell out of the loop into `unreachable!()`. The loop's end is now the round-limit failure | +38/−6 | 1 |
| E8, one more bullet: a result over the 64 KiB cap is saved to `<session>.results/<call id>.txt` beside the session file, and the stored result becomes its size, path and a 4 KiB preview. Ephemeral sessions keep the elided form. Mostly hook tools exceed the cap; `sh` and E1 tools are bounded at 32 KiB per stream, and their two streams plus headers can pass it by about 100 bytes. `read_file` reads the session's own `.results/` through its allowlist (§6.7) | +92/−1 (~45 of code) | 1 |
| E8, one more bullet: the automatic-compaction estimate becomes the larger of bytes ÷ 4 and an anchored count: the last `usage` entry's prompt and completion tokens plus bytes ÷ 4 of the messages since. A compaction, or hook state that injects context, voids the anchor, as Hermes's fingerprint check fails closed; state-only updates, which the batteries make most turns, keep it (a follow-up commit) | +67/−1, then +31/−2 (~37 of code) | 2 |
| E3b Anthropic Messages: `provider.api = "anthropic"`; system, tools and strictly alternating turns (tool results merged into user turns); signed thinking stored and replayed; three native cache markers; the typed event stream with text, thinking, signature and partial tool-input deltas; 529 and stream errors mapped | +611/−11 (~410 of code) | 3 |

All 196 tests pass, `cargo fmt` and `cargo clippy --all-targets` are clean,
and the result cross-builds for Motor OS without warnings. The final build
re-ran the minimal option in the VM (§4.3) unchanged, in 2.2 s. By change:
* **Unpaired calls.** The regression test fails on unpatched Gears
  ("`left: ["call_1"]`, `right: ["call_1", "call_2"]`") and passes with
  the fix. Both §4.4 reproductions (kill, SIGINT) then produce valid
  requests.
* **E6.** The prototype `delegate` tool (§4.3), switched to
  `--output jsonl`, ran in the dev VM. The child made one tool call. The
  parent's tool result carried the child's final answer from the `result`
  record plus a one-line trace ("child used 1 tool calls; 2
  completions"). The whole turn took 0.095 s. On the host, SIGINT
  during a child's tool call made the last line
  `{"type":"result","ok":false,"error":"turn cancelled",...}`, with exit
  status 1 and no surviving tool process. The HTTP and Telegram
  prototypes of §4.3 run on this change.
* **E11 and E7.** The review fork of §6.4 ran on them with full cache
  parity, including a fork that E7 started while the interactive parent
  was still alive and held the session lock.
* **Rounds that retry.** The E8 overflow retry and the dropped-call
  re-prompt both `continue` the bounded round loop. Gears' loop ends in
  `unreachable!()` (`runtime.rs:329`), so a retry on the last round would
  panic. The regression test for this (`max_tool_rounds = 1` plus an
  overflow) panicked on the first overflow prototype. Any retry added to
  the loop must end at the round limit.
* **Closing an interrupted round.** The session test covers three cases:
  a round cancelled after its results; one cancelled with a call unpaired;
  and a turn that failed before any round, which gets no closer. It fails
  without the change. The host reproduction then sent `assistant, tool,
  assistant, user`. The steering test, which expects a mid-turn `tool →
  user`, still passes. A first attempt with a structural rule failed it.
* **Lifecycle hooks.** The regression test cancels a streaming turn, then
  calls `/new` and `close`, with a hook that logs every event. It fails
  without the fix. It now also requires the `turn_error` entry and a
  `"status":"cancelled"` `turn_end` in the log. The first prototype
  missed the entry, and that assertion fails without the follow-up
  commit. Combined with E12 it fails earlier: `new_session`
  itself returns `sh stdin: Broken pipe`, because E12's re-`initialize`
  is one of the hooks that die at spawn. So on top of E12 the defect
  would break `/new` after any Ctrl+C, and its fix must land first.
* **The wedge.** Both regression tests fail on unpatched Gears with the
  two errors §4.4 quotes. With the fix, the §4.4 reproduction compacts
  on its first turn and later turns succeed.
* **E2.** Three calls to a parallel-safe tool that sleeps one second
  finished in about one second together, and their results came back in
  call order.
* **E1.** In the dev VM, the `sh` tool directory, a rush script run
  through its shebang, replaced the built-in `sh`. Of two calls, the first
  made a directory, changed into it and exported a variable; the second
  printed `/user/tmp/exp/e1ws/sub` and `FOO=bar`. The turn took 91 ms. On
  the host, a tool with `timeout_seconds = 1` stopped a 5 s sleep.
* **E3b.** A smoke test runs the real binary, with curl, against a mock
  server streaming Anthropic events. In the dev VM the same binary
  completed a turn against a host mock in 32 ms, sending the
  `anthropic-version` header and an `x-api-key` that Motor OS's curl
  expanded from the key file.
* **E10.** In the dev VM, a scripted `sh` call ran through Gears'
  process runner. With `sandbox = true` it got `PermissionDenied` reading
  `/user/cfg/rush.toml` but could still write a new file in `/user/tmp`.
  With `sandbox = false` it read the file.
* **E3a.** It raised two design points:
  * A new content block makes sessions unreadable to an older Gears. The
    session format needs either a version bump or a rule to skip
    unknown blocks.
  * Stored reasoning must not count toward the context estimate, since
    it reaches the wire only as a short echo. Otherwise long reasoning
    would trigger early compaction.

  Other routes to the same models, such as OpenRouter, need a
  configuration override, because the quirk table is keyed by host.

The E6, E11 and E12 estimates in the table above hold. E0 needed more:
~160 became ~220, once the prototypes covered the kept result, the
closer and the `turn_error` entry. Six items needed less than first
estimated, and the table carries the revised figures:
* E2: ~300 became ~200;
* E3b: ~1,000 became ~600;
* E5: ~200 became ~120;
* E7: ~200 became ~80;
* E8: ~650 became ~400, now that its wedge fix sits in E0;
* E13: ~50 became ~30.

The changes pay off in different places:
* E4 at once, for Claude and Kimi models through OpenRouter;
* E3a with DeepSeek, Kimi and MiMo thinking models;
* E3b with Anthropic's own API;
* E2 with slow tools;
* E5 with flaky endpoints.

Every hook receives every event: six per interactive text-only turn
(nine for a one-shot `gears -p` run), plus `permission`, `tool_result`
and `entry` per call, and `context` plus an assistant `entry` per extra
round. So the batteries register **one** hook, `gears-batteries hook`, that
dispatches internally to memory, skills, context, hints, todo and policy.
That costs one spawn per event instead of one per feature. E13 is then an optimization, not a
requirement.

A hook has a single `timeout_seconds` (default 30, at most 3600,
`config.rs:259-264`). It applies to every event, from a `permission`
check to a `tool_execute`. A hook tool that can run for minutes, such as
`delegate`, MCP or code mode, would force a long timeout onto every
`permission` and `entry` call as well. So the fast in-process tools stay
hook tools, and the long-running ones become E1 external tools. The E1
proposal gives each of those its own `timeout_seconds`
(`src/bin/gears/external-tools.md:90`, not yet implemented). Until E1
lands, a second hook entry that only executes the long tools can stand in
for it. That entry also receives every event and must answer the others
with `{}`, which costs one more spawn per event. On the plan's path this
never arises, because E1 lands in phase 1, before any long-running tool;
it matters only if E1 slips.

### 6.4 The batteries

**Policy hook** (`permission`):
* Allows the batteries' read-only tools without asking. They read what the
  None role can read, through a None-role child, plus a short
  allowlist: Lorry's dependency tree and the session's own spilled
  results. So none of them reaches `/user/cfg` or the keys in
  `/system/cfg` (§6.7).
* In a run with no one to ask (cron, delegation, a non-streaming HTTP
  request), answers `deny` instead of `ask`. Gateway chats do ask,
  through the chat. Saved E1 grants apply in neither (§6.7).
* Denies the Motor OS hard floor of `sh` commands described below.
* Answers `ask` for everything else, which leaves the decision to the
  user.

Gears keeps shell parsing out of its core on purpose, and a hook is where
Gears says such policy belongs. Hermes's other ~107 patterns stay out of
phase 1, because every `sh` call that the floor does not deny still asks the
user. About 78 of them are POSIX: force-push, `find -delete`, pipe to a
shell, `sudo`, SQL `DROP`. They become useful once `sh` is auto-allowed,
as under a cron job's `allow`, so their POSIX subset belongs in phase 6.

The floor is decided as follows. It is a Motor OS rule list, matched on
tokens rather than raw text: Hermes's quote masking, then unwrapping of
`sh -c`, `eval`, `rush -c`, `sysbox <applet>` and absolute program paths,
with `cd` tracked (§6.7). Hermes's 12 hardline patterns and their test
cases serve as its test corpus, not its implementation. The §4.3
prototype was a straight regex port of those patterns; the token-based
floor that replaced it is in §6.7.

Most of Hermes's 12-pattern floor (`tools/approval_detection.py:88`) has
no Motor OS counterpart. `mkfs`, `dd` or redirection to block devices
(Motor OS has no `/dev`), `kill -1` (rush's `kill` takes only a pid or
`%job`), `shutdown`, `reboot`, `systemctl`, `init` and `telinit` do not
exist there. The Motor OS floor is recursive `rm` of
`/`, `/system`, `/user`, `/user/cfg` or `/devtools`, any `rm` under
`/user/cfg`, and the fork bomb.
It keeps Hermes's anchoring rules, so a command name must be in command
position and quoted prose does not match.

The patterns port nearly as they are. A probe loaded all 155 of Hermes's
patterns (12 hardline, 107 dangerous, 36 threat-scan) with Hermes's
flags:
* 146 compile unchanged in Rust's `regex` crate, all 12 hardline ones
  among them;
* 9 need lookaround and compile in the pure-Rust `fancy-regex`: SQL
  `DELETE` without `WHERE`, cloud metadata access, and a hardcoded-secret
  scan, among others;
* none fails in both.

The regexes are not the whole matcher, though. Hermes first runs a
quote-aware pass that turns real `;`, `&` and `|` separators into
newlines and masks quoted prose (`_mask_quoted_prose` and
`_mark_command_starts`, `tools/approval_detection.py:150, 1174`). It also
extracts `sh -c` and `eval` payloads. That pass must be ported with the
floor and tested with Hermes's own cases, which is most of the policy
hook's ~600 lines in phase 1. The rest of Hermes's matcher (detection
variants, deobfuscation, carrier payloads such as `xargs` and
`find -exec`; about 800 lines of Python at `:482-1540`) comes with the
POSIX patterns in phase 6, at about 400 more.

Hermes's third stage, Tirith (review §11.2.15), is not ported. No Motor OS build
exists, so Hermes itself would skip it there. Tirith catches what
regexes cannot: look-alike Unicode host names, and escape sequences that
make a command display differently from what runs. There are two ways to
cover that later:
* Port Tirith to Motor OS as an optional external binary that the policy
  hook calls. That is a sibling-repository port whose license and
  dependencies were not checked here, and one more process per command.
* Add the two cheapest checks natively to the policy hook, about 50
  lines: a non-ASCII host name in a URL, and control or escape
  characters in a command.

*Recommendation:* the native checks in phase 6, with the POSIX patterns.
They matter most once `sh` is auto-allowed, and until then every command
is shown to the user before it runs.

**File tools**, one binary with four tool directories:
* `read_file`: numbered lines, offset and limit, and binary sniffing. The
  page budget must fit the model-output bound. That is 32 KiB per stream
  for `sh` today (`src/runtime.rs:19`), so pages are ~30K characters
  unless E1's manifests allow a larger per-tool bound. Hermes uses 100K.
* `write_file`: atomic via `create_new` plus `rename`, since `tempfile` is
  unsupported on Motor OS. It preserves CRLF and BOM and refuses to overwrite
  a file the session has not fully read or that changed since. Read
  tracking lives in a small per-session state file keyed by
  `GEARS_SESSION_ID`, written by the Interactive tool process, whose
  reads go through a None-role child (§6.7). It records each file's hash
  at read time, so the
  "changed since" check still holds after `/tree` moves to another branch,
  even though the file itself does not follow branches.
* `patch`: 5 of Hermes's 9 strategies (`tools/fuzzy_match.py:176-289`),
  with unified-diff output:
  1. exact;
  2. line-trimmed;
  3. whitespace-collapsed;
  4. indentation-flexible;
  5. escaped `\n`/`\t` in the pattern.

  The two similarity strategies (`block_anchor`, `context_aware`) are left
  out. Hermes's history shows them replacing the wrong region silently
  (commit `c0b0c88626`, and the in-code note that looser thresholds
  "matched unrelated blocks"). A failed match that asks the model to
  re-read is safer. Unicode normalization waits until it is needed; its
  position mapping took several fixes (`65a6a36093`, `e90857ba07`).
  `trimmed_boundary` is dropped because it can never fire. It strips only
  the first and last lines, so line-trimmed has already matched anything
  it would, and a multiple match returns at once
  (`tools/fuzzy_match.py:72-78, 212-214, 364-374`).
* `search_files`: wraps `/system/bin/rg --json` with a fixed argument
  vector that ends in `--` before the path (§6.7: a path of `--pre=sh`
  ran commands in the first prototype). `rg` ships in the standard and
  dev images. Wrapping the binary avoids linking the ripgrep crates,
  which needed a small Motor OS port (`../ripgrep`).

Motor OS's base image has no `grep`, `head`, `tail` or `diff` (§4.2). These
tools are therefore the difference between a model that works and one that
flails. About 2,000 lines.

**Terminal state.** Gears' `sh` starts every call fresh in the workspace.
Hermes's evidence is that models expect `cd` and `export` to persist. The
`sh` tool directory can wrap each command as follows (about 150 lines,
with no Gears change beyond E1's step 6):

```sh
. "$STATE/env.sh"
PATH=/system/bin:/devtools/bin     # pinned after the carried exports
cd "$(cat "$STATE/cwd")"
<command>
rc=$?
pwd > "$STATE/cwd"
export -p > "$STATE/env.sh"
exit $rc
```

`$STATE` is a per-session directory under `/user/cfg` in normal use.
Under E10 the wrapper runs as None and cannot reach it, so the state
lives in the sandbox copy instead. There another None process could
alter it, but under E10 the kernel, not the floor, keeps `sh` away from
`/user/cfg` and the system trees.

The `export -p` round trip was verified on rush (§4.3), and the E1
prototype ran this wrapper as an `sh` tool directory in the VM (§6.3),
passing the command as one `{command}` argument. An export whose
value exceeds 4,092 bytes aborts that command in rush (`moto_rt::setenv`,
§4.2), but the state files stay intact because the save lines never run.
A manifest has one fixed `timeout_seconds`, so the wrapper enforces the
model's per-call `timeout` below it. Tool programs are named by absolute
path, such as `/devtools/bin/gears`, because the tool contract rejects
bare names (`external-tools.md`). Background jobs that outlive a call
need a long-lived owner, because on Motor OS an ordinary child dies with its
parent (§4.2). They stay out of v1, and the tool description should tell
the model so (Q17).

**Context files** (`initialize`): the `AGENTS.md` chain from the
repository root down to the workspace, or `.gears.md`. They are capped
at 20K characters, Hermes's floor; Hermes scales the cap with the window,
but a fixed cap suits 32K-token models. Truncation keeps Hermes's 70%
head and 20% tail, and a small threat-pattern scan applies.

**Subdirectory hints** (`tool_result`): the first time a tool touches a
directory with an `AGENTS.md`, it is appended to that result.

**Memory** (`initialize` plus tool):
* Two `§`-delimited files with 2,200/1,375-character budgets.
* An atomic batch tool that checks the budget on the final state, with
  whole-file locks via `File::lock`, and a threat scan of each write
  (Hermes's `tools/threat_patterns.py`, "strict" scope). The prototype
  ports all 36 patterns, with `fancy-regex` for the one that needs
  lookaround, plus the invisible-character check. It passed "User prefers
  tabs over spaces" and blocked, by Hermes's pattern ids:
  * `prompt_injection`: "ignore all previous instructions…";
  * `exfil_curl`: a `curl` that sends `$OPENAI_API_KEY`;
  * `hardcoded_secret`: an `sk-…` key;
  * `role_hijack`: "you are now a pirate assistant";
  * a zero-width space.

  Hermes also NFKC-normalizes text before matching, against full-width
  homographs; a port needs the `unicode-normalization` crate for that.
* **Compile cost.** Hermes compiles its patterns once per process. A
  hook that starts per event compiles them on every call:
  * the 36 threat patterns take ~115 ms on the host and ~175 ms per
    scan in the VM. Most of that comes from bounded repetitions such as
    `[^\n]{0,2048}`, which Rust's `regex` expands into large automata.
    Hermes bounds them only to protect Python's backtracking engine, and
    Rust's `regex` matches in linear time. Rewriting the ten large
    `{0,N}` bounds as `*` halves the cost (63 ms on the host);
  * the 12 floor patterns take ~22 ms on the host when none matches, and
    ~15 ms per check in the VM with the process spawn included, so each
    `sh` permission check pays about that. A command that matches stops
    compiling at its pattern, since the patterns compile lazily in order.

  Both costs are small next to a model turn, and memory writes are rare.
  If they ever matter, `regex-automata` can serialize the compiled DFAs
  at build time, except for the nine lookaround patterns.
* The snapshot is frozen on first initialization, referenced from the
  session's namespaced hook state (next bullet), and reused on resume, so
  the prompt stays byte-stable across processes. Hermes gets the same effect by persisting the whole
  prompt; Gears rebuilds from resources, so the hook supplies the
  stability. A prototype of exactly this was verified on current Gears
  (§4.3) for one session per process. Interactive session switches need
  E12.
* The hook's state stays small. Gears appends a hook's whole state to the
  session on every change, and pipes it to the hook with every event
  (`src/hooks.rs:425-434`; "State replaces that hook's latest namespaced
  state"). A 6 KB snapshot kept in state would be re-written with every
  todo update. So the frozen memory snapshot and skills index live in
  content-addressed files, `batteries/snapshots/<sha256>.md`, which are never
  modified. The state holds only their hashes, the todo list and the
  review counters. If a snapshot file is missing, the hook falls back to
  the current memory, and the prompt changes once. In the batteries prototype,
  a session's `hook_state` entry holding the three hashes (memory, skills
  index, context files) was 355 bytes. The review fork still repeated the
  parent's prompt byte for byte, since the copied state named the same
  files.

About 450 lines.

**Skills** (`initialize` plus two tools):
* Discovery of agentskills.io-format `SKILL.md` files, reading name,
  description, platforms, `prerequisites` and `metadata.hermes`. A skill
  whose `platforms` list lacks `motor` is hidden on Motor OS, so imported
  skills must be reviewed and tagged. The frontmatter is real YAML:
  * every one of Hermes's 208 skills uses flow lists;
  * 202 nest maps two levels deep;
  * 114 quote scalars.

  So a hand-written parser would have to cover a real YAML subset. The
  pure-Rust `yaml-rust` crate parsed all 208 in a probe and extracted
  the 26 `prerequisites.commands` lists. A maintained pure-Rust YAML crate
  is the simpler choice (`yaml-rust` 0.4 itself is unmaintained).
* The index as a prompt fragment.
* `skill_view`, whole files with linked-file listing, confined to the
  skill's own directory (§6.7).
* `skill_manage` (create, patch, write_file, remove_file, archive) with
  per-skill locks, a `created_by` provenance flag and the same threat scan
  on every write.

Hermes's skills are MIT data: 58 bundled in `skills/` and 150 optional
in `optional-skills/`, 2.2 MB of `SKILL.md`. A read of each skill's
frontmatter, body and bundled files sorted them for Motor OS:

| Class | Bundled | Optional | Total |
| --- | ---: | ---: | ---: |
| Works as-is (instructions, git, curl, file tools, subagents) | 16 | 10 | 26 |
| Works with edits (`grep`/`tail`, `pip`/`npm`, `gh`, bash templates) | 14 | 15 | 29 |
| Not applicable (MLOps, macOS, Office, browsers, Python-script skills, SaaS CLIs) | 28 | 125 | 153 |

60 skills ship scripts: 155 Python files, 17 shell, 25 JavaScript and 2
PowerShell. The best candidates are the software-development methodology
skills:
* `systematic-debugging`, `test-driven-development`, `simplify-code` and
  `spike` (bundled);
* `subagent-driven-development`, `grill-me` and `code-wiki` (optional).

`requesting-code-review` and `github` are worth rewriting for `rg`,
Lorry and curl. "As-is" still assumes the batteries' equivalents of Hermes's
`read_file`, `search_files`, `patch`, `delegate_task` and web tools.

Gating needs a Motor OS rule. Every Hermes skill declares `platforms`, and
204 of the 208 include `linux` (`agent/skill_utils.py:20, 126-143`). A
literal match would therefore hide all of them on Motor OS, and treating
Motor OS as Linux would show the 153 that cannot work. The batteries show a
skill on Motor OS only when its `platforms` names `motor`, and the import
review adds that tag. Since the model writes skill frontmatter,
`skill_manage` may not change `platforms`, and an agent-written skill is
approved by the user by content hash, so a later agent edit withdraws
the approval (§6.7). Hermes records `prerequisites.commands` (26
skills) but never checks it (`tools/skills_tool.py:460-462`). The batteries
can check it against the image cheaply, hiding a skill that needs `gh`
or `python3`. About 1,400 lines.

**Todo** (hook tool): a list in namespaced hook state, so it follows
conversation branches. About 250 lines.

**Session search** (tool): scans Gears JSONL session files for
case-folded tokens and phrases and returns snippets, whole sessions, or a
window around a hit. A linear scan is enough at personal-agent scale;
SQLite FTS5 is the fallback if it is not (Q2). About 500 lines.

**Delegation** (tool): runs `gears --ephemeral --output jsonl -p "<goal>"`
with a child configuration. That configuration:
* excludes delegation, memory and `skill_manage`;
* has a bounded round count;
* passes the goal and context as the prompt.

The tool returns the final text and a short trace summary. Process
isolation gives interrupt propagation for free, since Gears kills the
process tree on cancel. A prototype confirmed this on Motor OS (§4.3). It is
an E1 external tool with its own timeout, not a hook tool (§6.3). The
child configuration does not enable `delegate`, which keeps the depth at 1.
About 300 lines.

**Web** (tools). Hermes never parses web pages itself. Its
`web_extract` sends the URL to a vendor extract API (Firecrawl, Tavily,
Keenable, Exa or Parallel), with a keyless free-tier fallback. It first
refuses URLs that carry secrets and applies an SSRF filter and a per-site
policy (`tools/web_tools_extract.py:1-7`). `web_search` likewise calls a
configured search API. The batteries follow that design:
* `web_search` against one configurable JSON API: a self-hosted search service, or
  a keyed vendor.
* `web_extract` through one configurable extract API. The VM then talks
  only to that vendor's host, which fits Gears' exact-host egress
  allowlist. It needs no HTML parser. The SSRF and DNS-rebinding
  questions do not arise inside the VM, because the vendor does the
  fetching. The batteries still refuse URLs that name private or link-local
  hosts, so the model cannot ask a vendor to probe addresses it should
  not know.

A local fetch mode (curl plus HTML-to-text) would be the alternative for
users without a vendor. It brings back what the vendor design avoids:
* an egress policy in the batteries for "any public host", since Gears'
  allowlist is exact-host configuration;
* a DNS-rebinding gap, since Motor OS's curl has no `--resolve` to pin the
  address the SSRF check approved (§8.2);
* an HTML-to-text converter.

It belongs after v1, if at all. About 600 lines for the vendor design.

**MCP** (tools). On Motor OS, remote servers are the realistic kind:
* A stdio server must be a native Motor OS binary. Most published ones are
  `npx` or `uvx` packages, and Motor OS has neither Node nor Python.
* Hermes's own curated catalog (`optional-mcps/`) is entirely remote: all
  65 entries use HTTP transport, 55 of them with OAuth and 10 with no
  authentication.

The design is therefore:
* Streamable HTTP first. The adapter lists tools at `initialize` and
  keeps the server's session id in a small state file, so each call is
  one POST through curl.
* stdio second, for native binaries, spawned per call.
* Tools register as `mcp__<server>__<tool>`, sanitized to the
  `[A-Za-z0-9_-]` names Gears accepts (`src/hooks.rs:440-448`).
* OAuth is most of the remaining work. Hermes spends ~2.5K lines on PKCE,
  dynamic client registration and device flow. A VM has no browser, so v1
  supports servers without authentication and bearer tokens obtained on
  the host; the OAuth device flow comes next.

A server that must keep live state beyond its session id needs a
client owned by Gears, deferred (Q8). About 1,200 lines, plus OAuth.

MCP tools should not go into `tools` one by one, for two reasons. A
single server often brings dozens of schemas, which is exactly the load
that Hermes's Tool Search (review §11.2.5) moves out of the prompt. And `tools` sits
at the front of the cached prefix, so a server that adds or renames a
tool would invalidate every session's cache. The batteries therefore expose
MCP tools through three fixed bridge tools, as Hermes does:
* `tool_search`, a keyword search over names and descriptions;
* `tool_describe`, which returns one schema;
* `tool_call`, which takes a name and arguments.

The policy hook must then judge `tool_call` by the inner tool name, not
the bridge's. A server with only a few tools can be listed directly
through a per-server option. The bridge adds about 250 lines.

**Code mode** (tool): Monty, verified on Motor OS (§4.3), running a script
whose host functions are the batteries' read-only tools (read, search, web).
Monty runs in a None-role child, and its host functions call back over a
pipe to the Interactive tool process (§6.7). Writes and `sh` stay outside
code mode in v1, so a script can do nothing a read-only tool could not,
and the policy hook allows it without asking. The
binary grows by ~7 MB, so this should be a separate binary or a Cargo
feature. About 600 lines.

**Learning loop.** The reviewer is itself a Gears run, forked from the
parent's session after a delivered turn. E7 runs `gears-batteries review
<session>`, which starts:

```text
GEARS_BATTERIES_REVIEW=1 gears --config <the parent's config> --read-fork <session> -p "<review prompt>"
```

Two facts about today's Gears shape this:
* **The session lock.** `--fork` opens its source with `Store::open`,
  which takes the session's single-writer lock (`src/session.rs:299-300,
  707-734`). While the interactive parent is alive, the fork fails with
  "session is already open by process N". The source only needs to be
  read: the file is append-only, and a partial final record is already
  tolerated. E11 therefore adds `--read-fork`, a lock-free read of the
  source that copies its active branch into an ephemeral session.
  Session-start flags are mutually exclusive (`src/cli.rs:167-173`), so
  it is a new flag rather than a combination of existing ones. The §4.3
  prototype forked only after the parent had exited, so it never hit
  the lock.
* **Cache parity needs the same configuration.** `tools` and the system
  fragments come from the configured hooks (`src/runtime.rs:605-616`,
  `src/prompt.rs:19-28`), and `tools` is at the front of the cached
  prefix. The reviewer therefore runs with the parent's exact
  configuration. The restriction is enforced at call time: the policy
  hook sees `GEARS_BATTERIES_REVIEW` and allows only the skill tools,
  `read_file` and `search_files`, plus `memory` when the memory counter
  fired. It denies everything else. Hermes does the same, advertising
  identical tools and applying a dispatch-side whitelist
  (`agent/background_review.py:1078-1119`).

With both in place, the fork sends the parent's fragments, including the
frozen memory snapshot copied with the branch, and the parent's messages.
The §4.3 prototype showed exactly that for a fork started after the parent
had exited. The trigger uses Hermes's two counters (every tenth turn or
tool round). Only the parent's hook writes them, since the parent is the
session's single writer:
1. At `turn_end` the batteries' hook updates the counters in its hook state.
2. When one reaches ten, the hook resets it and records a `review_due`
   sequence number in the same state.
3. `gears-batteries review`, started by E7, reads the parent's latest hook
   state from the session file without the lock.
4. It exits unless `review_due` is newer than the last number it handled,
   which it keeps in a small file under `batteries/`.

Because the reviewer carries the parent's configuration, including the E7 job,
`gears-batteries review` exits at once when `GEARS_BATTERIES_REVIEW` is already
set. Hermes's fork disables its nudges for the same reason. Hooks inherit
Gears' environment minus the provider key, so the marker reaches the
policy hook.

This design was run end to end on the host with the E11 and E6
prototypes (§6.3) and the batteries prototype (§4.3), whose policy gained the
review rule in five lines. The prototype names its marker `PACK_REVIEW`
and fires on every turn, without the counters. The parent ran two turns; in the first it saved
"fact A" to memory. The review fork ran `--read-fork <parent> --output
jsonl` with the marker set. Its first request compared with the parent's
last one as follows:
* the system messages, all seven tools, and every other request field
  were byte-identical;
* the parent's whole message list was an exact byte prefix, followed by
  the parent's final answer and the review prompt;
* "fact A" stayed out of the fork's prompt, because the frozen snapshot
  came with the copied hook state.

In the fork, the model's `run` call was denied and its `memory` call was
allowed, and the saved entry reached `MEMORY.md`.

The same run was then repeated interactively, with the E7 prototype
configured to start the review after each turn:

```text
after_turn = ["env", "PACK_REVIEW=1", "gears", "--config", "...", "--read-fork", "{session}", "--output", "jsonl", "-p", "Review ..."]
```

The review fork started while the line UI waited at its prompt and held
the session's lock. It read the live session without the lock and ran
its three requests. It saved its memory entry, and its first request
again repeated the parent's tools and messages byte for byte. On Motor OS,
which has no `env` command, `gears-batteries review` sets the marker itself.
A 15-line `review` subcommand in the batteries prototype did exactly that. The
same interactive run in the dev VM, with
`after_turn = ["/user/tmp/exp/pack-proto", "review", "{session}"]`,
gave the same results: parity of tools and message prefix, a denied
`run`, and a saved memory entry.

The review prompts are ported verbatim. A deterministic curator (stale
after 14 days, archive after 30, pinned exempt) runs as
`gears-batteries curator`: by hand until phase 6, then scheduled by the cron
daemon itself as built-in maintenance, not as a model turn. About 600 lines plus prompts.

### 6.5 Daemons

**Cron** (`gears-batteries cron`):
* Jobs live in `jobs.json` (id, schedule, prompt, optional skills, model,
  delivery, `allow`, `sandbox`). Only the user writes it. v1 gives the
  model no tool to create jobs, since an injected instruction could
  otherwise schedule one with `"allow": ["sh"], "sandbox": false`.
* Schedules are durations, 5-field cron expressions (a ~300-line parser)
  and one-shot times. The last two use one configured IANA zone, as in
  Hermes, backed by jiff's bundled tz database because Motor OS has none
  (Q11).
* A 60 s tick advances `next_run` before dispatch, giving at-most-once
  semantics, as Hermes does.
* Each job runs `gears --config <job config> --ephemeral --output jsonl
  -p "<prompt>"` with a watchdog and stdin closed, so any call that would
  ask is denied. The job's own config, under `/user/cfg`, gives the
  batteries' hook `--job <id>`, so the hook reads the job's `allow` from
  `jobs.json` (§6.7). The
  `result` record is written to `cron/output/` and optionally handed to
  the gateway. Like Hermes, cron jobs skip the review.
* This default is stricter than Hermes's on purpose. Hermes's cron
  default, `cron_mode: deny` (`hermes_cli/config_defaults.py:1658`),
  blocks only commands that its dangerous patterns or Tirith flag, and
  it allows every other command (`tools/approval.py:637-670`,
  `:1193-1201`). With `cron_mode: approve`, a job can run anything that
  passes the hardline floor. The batteries deny `sh` outright instead. A job
  that needs the shell names it in `jobs.json`, for example
  `"allow": ["sh"]`. The policy hook then allows `sh` for that job while
  still applying the floor and the POSIX dangerous-command patterns. That
  is roughly Hermes's default. By default the job's `sh` runs under E10,
  in a prepared copy of its workspace; `"sandbox": false` opts out.
  Sandboxed jobs cannot run Lorry builds yet (§6.7).

Motor OS has no cron service. The daemon detaches
itself when `rush.toml` grants it `spawn-detached` (Q12). About 1,000
lines.

**Gateway** (`gears-batteries gateway`):
* One adapter trait with Hermes's four methods: `connect`, `disconnect`,
  `send`, `get_chat_info`, plus an inbound callback.
* The first adapter is the Telegram Bot API by HTTPS long polling
  (`getUpdates` with a 30 s timeout, `sendMessage`, `editMessageText`),
  which needs only curl. A prototype ran in the VM against a mock Bot
  API (§4.3). The token travels in the URL path; §4.3 explains why that
  is acceptable inside the VM. Adding `--expand-url` to Motor OS's curl
  would remove the question, and it is a small change to `src/bin/curl`,
  not to this project.
* Each chat maps to one Gears session, created on the chat's first
  message. Later turns run as
  `gears --session <id> --output jsonl -p "<message>"`, and text deltas
  become rate-limited message edits.
* Turns for one chat are serialized: a session has a single writer, so a
  second concurrent turn would fail on the lock. Hermes's busy-input
  policy decides what happens to a message that arrives mid-turn, and
  each of its three answers has a mechanism here:
  * queue: the per-chat worker, prototyped;
  * steer: E6's stdin channel, prototyped;
  * interrupt: killing the turn's process tree.

  Hermes defaults to interrupt (`hermes_cli/config_defaults.py:808`).
  It demotes that to queue while subagents or a compaction are running
  (`gateway/run_busy.py:568-616`). The gateway can make the same choice.
* Only allowlisted user ids are served, and v1 serves the user only
  (§6.7). Later, as in Hermes, an unknown user can pair through a
  one-time code that the user approves from the command line (Hermes's
  `hermes pairing approve`, `gateway/pairing.py:476`), with a guest
  configuration. A call that would ask becomes a chat question through
  E6's stdin channel (Q9), in a private chat, with a single-use nonce per
  request (§6.7). The gateway denies it after a timeout, or when the chat
  moves on.
* One process per turn replaces Hermes's in-memory agent cache. The
  prompt stays cacheable because memory is frozen in session state.
* After a delivered turn the gateway itself runs `gears-batteries review`, since
  there is no interactive prompt for E7 to wait at. The read fork does
  not block the chat's next turn, and a new message from that chat kills
  the review's process tree, as E7 does.

About 1,800 lines. Discord and Slack need websocket clients, which have
no precedent on Motor OS; they are out of scope.

A third front end deserves a note: ACP, the editor protocol Hermes speaks
through `acp_adapter/` (3.5K lines). It runs over stdio, so an editor on
the host could reach an agent in the VM through the existing ssh exec path
(`ssh motor gears-batteries acp`; russhd gives exec sessions plain pipes). The
editor stays on the host while the workspace, tools and credentials stay
in the VM. It is not in the phased plan, but it fits the same "process per
turn" design.

An alternative first adapter is Hermes's OpenAI-compatible HTTP front
end (`gateway/platforms/api_server.py`). It serves `/v1/chat/completions`,
`/v1/responses`, and a runs API with `/approval`, `/steer` and `/stop`
endpoints (`api_server.py:81-98`). It needs no third-party account, it
can be tested hermetically, and any OpenAI client on the host could drive
the VM's agent. Motor OS has server-side precedent in `httpd` and
`httpd-axum`. The loopback-accept slowdown
(`docs/plans/future-work.md`) affects only a process that connects to its
own listener, so it does not affect this design. *Suggested order:* the
API front end first, for testability, then Telegram as the first chat
platform. A prototype of it ran in the VM (§4.3).

Chat Completions carries the whole history in every request, and Gears
builds context from its own session file, so the front end must pick
whose history wins. Hermes supports both:
* by default the body is authoritative, and a session id is derived from
  the system prompt and first user message
  (`api_server.py:1059-1064`);
* an `X-Hermes-Session-Id` header, allowed only with an API key, loads
  history from its database instead
  (`api_server_openai_routes.py:657-690`).

For Gears the options are:
* **Header continuation only**, as prototyped. The gateway sends just the
  last user message to `gears --session <id>`, for ids from its own
  session map only (§6.7), and rejects prior history without a session
  id. It needs no Gears change, and the client must
  keep the id.
* **Body-authoritative requests.** Each request starts an ephemeral
  session seeded from the body's messages. That needs a Gears flag to
  seed a session from a message file, about 80 lines, or the gateway
  writing Gears' JSONL format itself, which couples it to a storage
  format. It suits Open WebUI-style clients that edit and regenerate.
* **Fingerprint mapping with branching.** Map the first user message to a
  session and, when the body's history diverges from it, branch from the
  last matching user entry, as Gears' `/tree` does in-process
  (`Store::fork_at_user`). It needs a CLI form of that fork.

*Recommendation:* header continuation for v1, which gives the Hermes
header mode's security property: history is readable only with the
key. Add body-authoritative seeding when a client that needs it
appears.

### 6.6 Testing

* Every tool and hook gets host unit tests that call the binary with JSON
  on stdin and check stdout.
* Turn-level tests extend `gears-mock-provider` scenarios (scripted SSE),
  following the existing `test-gears-http.sh` pattern:
  * a file edit round;
  * a memory write that does not alter the prompt within the session;
  * a skill view;
  * a delegated child;
  * a review fork that hits the same prompt prefix, checked by recording
    request bodies, as Hermes's `tests/fakes/fake_llm_provider.py` does;
  * cron dispatch;
  * a gateway turn against a mock Telegram endpoint.
* All new mocks are Rust, as `gears-mock-provider` is: the Anthropic-format
  provider (phase 3), the MCP server (phase 5), and the HTTP client and
  Bot API fixtures (phase 6). The Python mocks behind this document's
  prototypes were scratch tools and do not enter the repository.
* Scenarios adapted from Hermes's regression tests (review §11.2.18; Appendix D
  lists 27 with their Hermes sources), scripted in the mock:
  * cancel or kill during a multi-call tool round, then resume: every call
    has a result;
  * a stream that ends after a `tool_use` start with no arguments: no
    tool runs and nothing is persisted as a turn;
  * an empty stream: retried once, never persisted as an assistant turn;
  * a compaction whose summary call fails: context unchanged;
  * one tool result larger than the window, with a mock that returns 400
    above a size limit as providers do: the session still compacts and
    later turns succeed (the §4.4 wedge);
  * Ctrl+C during a tool, then `/new` and `/quit`: hooks receive the
    cancelled `turn_end`, both `session_end`s and the new
    `session_start` (the second §4.4 defect);
  * a compaction that cannot shrink enough: it stops rather than
    repeating;
  * a compaction boundary landing inside a parallel tool group: the group
    stays whole;
  * a review fork: its first request's system prompt, tools and message
    prefix are byte-identical to the parent's (the §6.4 run, as a test);
  * approvals over E6: a `permission_request` answered `once`, `session`
    and `deny` on stdin, and a closed stdin denying.
* The batteries follow Gears' existing split:
  * a host leg, `src/tests/test-gears-batteries.sh`, called from `full-test.sh`
    as `test-gears-http.sh` is (`full-test.sh:292`);
  * a dev-image VM leg, `test-gears-batteries-vm.sh`, called like
    `test-gears-http-vm.sh` only when `FULL_TEST_VERIFY_DEV_SOURCES=1`
    (`full-test.sh:735-737`), that is from `full-test-dev.sh`, in release
    mode per `AGENTS.md`.
* No test contacts a real provider or the Internet.
* Hook fixtures written by a test run as `sh <script>` and are never
  exec'd directly. In a multithreaded test binary, another thread's fork
  can still hold a freshly written script open for writing, and the exec
  then fails with `ETXTBSY`. The E12 prototype's test failed that way in
  about 1% of runs until it switched to `sh` (0 failures in 1,000 runs
  after). Gears' two existing script-hook tests share the pattern but did
  not fail in 1,000 runs. E0's first test patch should move them to
  `sh <script>` too: two one-line, test-only edits.

### 6.7 Security on Motor OS

The model can read any file the agent can. That is the norm for Hermes's
local backend and for Gears (`README.md`: "`sh` ... is not a sandbox").
Motor OS's roles offer an improvement, but a narrower one than it first
appears (E10):
* Run `sh`, the model's arbitrary commands, with `MOTOR_OS_CAPS`
  selecting the None role. None cannot traverse `/user/cfg`
  (`docs/fs-permissions.md`), so provider keys, sessions, memory and
  skills are out of reach of model-written commands.
* The batteries' tools that need that state stay in the Interactive role:
  session search, delegation, web keys, memory and skills. They are trusted
  code and the intended route to it.
* The cost: None can write only the shared scratch trees (`/user/tmp`,
  `/devtools/tmp`, `/system/tmp`). Runtime-created files and directories
  are also `r--`/`r-x` for lower roles ("Runtime behavior" in
  `docs/fs-permissions.md`). So a None-role `sh` cannot modify anything
  the user or an Interactive tool created, even in `/user/tmp`. A
  sandboxed workspace must be created and edited entirely by None-role
  processes. Under E10 the batteries' file tools therefore do their file I/O
  in a None-role child, while the Interactive tool process keeps read
  tracking under `/user/cfg`, as `search_files` does.

That makes E10 opt-in for interactive use. It is the default where `sh`
runs without a per-command decision, as under a cron job's `allow`, with
an explicit `"sandbox": false` opt-out per job.

The None role bounds the filesystem, not every channel. A pre-existing
Motor OS issue found here undercuts E10 while it stands: rmux's server
accepts any loopback client and publishes its port where None can read
it (`src/bin/rmux/src/server.rs:1434-1487`, `src/sys/motor.rs:110-114`),
so a None-role process can drive an Interactive rmux session's shell.
Diagnosed in the VM: a None-role client started a session that ran a
command as Interactive. So E10 gives a real boundary only where no rmux
server is reachable, and the daemons must not be hosted in an rmux pane
(Q12). §8.2 lists the rmux fix; it is outside this plan.

An existing workspace can be opened to E10 without any kernel change. An
Interactive process may widen a lower role's permissions
(`src/sys/lib/async-fs/src/filesystem.rs:196`), so a
`gears-batteries sandbox prepare` step can raise None's permissions to match
Interactive's on each entry, leaving the System bits unchanged. It should
do that on a *copy*, never on the user's workspace. Anything a sandboxed
job writes, such as `build.rs`, sources or `AGENTS.md`, is untrusted, and
the user's next Interactive build or session would otherwise run or
read it with Interactive authority. That is the same poisoning risk that
rules out a shared build cache below. The user reviews the copy's
changes, for example as a diff, before taking them.
In the VM, `sysbox chmod rwxrw-rw-` on an Interactive-created file let a
None-role `rush` overwrite it, and widened directories let it create
files. A mode that also changed the System bits was refused.

Builds are the gap. In the VM, `lorry test` run by a None-role process
in its own copy of a crate failed with
`failed to create build-cache root /devtools/lorry/cache/…: NotAllowed`.
Lorry's global cache defaults to that path on Motor OS
(`src/bin/lorry/src/config.rs:357-359`). `cache.directory` can move it
only from `/devtools/cfg/lorry.toml` or `/user/cfg/lorry.toml`
(`:420-425`), and both apply to every build. None cannot read the second,
which is skipped silently (`:437`). Pointing either at a None-writable
directory, or widening the shared cache for None, would let a sandboxed
job plant compiled units that later Interactive builds reuse, so neither
is an option. Until Lorry can give a None-role build a private cache
(§8.2), a cron job that must build either runs its `sh` outside E10, by
an explicit `"sandbox": false` in `jobs.json` that accepts the risks
below, or does not build.

These rules were checked in the dev VM by running `rush` with
`MOTOR_OS_CAPS=0x4` (spawn only: the None role) from the Interactive ssh
shell:
* reading or listing `/user/cfg` failed with `NotAllowed`;
* a file Interactive had created in `/user/tmp` was readable;
* writing into that file's directory, or overwriting the file, failed
  with `NotAllowed`;
* a directory None created in `/user/tmp` could be written and
  rewritten, and Interactive could still edit its files afterwards;
* `gears` itself failed at start (`/user/cfg/gears: NotAllowed`), so
  sandboxed commands cannot reach the provider key or start nested
  agents.

The E10 prototype then applied the same mask inside Gears' own process
runner (§6.3). The model's `sh` got `PermissionDenied` on `/user/cfg`
and could still write in `/user/tmp`.

A coarser boundary already exists: the VM itself. Hermes skips approval
prompts entirely on container backends, because the container is the
boundary (review §11.2.15). A Motor OS VM booted with `-snapshot` is the same kind of
boundary. An agent there can run with permissive approval, and every
change disappears at shutdown. Only what the user copies out, or what
the agent sends over the network, leaves the VM. This is a deployment
choice with no Gears work, and it pairs naturally with the egress
allowlist.

A workspace role between None and Interactive would lift that restriction
more cleanly, but it would be a kernel and FS change, outside this plan.
The preparation step above covers the need (Q13).

The provider key already reaches only the curl seam: Gears removes it
from every child's environment, and the batteries keep that rule. A
consequence is that every nested `gears` run (delegation, the reviewer,
cron, the gateway) must find the key in a file, because an environment
key never reaches the tool process that starts the child. Gears' default
key file (`/user/cfg/gears/openrouter.key`, `src/provider/key.rs:41-56`)
serves; an explicit `provider.key_file` is required only for plain HTTP.
Under E10 neither file is readable by the sandboxed `sh`, which is the
point.

The daemons add network surfaces, and the prototypes (§4.3) show what
each one needs:
* **The HTTP front end** should listen on the VM's TAP address rather
  than on all interfaces (the prototype used `0.0.0.0`). It requires a
  bearer key read from a file under `/user/cfg`. Session ids carry timestamps and are guessable, so
  the key, not the id, protects history, as in Hermes's header mode.
* **Telegram** serves only allowlisted user ids. An approval answer is
  accepted only from the chat that was asked, and only while its question
  is pending, as in the prototype. The bot token is a file under
  `/user/cfg`, and the adapter must keep request URLs out of its logs.
* **Unattended turns** (cron, a non-streaming HTTP request, a delegated
  child) close stdin, so any call that would ask is denied. Nothing is
  auto-approved without an explicit allow in the policy hook, provided
  E1's saved grants stay out of `-p` runs (see the hardening below).

#### Hardening from a red-team review

An adversarial review of this design (2026-09-26) found paths the
sections above did not close. The high-severity items were checked
against the code; one was reproduced. The plan adopts these rules,
about 700 lines in all (§6.9):
* **Exfiltration through tools that need no approval** (high). An
  injected instruction can have `read_file` read a key, under
  `/user/cfg` or in `/system/cfg` (`sshd.toml` holds the host's private
  key and is Interactive-readable, `docs/fs-permissions.md:118-121`),
  then have `web_extract` send it to a vendor inside a URL. Both tools
  are allowed without asking, even in cron and gateway turns. Hermes
  blocks reads of its credential stores (`agent/file_safety.py:352`);
  the batteries go further:
  * `read_file` and `search_files` read in a None-role child. The
    Interactive tool process spawns it with `MOTOR_OS_CAPS`, as E10 does
    for `sh`, and gets the results over a pipe. The kernel, not a list of
    secret paths, then decides: the child cannot read `/user/cfg`,
    `sshd.toml`, `ssl-key.pem`, or anything else the None role cannot.
  * Two canonical-path allowlist entries are read by the Interactive
    process itself: `/devtools/lorry`, Lorry's repository and cache,
    which None cannot read (`docs/fs-permissions.md:76`), so dependency
    sources stay readable; and the current session's own spilled results
    (E8). Motor OS has no symbolic links (§4.2) or hard links (§4.3), so a
    canonical prefix check is reliable there.
  * `skill_view` reads only inside a skill's own directory, after
    canonicalization, as Hermes checks for traversal
    (`tools/skills_tool.py:81-88`). `session_search` reads the user's
    own history by design; what it returns is the one remaining
    Interactive-only source, and the web tools' secret check below is
    its only guard.
  * Code mode's interpreter runs in a None-role child too; its reads and
    searches go through the same two tools.
  * Read tracking stays in the Interactive process's session state under
    `/user/cfg`, where no None process can create or forge it. Memory and
    skills stay reachable through their own tools. The batteries do all
    of this themselves, with no Gears change and without waiting for E10.
  * A prototype reader that re-ran its own binary as a None-role child
    worked in the VM: `/user/cfg/rush.toml` failed with the kernel's
    `NotAllowed`, while workspace and system files read normally. The
    extra spawn cost ~3 ms per call (6.3 ms against 3.0 ms). Phase 1, and
    phase 5 for code mode.
  * The web tools refuse a URL or query that contains any secret value
    the batteries have loaded, and any line of the key files named above.
    Phase 5.
* **Flag injection into `rg`** (high, reproduced). The prototype passed
  the model's `path` to `rg` without a preceding `--`. A path of
  `--pre=sh` then ran every file through `sh` (the Motor OS fork keeps
  `--pre`, `../ripgrep/crates/core/flags/defs.rs:5826`), inside a tool
  that runs unattended. The fix: a fixed argument vector with
  `--no-config`, `-e <pattern>` and `--` before the path, plus a test.
  It was re-tested against the fork. E1 manifests need the same rule: a
  `{field}` template must follow `--`, or the executor must reject a
  value that starts with `-`. Phase 1.
* **Saved grants in unattended runs** (high). E1 consults session and
  global grants *before* "an unattended run denies"
  (`src/bin/gears/external-tools.md:205-210`). A global grant for `sh`
  would therefore cover cron, delegated children, non-streaming HTTP
  turns and gateway chats, contradicting "nothing is auto-approved"
  above. Fixes:
  * the policy hook answers `deny`, not `ask`, in any run with no one
    to ask. A hook's deny wins over grants. Phase 1;
  * the gateway relays only once or deny, and resumes only sessions
    from its own map. Phase 6;
  * step 4 of `src/bin/gears/plans/gears-external-tools.md` (scoped approval
    grants), whenever it lands, applies saved grants only in the
    interactive UIs (line and TUI), never in `-p` runs, which covers
    cron, delegation and the gateway. The port needs this rule; it is a
    change to that plan for its owner.
* **Loosening `/user/cfg` from an approved command** (high). A higher
  role may widen a lower role's permissions
  (`src/sys/lib/async-fs/src/filesystem.rs:196`). One approved
  Interactive `chmod` can therefore open `/user/cfg` to None-role
  processes, and silently undo E10 and the rule above. An approved `sh`
  can also edit `gears.toml`, grant files, `jobs.json` and the batteries'
  state directly, skipping the threat scans. Fixes:
  * the batteries' daemons refuse to start, and their hook denies
    sandboxed `sh` at `initialize`, unless `/user/cfg` is `---` for the
    None role. A prototype probe ran a None-role child that lists
    `/user/cfg`. In the VM it passed by default, refused to start after
    an Interactive `sysbox chmod rwxrwxr-x /user/cfg` (the attack), and
    passed again once the mode was restored. On Motor OS, `read_dir` on a
    directory the caller may not read succeeds, and only reading the
    entries fails, so a check must read them;
  * `write_file` and `patch` refuse `/user/cfg/**`. Phase 1;
  * snapshots are checked against their content hash on load. Phase 2;
  * where `sh` runs with no per-command human decision (a cron job's
    `allow`), it runs under E10 by default, in a prepared copy of the
    workspace (above). The daemons' check is phase 6, E10's phase 5.
* **Motor OS-specific ways around the floor** (medium).
  * `sysbox rm -r /user/cfg` has no `rm` in command position.
  * `rush -c '…'` is not among Hermes's unwrapped shells.
  * `cd /user/cfg` in one call, then `rm -r .` in the next.
  * A persisted `PATH` can hijack later approved commands.

  The floor maps `sysbox <applet>` and absolute paths to the command name,
  unwraps `rush -c`, resolves `rm` targets against the carried cwd, and
  pins `PATH` in the `sh` wrapper after the carried exports. Outside E10
  the wrapper keeps its state under `/user/cfg`, where a None process
  cannot pre-create it (§6.4, "Terminal state"). A token-based prototype of
  this floor, about 100 lines plus tests, denied all 13 bypass cases tried through
  the policy hook's permission path, among them `cd /user/cfg; rm -r .`
  and `rush -c "rm -r /user"`. It still allowed ordinary commands such as
  `rm -r target` and `echo "rm -rf /"`. Phase 1.
* **Injection that persists through the review** (medium). Web, MCP,
  delegate and non-owner chat results mark the session as tainted in
  hook state. A review of a tainted session writes to a pending area the
  user accepts, and each entry records its source session. The
  untrusted-content wrapping lands in phase 4, with the reviewer. A prototype in the batteries' hook, about 25 lines, set the flag
  from a `delegate` result's `tool_result` event. A review of that
  session then wrote its memory entry to a pending file tagged with the
  source session, while a review of a clean session wrote memory as
  before. This also ran end to end through the Gears prototype on the
  host. The `delegate` result's hook reply stored `tainted: true` in the
  session (any event may update state, `src/hooks.rs:425-431`). A
  `--read-fork` review of that session sent its memory write to the
  pending file, and a review of a session without delegation wrote to
  `MEMORY.md`. The entry named the fork's session id; the real hook
  should record the parent's, from the fork's header. Phase 4.
* **Skill approval lives in model-written text** (medium). `skill_manage`
  may not edit `platforms`. Hermes treats a missing value as every
  platform (`agent/skill_utils.py:126-129`). Approval becomes an
  user-written list of skill content hashes, so any later agent edit
  withdraws it. Delegated children get no `skill_manage`. Phase 2.
* **Chat approvals that approve the wrong call** (medium). A late
  `/approve` could approve the next call, and any member of a group chat
  could answer. Each request gets a random single-use nonce, as an
  inline-keyboard button, bound to the chat, the asking user and the
  command's hash; HTTP approvals use the same. Approvals are private-chat
  only. The command is shown as a plain `pre` block, and commands too
  long for one message, or containing control or non-ASCII characters,
  are refused over chat. The Telegram prototype gained text nonces
  (`/approve 716de721`) in about 30 lines and was re-run in the VM:
  * a wrong nonce and a bare `/approve` were ignored;
  * the right nonce ran the command;
  * replaying it found nothing pending.

  Phase 6.
* **Pairing hands over the user's agent** (medium). A paired user would
  get the user's `USER.md`, `session_search` over every session, and
  review writes into global memory. v1 serves the user only. Guests
  come after v1 with their own configuration: no memory, no review, no
  session search, and `sh` under E10. Hermes's pairing limits
  (`gateway/pairing.py`) are ported then, as constants with tests.
* **Forged steering markers** (medium). The marker is a fixed public
  string that the system prompt says to trust. The `tool_result` hook
  neutralizes it in tool output, along with Gears' summary prefix and
  Hermes's other control-frame openers, and memory and skill writes
  reject them. In a prototype of the batteries' hook a page carrying the exact
  marker came back as `(quoted) (OUT-OF-BAND USER MESSAGE …`. Matching
  ignores ASCII case, so lowercase forgeries are caught, and plain
  output passes unchanged. Phase 4.
* **Authority in the environment** (low). A cron job's `allow` reaches
  the hook through configuration, not the environment: the daemon runs
  each job with its own Gears config under `/user/cfg`, whose hook
  command line carries `--job <id>`, and the hook looks the job up in
  `jobs.json`. The batteries also strip their own markers from tool children,
  as Gears strips the provider key. Phase 6.
* **Loose ends** (low):
  * the HTTP front end limits body size, connections and header time
    before authentication, and compares keys in constant time;
  * Telegram commits the `getUpdates` offset before dispatching;
  * MCP pins each approved server's schema hash, and treats
    `tool_search` output as untrusted;
  * Monty runs in the None role. Its host functions call back over a
    pipe to the Interactive tool process, which runs read, search and
    web with the same checks, so web keys never enter the None process.
    Monty pauses at each host call (`RunProgress::FunctionCall`), which
    makes this simple. A prototype ran a script in the VM that counted
    lines across a directory in 32 host calls, in 21 ms including the
    spawn. It also tried `/user/cfg/rush.toml`: the prototype parent's
    path rule refused the host call, and the None-role child's own direct
    read was denied by the kernel. The real host functions use
    `read_file`'s None-role reads instead of that path rule.

The review found the rest sound:
* permission hooks fail closed, and a deny always wins;
* cron denies `sh` by default;
* the review fork's tools are a call-time whitelist;
* the provider key is stripped from children;
* vendor-side fetching avoids SSRF and DNS rebinding;
* HTTP history needs the key, users are allowlisted by id, cron runs at
  most once, and approvals are accepted only while pending.

### 6.8 Prompt resources and licensing

The prompt text worth porting totals about 40K characters, measured at
`d0288be5b3`:

| Text | Source | Characters |
| --- | --- | ---: |
| Identity, help, skills and session-search guidance | `agent/prompt_builder.py:160-258` | ~1.9K |
| Tool-use enforcement, task completion, parallel calls | `agent/prompt_builder.py:347-410` | ~2.2K |
| Memory review / skill review / combined review | `agent/background_review.py:352, 417, 503` | 1.0K / 10.0K / 9.1K |
| Compaction prefix and summary template | `agent/context_compressor.py:252, 3985` | ~5.2K |
| Curator consolidation prompt (optional) | `agent/curator.py:289` | 10.3K |
| Steering note (with E6) | `agent/prompt_builder.py:571-584` | ~0.8K |

Model-family guidance for OpenAI and Google models (~4.8K) is left out.
It exists to correct specific models' habits and should come back only
when needed. All of these texts name Hermes tools, so each one is edited
to the batteries' tool names, not pasted (§8.3).

Hermes is MIT-licensed. The prompt text and the SKILL.md files the
batteries reuse are copied with the MIT notice in `prompts/NOTICE.md`. Ported
algorithms are reimplemented rather than translated line by line; they
carry a one-line provenance comment where the design came directly from
Hermes. The Claude Code impersonation path (review §11.2.3) is not ported in any
form.

### 6.9 Size

| Part | Rust LOC (excluding tests) |
| --- | ---: |
| Gears fixes (E0) and other Gears changes E2–E13 | ~2,700 |
| The batteries' hooks: memory 450, skills 1,400, todo 250, context files 300, subdirectory hints 150, policy 1,050 (600 in phase 1; the rest of Hermes's matcher with the POSIX patterns, and two native checks, 450 in phase 6), redaction and untrusted-content wrapping 300, threat scans of memory and skill writes 200 | ~4,100 |
| The batteries' tools: files 2,000, the `sh` state wrapper 150, session search 500, delegation 300, web 600, MCP with its search bridge 1,450, code mode 600 | ~5,600 |
| The batteries' learning loop and curator | ~600 |
| Daemons: cron 1,000, gateway 1,800 | ~2,800 |
| Security hardening from the red-team review (§6.7), beyond the policy hook's floor: None-role reads with an allowlist, the argument rule, write refusal and unattended deny (phase 1, ~250); taint and pending review writes, marker neutralization, skill approval hashes, snapshot hash checks (phases 2 and 4, ~210); web secret refusal, MCP schema pins, Monty in the None role, the sandbox start check, `sandbox prepare` (phase 5, ~110); approval nonces, user-only gateway, HTTP limits, permission checks (phase 6, ~130) | ~700 |
| **Total** | **~16.5K** |
| E1 external tools, a prerequisite planned separately | ~1,400 |
| **Total with E1** | **~17.9K** |

MCP OAuth is not included; Hermes spends ~2.5K lines on it (§6.4), and it
comes after the first MCP release. Tests roughly double the line count
(§7).

Without E1 this is roughly half of the ~25–35K estimated for a
standalone port (review §11.2.16). Gears supplies the provider, HTTP, sessions,
process control, UI, hooks and mock provider, about 9K lines that
option B would rewrite.

## 7. Phased plan

Phases follow `AGENTS.md`: small patches of 100–300 lines including
tests, each gated by the component tests, and `src/tests/full-test.sh` in
debug and release where the change reaches it. The developer-image leg
runs in release only. Each phase leaves a usable agent. Patch counts are
estimates.

**Phase 0 — decisions (no code).** Before any code, the user decides:
1. Q1 (packaging), Q4 (image), Q10 (names) and Q14 (missing commands),
   §8.1. The other questions wait for the phase that needs them, which
   §8.1's table gives.
2. Whether to approve E0 (~220 lines, §6.3): standalone Gears patches that
   fix the §4.4 defects and land first in phase 1. Each has a scratch
   prototype with regression tests, so this is a decision, not an
   investigation. The plan depends on all three fixes:
   * closing unpaired tool calls, including a round that a turn error
     ended: the review fork and gateway turns replay earlier tool calls,
     and interactive users hit the defect on Ctrl+C;
   * delivering lifecycle hooks after a cancelled turn: the batteries'
     `session_end` flush and E12 need it;
   * bounding compaction's input: gateway sessions that live for weeks
     will otherwise wedge.
3. Whether E1 (§6.3) lands whole in phase 1 or in two parts.
   * The port needs only E1's steps 1, 2 and 6, about 500 lines. Steps 1
     and 2 bring tool directories with their own timeouts; without them
     `lorry test` and delegation run under the single hook timeout. Step
     6 ships the `sh` and `ls` directories. The batteries' `sh` state wrapper
     needs that, because today's built-in `sh` is dispatched ahead of
     hook-owned tools (`runtime.rs:505`), so no hook can wrap it;
     permission hooks still run first (`:472`).
   * Steps 3 to 5, about 870 lines, serve Gears' own users: enablement
     state (~300), scoped approval grants (~320), and UI commands and
     prompts (~250).
   * Phase 1 is ~5.3K lines with all of E1, and ~4.5K with the split.
   * Two rules for the E1 plan's owner (§6.7): in step 2, a `{field}`
     template follows `--`, or the executor rejects values that start
     with `-`; and when step 4 lands, saved grants apply only in the
     interactive UIs, never in `-p` runs.

   *Recommendation:* the split, with steps 3 to 5 landing whenever E1's
   own schedule allows.
4. Whether E3a (with the index-0 fix) and E4, about 250 lines, move from
   phase 3 into phase 1. They do not depend on the port and help today's
   Gears users.

   *Recommendation:* yes.
5. Q18: whether phase 1 may end with short manual sessions against real
   models (§8.1). A hosted model needs the Internet and an API account;
   a local one needs the Internet once, to fetch a server and weights.

The user may also decide on the base-image wrapper fix (`"$@"`, §4.4,
§8.2). The plan does not depend on it.

**Phase 1 — Gears groundwork and a coding agent on Motor OS** (~52 patches with all of E1):
* E0, the three Gears fixes (§4.4), with their regression tests.
* A forward-compatible content-block rule (an `Unknown` variant that
  requests skip), ahead of any new block such as E3a's (§8.3).
* E1 external tools, as planned in `src/bin/gears/plans/gears-external-tools.md`:
  at least steps 1, 2 and 6 (see phase 0).
* The `gears-batteries` crate skeleton and multi-call binary;
  tool-directory manifests.
* File tools: `read_file`, then `write_file` with read-before-write, then
  `patch`, then `search_files` over `rg`.
* The policy hook. It allows the read-only tools, denies the Motor OS hard
  floor of `sh` commands that no approval overrides (§6.4, tested with
  Hermes's hardline cases), and asks the user about every other `sh`
  call.
* The `sh` state wrapper (cwd and exports), with a pinned `PATH`.
* Phase 1's hardening (§6.7): `read_file` and `search_files` reading
  through a None-role child with a two-entry allowlist, a denied `ask`
  in unattended runs,
  `--` before model arguments, the floor's Motor OS mappings, and no writes
  to `/user/cfg`.
* The context-files hook and subdirectory hints.
* The todo tool.
* The schema-budget test, which keeps the enabled tools' schemas under
  ~6K tokens (§6.1).
* A mock-provider scenario for an edit round.

Exit: on the dev image, Gears with the batteries edits a Rust crate under
`/devtools/src` and runs `lorry test` there without the model using
`sed` or `head`. The dev image ships Lorry, not Cargo. A scripted
version of this loop already ran on the prototypes (§4.3). This exit also
needs short manual sessions with real models that check the terse tool
descriptions (Q18, §8.3): a local 32K model and a hosted one, as far as
the user approves the Internet access each needs. These sessions are
not automated gates.

**Decision point.** After phase 1 the user can stop, or go on to any
later phase. Phase 1 alone is the minimal option (§5.4), about 5.3K
lines with all of E1: the Gears fixes and E1, the file tools and policy floor, and the
terminal state, context files, hints and todo, and phase 1's hardening,
plus E3a and E4 if phase 0 moved them here. The real-model sessions of phase 1 are the evidence for
whether the rest is worth its ~12.6K lines.

**Phase 2 — memory and skills** (~27 patches):
* E12 in Gears: re-run `initialize` on session switches and after
  compaction. It relies on E0's lifecycle fix, which lands in phase 1
  (§6.3).
* Memory hook and tool, with the frozen snapshot in a content-addressed
  file referenced from hook state (§6.4).
* Threat scans of memory and skill writes, ported from Hermes's
  `tools/threat_patterns.py`. The review fork of phase 4 writes both from
  conversations that may contain injected text, and whatever it writes
  reaches every later prompt (§8.3).
* Skills discovery, index, `skill_view`, `skill_manage`, with approval by
  content hash and no `platforms` edits; snapshots checked against their
  hash on load (§6.7).
* A reviewed import of Motor OS-relevant bundled skills.
* Session search.

Exit: a fact saved in one session appears in the next session's prompt
and not in the current one. A skill created in one session is listed in
the next.

**Phase 3 — Gears provider work** (~17 patches):
* E4 cache markers and `prompt_cache_key` (native Anthropic markers come
  with E3b); the markers pay off at once for OpenRouter-routed Claude and
  Kimi models. Unless phase 0 moved it to phase 1.
* E3a reasoning echo on the Chat Completions wire (§4.4), and the
  assembler fix for parallel calls that reuse index 0 (§4.4). Unless
  phase 0 moved it to phase 1.
* E3b Anthropic Messages, with signed-thinking replay.
* E5 opt-in retry, with the dropped-call re-prompt (a reply that ends as
  a tool call but carries none is asked again).
* E8 compaction upgrades, building on E0's bounded input.
* E9, image input to the model, only if a use appears; on Motor OS images
  arrive only as files. Its ~300 lines count in the totals but are
  optional.

Each lands in Gears with mock scenarios. E3b also needs an
Anthropic-format mock. Exit: recorded request bodies show cache markers on the stable
prefix and on the last two messages, and a compaction keeps tool groups
whole.

**Phase 4 — learning loop and delegation** (~19 patches):
* E6 JSON events, with stdin approvals and steering (guidance the user
  sends while a turn runs).
* E7 after-turn job.
* E11 lock-free read fork.
* The reviewer configuration and ported review prompts.
* The counters that start a review every ten turns or tool rounds.
* Taint tracking, pending review writes for tainted sessions, Hermes's
  `<untrusted_tool_result>` wrapping and
  neutralized control markers in tool output (§6.7).
* The delegation tool.
* The curator subcommand, which archives stale agent-written skills.
* E2 parallel read-only batches.

Exit: after ten tool rounds a review fork runs, and its first request
repeats the parent's prefix byte for byte (asserted on the mock). A
delegated child's cancellation kills its process tree.

**Phase 5 — reach** (~30 patches):
* Web search and extract through configurable vendor APIs, refusing
  private and link-local URLs.
* MCP (stdio per call, Streamable HTTP) behind the tool-search bridge,
  which offers a search tool instead of every server's schemas (§6.4).
* Redaction for web, MCP and file content, with the phase 4 wrapping
  applied to the new tools; the web tools refuse URLs and queries that
  contain a loaded secret (§6.7).
* Code mode with Monty behind a feature flag, in a None-role child.
* MCP schema pins per approved server (§6.7).
* E10 sandbox mode; the batteries' hook denies sandboxed `sh` if
  `/user/cfg` is open to None, and `gears-batteries sandbox prepare` opens
  a copy of a workspace to it (§6.7).

Exit: tests against a local mock MCP server and a local HTTP fixture; no
Internet.

**Phase 6 — daemons** (~34 patches):
* The cron store, parser and ticker.
* The gateway core, the OpenAI-compatible HTTP front end, then the Telegram
  adapter against a mock Bot API server (Q16).
* Approvals relayed through E6's stdin channel (Q9), and a busy-input
  policy per chat: queue, steer or interrupt (§6.5).
* The POSIX subset of Hermes's dangerous-command patterns, and two
  native checks in place of Tirith, Hermes's external command scanner
  (non-ASCII URL hosts, control characters). They are needed once
  unattended runs auto-allow `sh` (§6.4).
* E13, the per-hook event filter, if hook spawns show up in daemon
  latency.
* Detached start with a pid file, and `stop` (Q12).
* Phase 6's hardening (§6.7): approval nonces in private chats,
  user-only service, HTTP limits before authentication, a `/user/cfg`
  permission check at start, and cron `allow` passed as `--job <id>`.
* Delivery of cron output through the gateway.

Exit: a VM test drives a mock Telegram chat end to end over the TAP
interface, including one approved and one denied tool call. The §4.3
prototypes of the HTTP front end, the approval relay and the detached
start are this phase's first patches in miniature.

That totals about 180 patches. Most patches are near 200 lines of code
and tests, within `AGENTS.md`'s 100–300. The code is ~16.5K lines plus
E1's ~1.4K, and the tests are a similar amount.

For calibration, Gears itself was started on 2026-07-31. It grew into a
44.5K-line workflow harness with modes, tasks, checkpoints, verification
and sub-agents. On 2026-08-25 it was rewritten into today's 12.5K-line
core (`d4513477`: +6,712/−40,662). That shows how fast code can be
written here, not how fast it can be made right: most of those 44.5K
lines were deleted, the grow-then-rewrite pattern that review §11.1.1 finds in
Hermes's history. The
history argues against re-growing a large built-in core, which is the
main reason §5.4 prefers the batteries. It also argues for the
phase 1 decision point.

As a rough measure of time, Motor OS's `main` landed 506 commits between 1
and 25 September, a median of 12 a day across all components. In the
month after Gears' rewrite (`d4513477`), Gears had 14 commits and Lorry
56, about 2 a day. Counting calendar days, as those commits fell, one
stream of reviewed patches at 2 to 4 a day gives:
* phase 1's ~52 patches: about 2 to 4 weeks;
* all ~180: about 6 to 13 weeks.

Review, not writing, sets that pace; the prototypes suggest the code
itself comes quickly.

## 8. Risks and open questions

### 8.1 Questions for the user

Each question lists the alternatives investigated and a recommendation.
In brief:

| Question | Recommendation | Evidence | Needed by |
| --- | --- | --- | --- |
| Q1 Packaging | C1: the batteries plus Gears changes | §5.4; thirteen Gears changes prototyped (§6.3) | phase 1 |
| Q2 Storage and search | JSONL plus a linear scan; an index past ~100 MB | search prototype: 0.24–0.53 s over 41 MB in the VM | phase 2 |
| Q3 HTTP transport | curl subprocess | ~3 ms per request; ~2 ms per MCP call | phase 3 |
| Q4 Image | dev image through phase 5 | — | phase 1 |
| Q5 Learning-loop trigger | E7 after-turn job with E11 | prototyped; parity with a live parent | phase 4 |
| Q6 Prompt stability | keep Gears' rule; freeze fragments in hook state | prototyped (§4.3) | phase 2 |
| Q7 Retries | E5 opt-in, for the daemons | prototyped: ~95 lines, three tests | phase 3 |
| Q8 MCP | per-call Streamable HTTP; OAuth later | prototyped: ~2 ms per call | phase 5 |
| Q9 Approvals over chat | E6's stdin channel | prototyped over HTTP and Telegram | phase 4 |
| Q10 Names | decided: Gears and the batteries (`gears-batteries`); subcommand names open | — | phase 1 |
| Q11 Time zones | one configured IANA zone via jiff's bundled tzdb | probed: DST-correct in the VM, +~0.5 MB | phase 6 |
| Q12 Daemon lifetime | detached manual start | prototyped: survives logout | phase 6 |
| Q13 Sandbox | E10 opt-in; the default for cron `sh`, in a prepared copy of the workspace | prototyped; None-role rules and preparation checked in the VM | phase 5 |
| Q14 Missing coreutils | native file tools plus a prompt fragment | edit-and-test loop prototyped | phase 1 |
| Q15 Code mode | Monty last, behind a feature | Monty ran on Motor OS | phase 5 |
| Q16 First front end | the HTTP API, then Telegram | both prototyped | phase 6 |
| Q17 Background processes | not in v1; later through the daemon | rmux has no scriptable interface | after v1 |
| Q18 Real-model sessions | one local and one hosted model, manual | no model was used here (§8.3) | phase 0 (sessions at the end of phase 1) |

**Q1. Packaging.** The options (§5) are C1 (the batteries plus Gears
changes), C2 (an in-process distribution on the Gears library) and B (a
standalone reimplementation of Hermes's core, not built on Gears).
Running Hermes itself (option 0) and a module-by-module translation
(option A) were ruled out in §5.1 and §5.2. *Recommendation: C1* (§5.4). If the Gears changes in
§6.3 are unwelcome, the fallback is C2. It leaves the `gears` binary's
behaviour alone, though the library still needs a seam for native tools.
B is the last resort.

**Q2. Storage and search.**
* (a) Gears' JSONL sessions plus a linear-scan `session_search`.
* (b) SQLite with FTS5, which works today (§4.3) with a `geteuid` override
  through `xSetSystemCall`, the `unix-none` VFS, and a whole-file
  `File::lock` for single-writer safety. It costs a C toolchain in the
  build and a stub `sys/ioctl.h`. It rules out native Lorry builds unless
  `libsqlite3-sys`'s build script is patched (§4.3).
* (c) (b) without the workarounds, by adding the missing mlibc sysdeps
  (the getuid family and `F_SETLK`). This is a cross-repository change to
  `../toolchain-src/mlibc` that selects a new toolchain assembly. The
  CPython plan proposes the getuid part (`docs/plans/cpython.md` §6.3);
  `F_SETLK` would be new.
* (d) A pure-Rust inverted index kept beside the JSONL files.

*Recommendation: (a)*. The measured scan speeds (§4.3) keep (a) near a
second up to about 100 MB of history. Move to (d) past that, and to
(b) only if ranked full-text search becomes a requirement. Both Gears
and Hermes started with per-session files.

**Q3. HTTP transport.**
* (a) Gears' curl subprocess: one spawn per request, streaming SSE today,
  pure-Rust dependencies.
* (b) In-process rustls with the `moturus/ring` fork: faster and needed
  for websockets, but host-built only because ring's build needs Perl.
* (c) tokio plus hyper plus tokio-rustls: works on Motor OS in principle
  (`httpd-axum` is the server-side precedent), but pulls in the tokio,
  mio and `parking_lot` forks.

*Recommendation: (a)*. A curl request costs ~3 ms and a whole `gears -p`
turn ~36 ms on Motor OS (§4.3), which is invisible at personal-agent request
rates. Websocket platforms stay out of scope.

**Q4. Which image hosts the agent.** Gears and curl ship only in the dev
image. A personal-agent VM (gateway plus cron) on the standard image would
need curl, gears and the batteries added to `src/imager/motor-os.yaml`, about
+6 MB and no boot-time work. Measured release builds for Motor OS: `gears`
1.4 MB and curl 1.4 MB. The batteries prototype is 2.2 MB stripped. It was
413 KB before the threat scans and the floor pulled in `regex` and
`fancy-regex`, whose Unicode tables dominate. With jiff's time-zone data
(Q11) it measured 2.7 MB, so a full build without code mode is likely
~3 MB. Monty adds ~7 MB. Trimming `regex`'s Unicode features where the
patterns allow is the main size lever. *Recommendation:* use the dev image through
phase 5 and decide for phase 6.

**Q5. Learning-loop trigger.**
* (a) E7, a Gears after-turn job, with E11's lock-free read fork
  (§6.4). The gateway starts the same reviewer itself after its turns.
* (b) A `turn_end` hook that starts a detached reviewer. This needs
  `gears` listed under `spawn-detached` in `/user/cfg/rush.toml`, and
  Gears changed to pass `CAP_SPAWN_DETACHED` to that hook. Default spawn
  masks never include it (`docs/caps.md`), so this is a Gears change as
  well, and a less contained one.
* (c) An explicit `/review` command only.

*Recommendation: (a)*. Prototyped: E7 was ~60 lines in the runtime with
no UI change, and it drove a live-parent review end to end (§6.4).

**Q6. Prompt stability.** Hermes pins the system prompt for a session's
whole life. Gears deliberately rebuilds it from current resources on
resume and notes changes by hash. *Recommendation:* keep Gears' policy,
and have volatile fragments (the memory snapshot and the skills index)
frozen in hook state. E12 re-runs `initialize` after a compaction, which
is where Hermes refreshes them; `after_compact` cannot return fragments
today. That gives Hermes's cache behaviour without changing Gears'
rule.

**Q7. Automatic retries.** Gears retries nothing by design ("plan
decision 7" in `src/provider/mod.rs`). Hermes retries three times with
backoff, plus fallbacks. *Recommendation:* E5 as opt-in configuration,
enabled by the unattended daemons (cron, gateway) and off for interactive
use. No provider fallback chains. The prototype put the retry in the
runtime rather than the provider, because only the runtime knows whether
anything has been shown (§6.3).

**Q8. MCP lifetime and auth.** The options are per-call HTTP and stdio
(no Gears change), or a persistent client owned by Gears. The auth
options are:
* unauthenticated servers only;
* bearer tokens obtained on the host and stored in `/user/cfg`;
* the OAuth device flow in the VM.

*Recommendation:* per-call Streamable HTTP first, with host-obtained
tokens. A prototype ran it in the VM at ~2 ms per tool call, surviving
an expired server session (§4.3). Add the device flow next, since 55 of Hermes's 65 catalog servers
use OAuth. Add a client to Gears only for a concrete stateful server that
is actually needed.

**Q9. Approvals over chat.**
* (a) Allowlisted users only; unattended runs deny any `ask`.
* (b) A permission hook that parks the request in a file the gateway turns
  into a chat prompt, then waits for the answer with a timeout. This is
  Hermes's blocking rendezvous, done across processes. It needs polling,
  and the hook's single timeout would have to cover a human's reply time
  (§6.3).
* (c) Gears' own `ask` path, carried over E6. In `--output jsonl` mode,
  Gears' approver writes a `permission_request` record and reads a
  `{"id": N, "answer": "once" | "session" | "deny"}` line from stdin. A
  caller that closes stdin, as delegation and cron do, gets every prompt
  denied, which is today's `-p` behaviour. The gateway turns the record
  into a chat question or an HTTP event, and writes the answer back.
  Hermes's `/v1/runs/{id}/approval` endpoint maps onto the same channel.

*Recommendation:* (c). It needs no files, polling or hook timeouts, and it
keeps Gears' existing approval semantics. Over chat the gateway offers
only once and deny. In today's Gears a "session" answer allows every
later tool call of any kind for the rest of the process
(`runtime.rs:486-493`), which in a gateway turn the user would not see
coming (§6.7). Prototyped as ~50 lines on top of E6 plus a smoke test, and run
end to end through the prototype HTTP front end in the VM (§4.3).

**Q10. Names.** Hermes's MIT license covers code and text, not its name.
Decided: the extension is the batteries, built as `gears-batteries`. Its
subcommand names (`gears-batteries cron`/`gateway`) are still working
names, and whether to present the result as "Hermes" at all is still the
user's choice.

**Q11. Time zones.** Motor OS has no time-zone database, and its clock is UTC.
Hermes resolves one IANA zone (`HERMES_TIMEZONE`, then `timezone` in
`config.yaml`, then server-local time; `hermes_time.py`). It uses that
zone for cron expressions, for naive one-shot timestamps and for the
time line in the system prompt. Its #51021 fixed jobs firing hours off
when the stored zone and the checking zone differed. The options are:
* UTC schedules plus an optional fixed offset per job. This is wrong
  twice a year for any zone with daylight saving time.
* A tz database compiled into the batteries with `jiff` (pure Rust,
  MIT/Unlicense, no build script), using `default-features = false` and
  `features = ["std", "tzdb-bundle-always"]`. jiff 0.2.35 is already in
  `src/bin/gix/Cargo.lock` and `src/bin/lorry/Cargo.lock` through gitoxide,
  so it is not a new crate for the tree.
  The probe (`tz-probe/`) converted 09:00 America/Los_Angeles to 16:00Z
  on 2026-10-31 and to 17:00Z on 2026-11-02 in the VM, which is correct across the
  2026-11-01 change. It lists 598 zones. Size on Motor OS, stripped:
  * a bare `println!` binary is 96 KB;
  * jiff with fixed offsets only is 301 KB;
  * jiff with the bundled database is 612 KB.

  The database therefore adds about 310 KB on top of about 205 KB of
  jiff itself. Rule changes need a rebuild with a newer `jiff-tzdb`,
  which the images' regular rebuilds cover.
* A zoneinfo directory in the images, read at run time. This changes
  the images for one consumer.

*Recommendation:* the bundled jiff database, with one configured zone
as in Hermes (UTC when unset). The cron parser stays hand-written
(~300 lines), because jiff has no cron expressions. It walks civil
time in the configured zone, and `to_zoned` resolves times in DST gaps and
folds with jiff's "compatible" rule: a gap moves later, and a fold takes the
earlier instant. Durations ("every 30m", "in 2h") stay in absolute time, as
Hermes does. The ~0.5 MB grows the `gears-batteries` binary (2.2 MB to 2.7 MB stripped, Q4), so an alternative
is to keep jiff out of it and build `gears-batteries-cron` as its
own binary. Fixed offsets remain the fallback if that size is unwelcome.

**Q12. Daemon lifetime.** Cron and the gateway must outlive the login
shell. The options are:
* list `gears-batteries` under `spawn-detached` in `/user/cfg/rush.toml`,
  as rmux is, so it can start its daemons detached;
* an rmux pane, whose server already survives logout, but only once
  rmux authenticates its loopback peer (§8.2): today a None-role process
  can drive any pane, so a sandboxed job could reach an Interactive
  shell;
* a `svc:` line in `sys-init.cfg`, which adds boot-time work and would need
  review under `AGENTS.md`.

*Recommendation:* a detached manual start in v1. Do not add a boot
service. The prototype gateway detached this way and kept serving after
its ssh session ended (§4.3). The batteries' start command must be run from
the login shell itself, typed or sourced with `.`. A script run as
`rush start.sh` cannot pass on the capability.

**Q13. Sandbox.** E10 runs `sh`, and the file tools in that mode, in the
None role: the lowest of Motor OS's three process roles (None ⊆ Interactive
⊆ System), which can write only in shared scratch trees such as
`/user/tmp` (`docs/fs-permissions.md`). The child gets it through
`MOTOR_OS_CAPS` (`docs/caps.md:105-109`). Runtime-created files are
read-only to lower roles, so on its own E10 works only in workspaces that
None-role processes created (§6.7). A preparation step that widens
None's permissions works today, checked in the VM (§6.7). It runs on a
copy of the workspace, since whatever a sandboxed job writes is
untrusted. A dedicated workspace role would be cleaner, but it would be
a kernel and FS change.

*Recommendation:*
* E10 opt-in for interactive use;
* the default for a cron job's `sh`, with an explicit `"sandbox": false`
  opt-out, working in a copy that `gears-batteries sandbox prepare` makes;
* no kernel change for this project.

Sandboxed jobs cannot run Lorry builds until Lorry offers a private
cache to None-role callers (§6.7, §8.2).
The `sh` part of E10 was a ~35-line prototype, checked in the VM (§6.3,
§6.7); the estimate with the file tools is ~60.

**Q14. Missing coreutils.** Models reach for `grep`, `head`, `tail`,
`diff` and `mkdir -p`, and redirect to `/dev/null`, none of which exist on
Motor OS (§4.3). Quoted arguments with spaces break in the base image's
command wrappers (§4.4). The options are:
* add them to `sysbox`, a core OS change that `AGENTS.md` treats as
  suspicious for project work;
* rely on the native file tools and list the available commands in a
  prompt fragment;
* point the model at `rg`.

*Recommendation:* the native tools plus a prompt fragment. Revisit if
transcripts show wasted rounds. `/dev/null` is the exception worth a
separate look. The `sh` state wrapper could rewrite it to a scratch
file, but a rush-level null sink would be cleaner. That would be a
change to rush, not this project's to make.

**Q15. Code mode.** Monty works on Motor OS (§4.3) but is experimental
(0.0.21), adds ~7 MB, and needs the `getrandom` custom-backend cfg. The
alternatives are Lua, which already exists as C on the dev image, and
rush scripts calling `gears-batteries tool ...`. *Recommendation:* ship code
mode last, behind a feature, with Monty pinned to a reviewed revision.
The rush-script route needs nothing new and is worth a prompt note
meanwhile. Lua (5.4.8 in the dev image) is a weaker alternative than it
looks. In the VM, `io.popen` failed with mlibc's "Library function fails
due to missing sysdep" (`posix_stdio.cpp:66`), while `os.execute` and
file I/O worked. A Lua script could therefore call tools only through
temporary files.

**Q16. First front end for the daemon.** The options are an
OpenAI-compatible HTTP API, Telegram long polling, or IRC (Hermes's
reference chat adapter). *Recommendation:* the HTTP API first, because it is
hermetic and needs no outside account; Telegram second, as the first real
chat platform (§6.5). A 191-line prototype of the HTTP front end served
chat completions from the VM at ~35 ms per turn, with session
continuation by header and per-session serialization (§4.3). A 215-line
Telegram prototype then ran against a mock Bot API with streamed edits
and chat approvals, so neither order is risky. Whose history wins, the
request body's or the Gears session's, is a sub-question answered in
§6.5.

**Q17. Background processes.** Hermes lets the model start a command
in the background, then poll, read, wait on or kill it; that is how
models run dev servers and long builds. On Motor OS a job needs a user
that outlives the tool call, since an ordinary child dies with its
parent. In the VM, a `sleep 40 &` started from an ssh shell was gone as
soon as that shell exited. The options are:
* rmux as the user. Its server already survives logout, but it has no
  scriptable interface for this: control mode and `run-shell` are
  explicit non-goals (`src/bin/rmux/README.md`), and its CLI offers only
  `new`, `attach`, `ls` and `kill-session`;
* a job table owned by Gears, so jobs die with the agent, as Hermes's
  in-process registry does. This is a Gears change of a few hundred
  lines;
* the batteries' detached daemon, which already hosts cron and the gateway.
  It would take job requests through a spool directory under
  `/user/tmp`, because Motor OS has no Unix sockets. Tools would read the
  logs it writes.

*Recommendation:* leave them out of v1. If transcripts show the need,
add them through the daemon, which keeps Gears unchanged and lets
jobs survive the agent.

**Q18. Real-model sessions.** Every experiment here used scripted mocks
(§8.3). Phase 1's exit should include short manual sessions that check
whether real models follow the terse tool descriptions and the ported
prompts. The options are:
* a local model only. The build host has no `llama-server`, `ollama` or
  weights, and fetching them needs the Internet once;
* a hosted model through OpenRouter, Gears' default. Each session
  reaches the Internet, which `AGENTS.md` allows only with the user's
  approval, and needs an API account;
* both.

*Recommendation:* both, as manual sessions outside the automated gates:
one 32K local model and one hosted model the user picks. The user
supplies the account and approves the Internet access for both: the
hosted sessions, and the one-time download for the local model.

### 8.2 Small changes elsewhere in Motor OS that would help

The three Gears defects of §4.4 are not listed here: the plan needs
them fixed and schedules them as E0 in phase 1. None of the changes
below is required by the plan. Each is outside its scope and is listed
for the owners of those components.

| Where | Change | Why | Size |
| --- | --- | --- | --- |
| `img_files/motor-os-base/system/bin` | `"$@"` instead of `$@` in 26 wrappers (§4.4) | Arguments with spaces are split again | 26 one-line edits |
| `src/bin/rush` | A null sink for `/dev/null` redirections, also used for `>&-` | `2>/dev/null` fails, and so does `>&-`: rush approximates closing a descriptor by opening `/dev/null` (`src/bin/rush/src/exec.rs:1361-1366`), and `echo x >&-` printed `rush: /dev/null: NotFound` with status 1 in the VM | ~30–50 lines |
| `src/bin/curl` | `--expand-url`, like the existing `--expand-header` | Keeps URL-path secrets (the Telegram token) out of argv (§4.3) | small |
| `src/bin/curl` | `--resolve` | Would let a local-fetch `web_extract` pin the address its SSRF check approved; the recommended vendor design does not need it (§6.4) | small |
| `src/sys/lib/rt.vdso/src/rt_fs.rs:1359-1383` | `opendir` checks the caller's list permission, as POSIX `opendir` does with `EACCES` | It only stats the path, so `std::fs::read_dir` on a directory the caller may not list succeeds and the first entry fails. The kernel still denies the listing, but a check that only opens the directory is fooled (§6.7). It is a core-OS change | small |
| `src/sys/tools/sysbox` | `mkdir -p` | Models use it constantly (§4.3). It is a core-OS change, and the batteries' file tools can create parents instead | small |
| `src/bin/rmux` | Authenticate the loopback peer, for example a session cookie in a file the None role cannot read | The server binds `127.0.0.1:0` and accepts any local client (`src/server.rs:1434-1487`); the port is published in `/user/tmp/rmux.port`, which None can read (`src/sys/motor.rs:110-114`). So a None-role process can attach to, or start, an Interactive rmux session and drive its shell. Diagnosed in the VM (§6.7). Until it is fixed, E10 must not run where an rmux server is reachable, and the daemons must not be hosted in an rmux pane | small; rmux work needs its user's approval |
| `../toolchain-src/mlibc` (another repository) | A fork-less `popen` in mlibc's generic code, plus spawn-time stdio redirection (file actions), which Motor OS's `PosixSpawn` sysdep rejects today (`sysdeps/motor/generic/sysdeps.cpp:488-490`) | Lua's `io.popen`, and any C program's `popen`, fails on Motor OS: the generic `popen` needs `Fork` (`options/posix/generic/posix_stdio.cpp:60-66`). `system()` works through a separate spawn path (Q15) | not sized; it changes the toolchain assembly |
| `src/bin/lorry` | A build cache that a None-role process can use, for example the project-local `target/lorry/.cache` when the global cache is not writable | Sandboxed (E10) `sh` cannot run `lorry test`: the global cache `/devtools/lorry/cache` is not None-writable, and its overrides in `/devtools/cfg/lorry.toml` and `/user/cfg/lorry.toml` apply to every build (§6.7) | small; Lorry work needs its user's approval |
| `src/bin/lorry` | No incremental builds on Motor OS, or no hard-link warning | Every compilation printed rustc's incremental-cache hard-link warning, ~300 bytes of noise in the agent's context (§4.3) | small |

### 8.3 Risks

* **Prompt text is coupled to Hermes's tool names and behaviour.** Ported
  guidance must be edited to match the batteries, not pasted, or it will tell
  the model about tools that do not exist.
* **Small local models.** At 32K tokens with a local model, the learning
  loop can produce low-value skills. The curator's archive rule and the
  review prompt's "do not capture" list are the mitigation. The
  schema-budget test keeps the toolset from crowding out the conversation.
* **Long-lived sessions amplify the §4.4 bugs.** A gateway chat is one
  session that lives for weeks. Any of the following would break it for
  good:
  * a single unpaired tool call;
  * an empty assistant turn;
  * one oversized tool result that compaction cannot summarize.

  So the §4.4 fixes are prerequisites (E0, phase 1), not options.
* **No real model was used.** Every prototype ran against a scripted mock
  provider, so the plumbing is tested but model behaviour is not. Even a
  local model was out of reach: the build host has no `llama-server`,
  `ollama` or model weights, and fetching them needs the Internet. That
  covers whether terse tool descriptions (Appendix C) steer models as
  well as Hermes's tuned ones, whether ported review prompts produce
  useful memories and skills, and whether models honour the steer marker.
  Phase 1 should include short real-model sessions against the dev image
  before the descriptions are final.
* **Hermes is not an upstream.** At ~670 commits a day it cannot be
  tracked. Treat `d0288be5b3` as a reference snapshot, and adopt later
  ideas deliberately.
* **Prompt injection, including injection that persists.** Web, MCP and
  file content reach the model. The review fork then reads those
  conversations and writes memory and skills, which reach every later
  prompt. Mitigations:
  * phase 2 ports Hermes's threat scans for memory and skill writes;
  * a skill's `scripts/` are never run automatically;
  * an agent-created skill keeps its `created_by` flag, and the user
    approves skills by content hash, so a later agent edit withdraws the
    approval;
  * phase 4 ports Hermes's `<untrusted_tool_result>` wrapping as a
    `tool_result` hook, with the reviewer. A review of a session that saw
    web, MCP, delegated or non-owner content writes only to a pending
    area the user accepts (§6.7);
  * the web tools fetch through vendor APIs, which avoids SSRF, and
    refuse URLs that carry a loaded secret.

  These reduce the risk; none removes it, since reworded instructions
  pass any pattern scan.
* **Format compatibility.** Several formats outlive a single release:
  * the session JSONL gains a content block with E3a, which an older
    Gears cannot read. Content blocks are an internally tagged enum with
    no fallback (`src/provider/types.rs:16-31`). In a host test, base
    Gears resuming a session that the E3a prototype had written failed
    with `bad message: unknown variant 'reasoning'`, and the whole
    session became unusable. The fix is cheap if it lands first: an
    `Unknown` variant (`#[serde(other)]`) that request building skips.
    Prototyped on base Gears, it is a five-line change: that build
    resumed the E3a-written session and finished the turn, and the base
    suite passed. It belongs in phase 1, with E0. A Gears from before that rule
    still cannot read newer sessions. That matters when a session meets
    an older binary: Gears rebuilt in place from an older revision under
    `/devtools/src`, or a session copied from another VM. The fallback
    loses nothing on disk: forks and clones copy entries as raw JSON
    (`Entry::data` is a `serde_json::Value`, `session.rs:33-41`), so only
    the older binary's requests omit the block;
  * E6's records and stdin lines form a protocol that daemons depend on,
    and should carry a version in their first `session` record;
  * the batteries' state (hook state, snapshot files, cron jobs, the
    gateway's session map) needs a version field from the start.
* **Maintenance.** The batteries and the Gears changes come to ~18K lines of
  code, and as much again in tests. E3b must follow Anthropic's API
  changes, Monty is pinned at an experimental 0.0.21, and every
  dev-image VM leg adds time to `full-test-dev.sh`. The batteries need a user
  as much as the code needs writing, which is another reason for the
  phase 1 decision point.
* **Motor OS limits:**
  * a process that sets an environment value over 4,092 bytes panics
    (`setenv`, including rush's `export`). Values passed to a child at
    spawn are not limited. Prompts should still go over `argv`, stdin or
    files, since a child that re-exports them would hit the limit;
  * 256 KiB default thread stacks;
  * the loopback accept slowdown in `docs/plans/future-work.md` matters
    only for a process that connects to its own listener;
  * DNS has no cache, and a 33rd concurrent lookup fails
    (`docs/plans/networking-remaining-steps.md:145-147`).

## Appendix A. How the numbers were measured

Run from the Hermes checkout unless noted.

* Size of history and tree: `git count-objects -vH`, `du -sh --exclude=.git .`,
  and per-path history cost from
  `git rev-list --objects --all | git cat-file --batch-check='%(objecttype)
  %(objectname) %(objectsize) %(objectsize:disk) %(rest)'`, aggregated by
  path.
* Lines of code: `tokei` per directory; growth over time from
  `git ls-tree -r -l $(git rev-list -1 --before=DATE HEAD)` byte sums.
* Commit velocity: `git log --format=%cd --date=format:%Y-%m | sort | uniq -c`;
  co-author trailers: `git log --since=2026-08-01 --format=%B | grep -ic
  'co-authored-by: claude'`.
* Tests: `grep -rh '^\s*\(async \)\?def test_' tests --include=*.py | wc -l`.
* Tool schemas: a Python `ast` walk over `tools/`, `agent/` and `plugins/`
  evaluating literal `registry.register(schema=...)` arguments across
  module imports (25 of 59 core tools resolve statically).
* Motor OS experiments: scratch crates cross-built with the Motor OS toolchain
  (`rust-toolchain.toml` of this repository), linked with
  `motor-rust-cc` when C was involved, uploaded with sftp to a
  `run-qemu.sh -snapshot` VM of the release `motor-os.qcow2` or
  `motor-os-dev.qcow2`, and run over ssh.
* Gears prototypes: a scratch git copy of `src/bin/gears` at `2ff1400c`,
  one commit per change, tested with `cargo test`, `cargo fmt` and
  `cargo clippy --all-targets` on the host and cross-built for Motor OS.
* Mock model providers and the mock Bot API: small throwaway HTTP servers
  on the host that record request bodies, reached from the VM over the
  TAP interface.

None of this code is in the repository.

## Appendix B. What option B would take

If a standalone port is preferred (§5.3), this is its shape. The sizes are
the per-area estimates of review §11.2.16, split into components. The layout is a
single workspace of small crates so each can be tested on Linux as well as
Motor OS.

| Crate | Contents | Hermes source it replaces | Rust LOC |
| --- | --- | --- | ---: |
| `agent-types` | messages as content blocks (text, image, tool call, tool result, reasoning, opaque provider state), tool specs, usage, stream events | `agent/transports/types.py`, message dicts | ~400 |
| `agent-http` | HTTP/1.1 client over rustls and ring (Motor OS curl's `http.rs`/`tls.rs` as the reference), SSE parser, egress allowlist | openai/anthropic SDKs, httpx | ~1,200 |
| `agent-provider` | three wires (Chat Completions, Anthropic Messages, Responses), status-first error classes, bounded retry, cache markers, a provider table of ~10 entries, context-window table | `agent/transports/`, `chat_completion_helpers.py`, `error_classifier.py`, `prompt_caching.py`, `model_metadata.py` | ~4,500 |
| `agent-core` | the loop and its invariants (review §11.2.17), read-only parallel batches, result budgets and spill, interrupt tokens, per-agent iteration budgets | `conversation_loop.py`, `turn_*.py`, `tool_executor.py` | ~2,500 |
| `agent-store` | JSONL sessions with lineage, soft-archive on compaction, frozen prompt, scan search | `hermes_state*.py` (essential part) | ~1,200 |
| `agent-context` | prompt assembly (tiers, context files, skills index, memory snapshot), compaction (prune, aligned boundaries, templated summary, fallback) | `prompt_builder.py`, `system_prompt.py`, `context_compressor.py` | ~2,500 |
| `agent-tools` | registry and toolsets; terminal on rush with the state wrapper; read, write, patch, search; memory; skills; todo; clarify; session search; delegation; web; MCP; approval floor; redaction | `tools/` (essential part) | ~10,000 |
| `agent-review` | nudge counters, review fork, curator | `background_review.py`, `curator.py` | ~900 |
| `agent-cli` | line REPL, about 10 slash commands, inline approvals | `cli.py` and REPL mixins | ~1,500 |
| `agent-daemon` | cron store and ticker; gateway core with a Telegram adapter | `cron/`, `gateway/` (essential part) | ~3,500 |
| **Total** | | | **~28K** |

Compared with C1, option B rewrites the provider, HTTP, session, process
and UI layers that Gears already has (about 9K lines). Its advantage is
full control over the loop, for example pinning the prompt the way Hermes
does rather than freezing it through hook state. Its phases would follow
§7, with an extra first phase for the loop, provider and store that C1
inherits from Gears.

## Appendix C. A draft of the batteries' tool surface

To test the "under ~6K tokens" target of §6.1, the batteries' default tools
were drafted with terse descriptions. The semantics follow Hermes's tools,
and the descriptions carry the Motor OS facts from §4.3 (the `sh` text
describes Motor OS's shell). Sizes are
the JSON of each `{"type": "function", ...}` entry as it would be sent:

| Tool | Parameters | Characters |
| --- | --- | ---: |
| `sh` | `command`, `timeout` | 515 |
| `read_file` | `path`, `offset`, `limit` | 431 |
| `write_file` | `path`, `content` | 320 |
| `patch` | `path`, `old_string`, `new_string`, `replace_all` | 432 |
| `search_files` | `pattern`, `path`, `target`, `glob`, `limit` | 419 |
| `memory` | `target`, `operations[]` (add/replace/remove) | 759 |
| `skill_view` | `name`, `file` | 260 |
| `skill_manage` | `action`, `name`, `content`, `old_string`, `new_string`, `file` | 611 |
| `todo` | `items[]`, `merge` | 512 |
| `session_search` | `query`, `session_id`, `around`, `limit` | 339 |
| `delegate` | `goal`, `context` | 351 |
| `web_search` | `query`, `limit` | 257 |
| `web_extract` | `urls[]` | 283 |
| **13 tools** | | **5,489 (~1.4K tokens)** |

When MCP servers are configured, the three bridge tools (§6.4) add about
800 characters, whatever the number of servers.

For comparison, Hermes's schemas for 13 comparable tools total about
20.6K characters (§6.1). The batteries' other fixed prompt content is:
* the memory snapshot, at most 3,575 characters with Hermes's budgets;
* a skills index of roughly 60–80 characters per skill;
* a few thousand characters of guidance.

Together with the schemas, the fixed cost per request is roughly
3–5K tokens, against ~35K for Hermes's defaults. Hermes's longer
descriptions were tuned against real models, so terse versions need
checking in real sessions before they are final. The budget test in phase
1 is the guard either way.

An example of the style, the `sh` tool:

```json
{"name": "sh",
 "description": "Run a command with rush (POSIX-like) in the workspace. cd and exported variables persist between calls. No /dev/null, grep, head, tail or diff exist: use read_file and search_files instead. mkdir takes one directory and no -p. Background jobs end with the call.",
 "parameters": {"type": "object",
                "properties": {"command": {"type": "string"},
                               "timeout": {"type": "integer", "description": "Seconds, default 120, max 600."}},
                "required": ["command"]}}
```

## Appendix D. A regression-test backlog from Hermes

These Hermes tests encode loop invariants rather than provider folklore.
Their scenarios should become scripted mock-provider tests in Gears or
the batteries. Paths are under Hermes's `tests/`. "Where" names the plan item
that owns each scenario; "prototyped" means a §6.3 prototype already has
an equivalent test.

| Area | Hermes test | Scenario | Where |
| --- | --- | --- | --- |
| Pairing | `agent/test_tool_call_incremental_persistence.py` | An interrupt mid-batch still writes a result for every call, and the assistant turn is saved before any tool runs | E0 (prototyped) |
| Pairing | `agent/test_close_interrupted_tool_sequence.py`, `agent/test_turn_finalizer_interrupt_alternation.py` | After an interrupt, a transcript ending in a tool result gets a closing assistant message, so a user message never follows a tool message directly | E0 (prototyped; steering keeps its mid-turn `tool → user`) |
| Pairing | `agent/test_message_sequence_repair.py` | Before each call, orphan tool results are dropped, adjacent user messages merged and duplicate results removed | E0 (partly: missing results only) |
| Pairing | `agent/test_dropped_tool_call_recovery.py` | `finish_reason: tool_calls` with no calls re-prompts, at most 3 times in a row | E5 (prototyped, opt-in with `runtime.retries`; Gears today ends the turn) |
| Pairing | `agent/test_malformed_tool_arguments.py` | One call with invalid JSON gets an error result; its sibling still runs | Gears' built-in `sh` today (`runtime.rs:554`), untested; E1's executor in the prototype; hook tools receive the raw string, so the batteries must check (test to add) |
| Streams | `agent/test_partial_stream_finish_reason.py` | A stream that ends mid-arguments never runs the call with `{}`; siblings are discarded too | Gears today (a `Truncated` error) |
| Streams | `agent/test_run_agent.py::test_ollama_reused_index_separate_tool_calls` | Parallel calls sent at the same index with different ids stay separate calls | E3a (prototyped) |
| Streams | `agent/test_streaming.py` (`TestSilentRetryMidToolCall`, zero-character retries) | Retry a drop only before visible text or during a tool call; after the retries, fail upward rather than store an empty stub | E5, before visible text only; Hermes's retry after text, mid-tool-call, is not planned |
| Streams | `agent/test_thinking_only_sanitizer.py`, `agent/test_empty_terminal_reasoning_surface.py` | Thinking-only turns never go back to the provider, and a truly empty reply takes a recovery path | E0 (prototyped: empty replies not stored) |
| Compaction | `agent/test_compression_boundary.py`, `agent/test_compressor_tail_cut_tool_pair_floor.py` | A boundary never splits a tool group; the minimum cut moves to a group's end | E8 (partly in Gears) |
| Compaction | `agent/test_context_compressor.py::TestSanitizerPreservesInFlightToolChain` | A trailing call still awaiting its result survives compaction | E8 |
| Compaction | `agent/test_compaction_anti_thrash.py`, `agent/test_infinite_compaction_loop.py` | A compaction that cannot get under the threshold, or does nothing, backs off instead of refiring every turn | E8 |
| Compaction | `agent/test_compressor_truncated_summary_guard.py`, `agent/test_context_compressor.py::TestAbortOnSummaryFailure` (an opt-in mode) | A truncated, refused or empty summary never replaces history | E8 (Gears keeps history on error) |
| Compaction | `agent/test_summary_prefix_semantics.py`, `agent/test_summary_prefix_tool_use.py` | The summary is framed as reference only, does not forbid tools, and old prefixes are stripped on re-compaction | E8 |
| Compaction | `agent/test_context_compressor.py::TestSummaryPromptBounding` | The summarizer's input is capped, the newest record is kept, and the iterative form is capped too | E8 (prototyped: the §4.4 wedge) |
| Compaction | `agent/test_compressor_zero_user_guard.py` | At least one user message survives, without two user messages in a row | E8 |
| Caching | `agent/test_system_prompt_restore.py` | A resumed session sends a byte-identical system prompt, when its resources are unchanged | the batteries' snapshots (shown in a run, §4.3; test to add) |
| Caching | `agent/test_background_review_cache_parity.py` | The review fork sends the parent's exact prompt | E11 + E7 (shown in a run, §6.4; test to add) |
| Caching | `agent/test_compaction_prompt_rebuild.py` | A prompt rebuilt after compaction that comes out identical stays identical | E12 |
| Interrupts | `agent/test_cascading_interrupt.py`, `agent/test_stream_interrupt_retry.py` | The transport error from our own cancel is never retried; a stale stream cannot emit late chunks | E5 |
| Interrupts | `agent/test_sequential_tool_interrupt.py`, `agent/test_concurrent_interrupt.py` | A tool that ignores cancellation is abandoned with a synthetic result; an interrupt set before a batch skips every call | E0, E2 |
| Interrupts | `agent/test_background_review.py` (live turn cancels review) | A new turn cancels the review before it calls the provider | E7 (prototyped) |
| Budgets | `tools/test_tool_result_storage.py`, `tools/test_terminal_truncation_spill.py` | An oversized result, or one that breaks the per-turn total, is spilled to a file with a preview | E8 (prototyped: cap and spill; the per-turn total to add) |
| Budgets | `agent/test_usage_anchor.py` | Context size anchors on the provider's reported prompt tokens plus an estimate of what was added since, and falls back when compaction rewrote the transcript | E8 (prototyped) |
| Budgets | `agent/test_proactive_tool_result_pruning.py::test_no_orphans_both_directions` | Pruning old results keeps pairing intact | E8 |
| Memory | `tools/test_memory_tool.py` (frozen snapshot, overflow, batch) | The snapshot ignores writes after load; going over budget fails with the current entries; a batch is all or nothing | the batteries' memory |
| Skills | `tools/test_skill_manage_batch.py`, `tools/test_skill_size_limits.py` | A failed batch restores the previous state; agent-written skills are size-capped | the batteries' skills |

Hermes has many more tests in each area: about 340 of the ~1,590 test
files in `tests/agent` and `tests/tools` have names in these areas. Most of the streaming and interrupt
files concern specific providers and are not in this list.

