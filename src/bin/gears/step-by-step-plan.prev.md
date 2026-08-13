# gears: step-by-step plan, from zero to self-hosting

Written 2026-07-31; status refreshed and completed history compacted
2026-08-13.

`proposal.md` is the governing design document, `README.md` is the user guide,
and this file records implementation status and the remaining order of work.
Detailed instructions and validation notes for completed steps are available in
git history and are intentionally not repeated here.

## Status — 2026-08-13

Overall: **steps 0–9 are complete. Step 10, the Motor OS port, is partially
complete.** gears works on Linux and runs on Motor OS from the dev image. The
remaining work is Motor interrupt handling, hermetic VM integration, native
self-build provisioning, and final manual validation.

### Done

| Step | Result |
|---|---|
| 0 | Crate skeleton, configuration, platform seam, and tracing |
| 1 | HTTP transport, SSE parsing, egress policy, and loopback mock |
| 2 | OpenAI-compatible provider, key handling, redaction, usage accounting, and `gears ask` |
| 3 | Workspace-confined file tools |
| 4 | Agent loop, permission gate, sessions, undo log, REPL, and one-shot mode |
| 5 / 5a | `run`, `build`, `test`, `fetch`, bounded output, and `/+` expansion |
| 6 | Host git tools; Motor reports git as unsupported |
| 7 | Concurrent, budgeted, optionally read-only sub-agents |
| 8 | Context eviction, summarization, and resumable compaction records |
| 9 | Linux self-build, candidate validation, promotion, and session-preserving restart |
| 10a | Motor cross-build, process platform layer, Makefile/clippy wiring, dev-image installation, and VM smoke run |
| 10b | Motor `build` and `test` tools through `/bin/lorry` |
| 10c | Motor HTTPS transport through `/bin/curl`, including provider errors and `fetch` |

Current verification:

- The host suite passes with `cargo test --locked --offline`.
- A real model created a working Rust hello-world on Linux on 2026-08-01.
- In-VM smoke checks covered gears startup, sessions, the REPL, `/bin/lorry`,
  and HTTPS through `/bin/curl` on 2026-08-01.
- The VM reached OpenRouter and parsed its expected authentication error with
  a placeholder key; an in-VM real-model completion has not been run.

### Planned

| Order | Work | Completion condition |
|---|---|---|
| 10.1 | Motor mid-turn Ctrl-C | An in-band Ctrl-C cancels a live completion/turn and leaves the session resumable |
| 10.2 | In-VM provider mock | A Motor-native loopback TLS mock drives deterministic streaming and tool calls without Internet access |
| 10.3 | Dev full-test integration | The host gears suite and a gears-specific VM scenario run from the dev full-test lane |
| 10.4 | Native self-build provisioning | Lorry can build gears' reviewed dependency graph inside the dev VM |
| 10.5 | Manual milestones | Real-model in-VM run, in-VM self-build, and real-model self-host/promotion are recorded |
| 10.6 | Final gate | Debug and release full tests pass three consecutive times each, with no new warnings |

## Remaining work

### 10.1 — Motor mid-turn Ctrl-C

Motor delivers Ctrl-C as byte `0x03` on stdin rather than as a signal. The
line editor already handles it at the prompt; no reader observes it while an
agent turn is running.

Work:

1. Add a single stdin path that can detect `0x03` during a live turn and call
   `platform::note_interrupt` without competing with prompt input.
2. Make cancellation stop the provider request and sub-agent wait path at
   their existing safe points.
3. Cover prompt-time and mid-turn behavior in focused tests and in the VM
   scenario.

Exit: Ctrl-C cancels an active Motor turn, reports cancellation, and the same
session can be resumed.

### 10.2 — hermetic provider mock inside the VM

The existing mock core is standard-library-only and runs on the Linux host.
The VM test needs a Motor-buildable service around it.

Work:

1. Add a small Motor mock-provider binary with a loopback TLS endpoint and a
   committed test CA.
2. Keep TLS dependencies out of the gears binary itself.
3. Script fragmented SSE, tool calls, usage, and error responses needed by the
   VM scenario.
4. Keep every automated request on loopback; automated tests must never reach
   a real model provider.

Exit: gears completes a deterministic streamed tool-call exchange entirely
inside the VM.

### 10.3 — dev full-test integration

`full-test-dev.sh` already selects `motor-os-dev.img`, which contains gears,
curl, and lorry. It currently runs the common suite without gears-specific
host or VM checks.

Work:

1. Add the gears host suite to the dev full-test lane in debug and release.
2. In the VM, check `gears --version` and run a one-shot mock scenario that
   exercises file tools, `run`, and a dependency-free lorry build.
3. Assert exit statuses and resulting files rather than matching incidental UI
   text.

Exit: one dev full-test command covers the host suite and the hermetic Motor
scenario.

### 10.4 — provision Lorry for an in-VM gears build

The dev image contains the native Rust toolchain and Lorry. A dependency-free
crate builds there today, but gears' full locked dependency graph has not been
provisioned and validated for a native build.

Work:

1. Put the exact reviewed dependency closure and required configuration in the
   dev image's Lorry repositories.
2. Build gears from a synced checkout inside the VM.
3. Record memory use, elapsed time, and motor-fs behavior; this remains a
   manual milestone rather than a routine full-test item.

Exit: the running Motor gears can invoke `build` on its own checkout and stage
a candidate binary.

### 10.5 — manual milestones

Perform and record only the date and outcome of each run:

1. Run a real model from inside the VM with a budget-capped key.
2. Build gears inside the VM with Lorry and stage the result.
3. Drive the Linux self-hosting loop with a real model, validate the full
   applicable suite, promote the candidate, and restart on the same session.
4. Optionally use `gears ask` as a direct endpoint/key spot check.

### 10.6 — final gate

Before declaring step 10 complete:

1. Format with `cargo +nightly fmt`.
2. Run host and Motor clippy with no new warnings.
3. Run the gears crate suite in debug and release.
4. Run the dev full-test lane in debug and release three consecutive times
   each.
5. Update the status table and user-facing README to match the observed
   result.

## Current platform mapping

| Seam | Linux host | Motor OS |
|---|---|---|
| HTTP | Host `curl` subprocess | `/bin/curl` subprocess |
| Toolchain | `cargo` subprocess | `/bin/lorry` subprocess |
| Version control | Host git, when the workspace is a work tree | Explicit unsupported tools; `/undo` remains available |
| Process timeout | Process-group kill | Direct-child kill only |
| Interrupt | SIGINT | Prompt-time in-band Ctrl-C; mid-turn support planned in 10.1 |
| Config | `~/.config/gears.toml` | `/user/cfg/gears.toml` |
| Key | `~/.config/gears/openrouter.key` | `/user/cfg/gears/openrouter.key` |
| Image | Host binary | `motor-os-dev.img` |

## Constraints that remain in force

- Use standard Rust and native Motor OS APIs; keep dependencies small and
  reviewed.
- Automated tests are hermetic. No automated test contacts a real provider.
- Do not add retries, ignored failures, or longer timeouts to hide defects.
- Keep the push-shaped `HttpClient` seam. Motor continues to drive
  `/bin/curl`; gears does not link the curl crate.
- Do not make automatic commits. The per-session copy-before-write undo log is
  the default safety net.
- Validate a candidate before promotion; restart by spawning on the same
  session, not by `exec`.
- A configured-off or platform-missing capability should refuse explicitly
  when silence would mislead the model.
- Select platform code with `cfg(unix)` / `cfg(not(unix))`; Motor has no Unix
  target family.
- gears, curl, and lorry remain dev-image tools and are not part of the main
  Motor OS image.

## Accepted v1 limitations

These do not block step 10 unless separately promoted into planned work:

- Motor has no git; the undo log is the Motor safety mechanism.
- Motor timeouts kill the direct child, not descendants; Motor has no process
  groups.
- The UI remains line-oriented.
- HTTP connection reuse is deferred.
- A native git-format tool and machine-readable Lorry diagnostics are
  post-v1 work.
