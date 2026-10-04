# Gears batteries implementation record

Updated 2026-10-03. The design in [gears-batteries.md](gears-batteries.md)
remains authoritative. Work proceeds in small patches with one-line commits.
All Gears defects found during implementation are in scope.

## Current position

The phase 0 companion documents and the phase 1–4 implementations are in
place. Phase 5.1–5.6 are implemented. The real-binary workflow passes on
Linux and Motor OS, and the updated release developer-image gate passes.
The sysbox track and phases 6–12 are not implemented. The next design
decision is the phase 5 user-run local/OpenRouter trials.

The phase 3 manual checklist is not marked complete. Automated host tests
cover the runtime and both UIs; native gates cover shipped tools, literal
arguments, local HTTP, the six line-interface approval choices, process
ownership and the directory lock. Complete native interactive UI checks
before declaring that checklist finished.

## Implemented extensions

- Immutable live-session snapshots and ephemeral forks.
- Structured tool outcomes, usage and JSONL one-shot output.
- Hook event subscriptions and bounded `before_stop` follow-ups.
- Hook setup after session changes, provider/model changes and compaction.
- An owned after-turn runner, stopped and joined before runtime writes,
  session changes and exit; interactive interfaces opt in explicitly.
- Hook slash commands, bounded questions and hints in both interactive
  interfaces, with unattended answers for one-shot runs.
- Tool-round counts and last entry ids in end-of-turn metadata.

These changes reuse Gears' shared process runner. Children do not receive
the provider key; cleanup uncertainty prevents subsequent writers or spawns.
Nested timeout behavior is tested with real Gears running a shell child and
grandchild on Linux and Motor OS.

## Everyday coding batteries

- Workspace-root `AGENTS.md`, falling back to `.gears.md`, and bounded,
  content-addressed prompt snapshots. Resume, fork and provider changes reuse
  the snapshot; new sessions and compaction refresh it.
- Numbered UTF-8 `read_file` pages and read coverage tied to the whole file's
  version. Existing files require complete current reads before replacement.
- Literal `search_files` paths with bounded ripgrep output; atomic
  `write_file` and `patch` preserving BOM, newline style and caller access.
  Patches use unique matches and original byte positions for normalized
  matching, and return bounded diffs.
- Protected Gears state paths, with a read exception for the current
  session's saved tool results. File tools refuse symlink traversal.
- Branch-aware `todo` state and durable mechanical turn records, including
  saved entry ids, actual outcomes, failures, repeated calls, writes and
  checks. Incomplete final journal lines are removed before appending.
- Workspace read approvals, ordinary write/command prompts, a short static
  destructive-command list, and fresh confirmation for publishing or
  discarding work. Shell policy uses the shell's saved working directory.
- Literal check vectors with Linux/Motor/common selection in workspace-root
  `.gears/batteries.toml`. Approval details show the selected vector;
  only a matching completed receipt records its execution. Later writer
  calls stale the evidence. Missing, failed or stale checks can add at most
  three follow-ups in a turn.
- Paged `session_search` across all saved branches and workspaces, using
  immutable snapshots. Hits retain session/entry ids and identify off-branch
  text. Curl output and externally sourced history are marked untrusted;
  copied provenance delimiters are defused.
- The opt-in `config/gears-batteries.toml` selects OpenRouter or a local
  provider, registers the hook and enables the coding tools. Developer-image
  packaging merges both tool directories and installs the workflow fixture.

These policies prevent accidents; they do not confine tools. Native atomic
replacement preserves the caller's access rather than every role's metadata.
Checks provide development evidence, not user acceptance. Memory, skills,
`/accept`, reviews, workers, scheduling and gateways remain later work.

The portable workflow uses the actual CLI, shipped manifests and shared
Gears runtime with a scripted provider. It reads a deliberately broken Rust
crate, searches source and sessions, writes a literal filename, patches the
assertion and compiles it. It verifies the saved check, approval details and
turn journal, restores earlier tasks on a fork, then proves a model can get
only three missing-check reminders. No provider or Internet request is made.

## Recent defects and their evidence

- Motor shell state restoration assumed `/dev/null` existed. The original
  developer-image gate failed; removing that redirect restored the native
  shipped-tool gate (`e77e3e5a`).
- Explicit Cargo example metadata prevented the packaged Gears source from
  building with Lorry. Automatic example discovery resolved it (`c0266402`).
- A forced TUI one-shot run could ask for approval. Unattended runs now deny
  without reading input; modified shortcut keys cannot save grants
  (`753fe8c9`).
- A cancelled hook answer still saw the process-wide interrupt flag and
  never reached its hook. A dedicated regression verifies delivery and
  preservation of the original interrupt (`da3c55d3`).
- Scrolling past the beginning blanked the TUI transcript. The renderer now
  clamps scrolling and keeps complete questions readable (`8e81469f`).
- Raw line input discarded bytes queued after a newline and split UTF-8
  characters on backspace. Byte-stream regressions cover queued lines,
  UTF-8 editing and split CRLF input (`b71fe348`).
- A nested Motor OS tool timeout let Gears request another model answer
  and finish successfully. The runner now validates inherited process
  ownership, reaps the child tree and ends the interrupted nested process
  (`83d1521d`). Original failure: `/tmp/gears-owned-vm-sftp-repro.log`;
  fixed native regression: `/tmp/gears-owned-vm-fixed.log`.
- Motor OS command names include arguments and may be truncated. Gears
  misidentified a live lock holder and let a second instance contact the
  model. Complete names now recognize Gears with arguments; ambiguous live
  names preserve the lock (`b0e8eaeb`). Original failure:
  `/tmp/gears-lock-vm-original.log`; fixed native regression:
  `/tmp/gears-lock-vm-fixed.log`.
- Bare hook commands searched PATH for `gears-batteries`, bypassing the
  sibling executable required by the design. Shared-runner resolution now
  covers hooks and after-turn commands as well as tools (`bca70fa5`). The
  original competing-PATH failure is in
  `/tmp/gears-batteries-sibling-original.log`.
- The new opt-in sample omitted loopback egress permission and an explicit
  local key. A direct configuration load caught both policy requirements;
  the corrected sample has a parsing regression (`7d1ba369`).
- The sibling regression's executable copy occasionally failed to start
  with Linux `ETXTBSY`. A syscall trace showed parallel spawns while its
  writable copy descriptor was open. Fixture preparation now runs in its
  own test process (`8a6c7049`), preserving the original assertions and
  timeouts. Original failure:
  `/tmp/gears-batteries-config-complete-host-gate.log`; fixed component gate:
  `/tmp/gears-batteries-sibling-isolated-host-gate.log`.

## Validation boundaries

Each Gears code patch passes `test-gears-http.sh`, formatting and Clippy.
The latest ownership and lock patches also pass Motor-target Clippy, a
native release build and the focused VM regressions. Their portable smoke
tests are included transitively in `full-test.sh` and the installed native
shipped-tools gate.

The release developer-image gate passed after phase 3 packaging
(`0d4a98c2`), with Gears code through `c0266402`. Its log is
`/tmp/gears-phase3-dev-release-compatible.log`. Later phase 4 code is not
covered by that earlier image result. The phase 5.1 release developer-image
gate now passes with Gears through `b0e8eaeb` and the initial batteries
protocol skeleton, including both installed component tests and native
source builds. Its log is `/tmp/gears-batteries-scaffold-dev-release.log`.
That image result does not cover later batteries features.

Phase 5 patches pass the batteries host gate, formatting, and host/Motor
Clippy with warnings denied. The complete workflow passes the focused native
gate (`/tmp/gears-batteries-workflow-native-gate.log`). The installed opt-in
configuration also passes a native startup check, with no model request
(`/tmp/gears-batteries-installed-config-fixed-native-gate.log`). The updated
`full-test-dev.sh --release` gate passes, including installed Gears and
batteries workflows, native HTTP regressions, packaged-source builds with
Lorry, and Lorry's complete product suite (649 seconds). Its log is
`/tmp/gears-batteries-coding-dev-release.log`. The native workflow is included
transitively in `full-test.sh` when testing the developer image. The gate
covers all production changes and the fixture fix. The final setup and
progress documentation was updated afterward.

The atomic lock-publication race remains recorded separately in
`docs/plans/future-work.md`, as requested. Do not hide diagnostic failures
with retries, longer timeouts or weaker assertions.

## Next steps

Stop at the phase 5 decision point for user-run local/OpenRouter sessions:
continue, change course or stop. Use the opt-in configuration and choose the
models, budgets and tasks for those sessions. Automated mock tests establish
behavior, not real-model usefulness. Keep the outstanding native interactive
checklist visible; do not mark it complete from component tests alone.
