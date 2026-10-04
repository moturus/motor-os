# Gears batteries implementation record

Updated 2026-10-03. The design in [gears-batteries.md](gears-batteries.md)
remains authoritative. Work proceeds in small patches with one-line commits.
All Gears defects found during implementation are in scope.

## Current position

The phase 0 companion documents and the phase 1–4 implementations are in
place. Phase 5.1, the new batteries crate and its build, packaging and test
integration, is undergoing validation. The remaining phase 5 features, the
sysbox track and phases 6–12 are not implemented.

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

## Validation boundaries

Each Gears code patch passes `test-gears-http.sh`, formatting and Clippy.
The latest ownership and lock patches also pass Motor-target Clippy, a
native release build and the focused VM regressions. Their portable smoke
tests are included transitively in `full-test.sh` and the installed native
shipped-tools gate.

The release developer-image gate passed after phase 3 packaging
(`0d4a98c2`), with Gears code through `c0266402`. Its log is
`/tmp/gears-phase3-dev-release-compatible.log`. Later phase 4 code is not
covered by that earlier image result. A new release developer-image gate
is running for phase 5.1; record its outcome before committing packaging.

The atomic lock-publication race remains recorded separately in
`docs/plans/future-work.md`, as requested. Do not hide diagnostic failures
with retries, longer timeouts or weaker assertions.

## Next steps

Finish phase 5.1 validation, then implement project instructions and prompt
snapshots, file tools, task/turn tracking and approval policy, declared
checks and their reminder, and session search. At the end of phase 5,
stop for the planned user-run local/OpenRouter trials and their decision.
