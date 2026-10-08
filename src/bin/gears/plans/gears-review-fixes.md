# Gears review fixes

Status (2026-10-08): steps 1–15 are done, one commit each. The
learning-stack bugs (steps 16–20) are not started: the user asked to keep the
learning stack as it is for now. Where the work differed from the steps below:

- **Step 2, session lock.** It keeps the plain "process alive" owner rule.
  Sessions are also opened by gears-batteries and by test processes, so a
  "process is Gears" check would remove their live locks.
- **Step 4, lifecycle hooks.** Most of the 11 `reset()` calls start a new
  operation and are correct. A separate token would also need its own handling
  of the global Ctrl+C flag. The three reset/run/restore sites now share one
  helper, with no change in behavior.
- **Step 12, approval identities.**
  - They are not cached. An identity hashes the tool's executable, so a
    binary replaced mid-session must stop matching earlier approvals.
  - Removing the manifest fields kept every shipped tool's identity
    byte-identical, so saved grants stay valid.
- **Step 15, `workflow-smoke`.**
  - Only `eval_options` was pure logic. It moved into a unit test.
  - The other modules exercise files through the library. They stay in the
    native Motor OS gate.
  - The request total became a check that the script was used up. The
    other totals pin real behavior and now carry comments.
- **Additional fixes:**
  - The "repeated spaces" patch rule matched indentation differences and
    inserted the text unchanged. It now leaves indentation to the
    indentation rule.
  - `${HOME}` is now kept as one word by the shell tokenizer.
  - A symlinked workspace `.gears/batteries.toml` is still refused, because
    the check command must be declared in the workspace itself.

This plan fixes the Gears and gears-batteries findings from the 2026-10-07
branch review (non-Gears findings are in
[docs/plans/2026-10-07-main-review.md](../../../../docs/plans/2026-10-07-main-review.md)).
It includes the review's simplifications, except those that restructure the
learning stack (memory, skills, reviews, eval, cleanup), which stays as it is
for now.

## Corrections to the review

Checking the code while writing this plan showed that some review claims
were wrong:

- `stdin = "arguments"` and `command.common` are used, by all five batteries
  tool manifests. Only the other manifest fields listed in step 12 are unused.
- `paths::save_result` is used, by `check.rs:65`.
- The `moto-rt` dependency of gears-batteries is used, by `eval_copy.rs:215`.
- Ignoring global grants in `-p` runs (`runtime.rs:1437`) is intended: the
  plan's retained decisions say so. It is not a bug.

Every remaining item is re-checked against the code before it is changed.
An item that turns out to be wrong is dropped and reported.

## Out of scope

- **Learning-stack restructuring.** Not done:
  - merging the memory and skill copies of the pending, snapshot and
    admission code;
  - shrinking eval;
  - replacing skill cleanup;
  - typed `changes.jsonl` records;
  - merging `memory_cli`, `memory_options` and `memory_history`.
- **Approval policy.** The approval surface stays: six answers, global
  deny, and session tool toggles. These are retained decisions.
- **Non-Gears findings** from the main review: sysbox, rush, kernel and
  `full-test.sh`.

## Steps

Each step is one patch of about 100–300 lines with its tests. Every step
passes `test-gears-batteries.sh` and the Gears host tests. Steps that change
process or session behaviour also pass the native Gears VM tests. The final
gate is `src/tests/full-test-dev.sh --release`.

### Gears correctness

1. **Session append is all-or-nothing** (`gears/src/session.rs:571`, `:1190`).
   - Serialize each record and its newline to a buffer, then do one
     `write_all`.
   - On failure, truncate the file back to its previous length and return
     the error.
   - Test: a writer that fails mid-record leaves the file openable, and the
     next append starts on a clean line.
2. **One PID-lock helper.** `session.rs:1154` `acquire_lock` gets the same
   rules as `run_lock.rs` `DirectoryLock`:
   - a grace period for a lock file that exists but is still empty;
   - a `process_is_gears` check, so a reused PID does not block a session.

   Share one helper between the two locks.
3. **Process ownership: no `exit` in library code, and a nested Gears cleans
   up after itself.** Done (uncommitted), with the recommended option the
   user chose on 2026-10-08. The implementation changed from the plan on
   Linux:
   - **Why the subreaper was dropped.** Gears starts provider `curl`
     processes directly (`net/curl.rs`, `net/host_curl.rs`), outside the
     runner. A subreaper sweep of unknown children could kill one of them
     while a background review cleans up.
   - **Linux.** Every runner starts each child in a new process group.
     - After a normal exit, it kills that group.
     - To stop a running child, it freezes the child's descendant tree with
       `SIGSTOP`, then kills every process and process group in it. This
       reaches a nested Gears' own tool groups while their parent links are
       still intact.
     - It also catches a `setsid` job whose parent is still alive. Only a
       job that is in a new session *and* orphaned escapes.
       `tests/cleanup_failure.rs` now builds that escape to keep testing
       the fail-closed path.
   - **Motor OS.** Keep the native descendant walk, and remove
     `finish_interrupted_run`'s `std::process::exit(1)`.
   - **Removed:** `GEARS_PROCESS_GROUP`, `GEARS_PROCESS_OWNER`,
     `inherited_group`, `inherited_owner`, the nested branch of
     `cleanup_after_exit`, and `finish_interrupted_run`.
   - **Also bounded:** the stdin writer join, by the drain deadline.
   - **Result.** A nested timeout stops only that tool, and the nested run
     continues. A background job left by a nested tool is killed at the
     tool's end instead of blocking that Gears' later tools for good.
     Against the old code, the new normal-mode test fails with "further
     work is blocked".
   - **Docs.** "Process ownership and cancellation" in `gears-batteries.md`
     is updated.
   - **Tests.** `tests/smoke.rs` and `examples/tool-smoke/owned_work.rs` (the
     latter runs on both systems) now cover:
     - parent cancellation;
     - a nested timeout that continues the run;
     - a background job followed by a second tool call.
4. **Lifecycle hooks get their own token** (`runtime.rs`, 11
   `cancellation.reset()` calls). `turn_end`, `entry` and `session_end` hooks
   run with a separate cancellation token that only exit or a second
   interrupt sets. The user's cancel token is then never reset and set again.
5. **Request-prefix checkpoints only when hook state changed**
   (`session.rs:744`). `record_request_prefix` appends
   `request_prefix_checkpoint` only if a `hook_state` entry was appended since
   the last prefix or checkpoint. `request_prefix_hook_states` is unchanged,
   and so are saved-prefix reviews.

### Batteries tool correctness

6. **`patch` keeps indentation** (`gears-batteries/src/patch_match.rs`).
   - Insert `new_text` verbatim for the exact, trailing-space and
     repeated-space rules.
   - Under the indentation rule, shift `new_text` by the difference between
     the matched first line's indentation and `new_text`'s first line.
   - Under the escaped rule, unescape `old_text` only.
   - Tests: the dedenting-block case from the review, literal `\n` in
     `new_text`, and the existing table.
7. **File tools.**
   - **New files get default permissions.** `write_file` creates them with
     the umask, not 0600 (`gears/src/state.rs` `replace` when there is no
     destination).
   - **`read_file` gets a size cap** (the 4 MiB `patch` already uses).
   - **`patch` reads the file once**, not three times (`file_patch.rs:32-39`).
   - **Drop the `writes/<hash>.json` receipts**, if a re-check confirms
     nothing reads them (`file_write.rs:59-79`).
8. **Path checks** (`paths.rs:49`, `:54`).
   - Canonicalize the Gears directory and the workspace once.
   - Allow symlinked ancestors of either.
   - Allow symlinks inside the workspace, but refuse a path whose canonical
     target is inside the Gears directory, except the current session's saved
     results, as now.
   - Merge `paths::normalize` and `command_policy::absolute` into one
     normalizer.
9. **`sh` refusal list** (`command_policy.rs`).
   - Skip `then`, `do`, `else`, `elif`, `!` and `time` the way `command`,
     `exec` and `env` are skipped.
   - Expand a leading `~` and `$HOME`/`${HOME}`.
   - Tests for each.
10. **`session_search`.**
    - ASCII case-insensitive matching.
    - Session-file discovery moves to one Gears function
      (`gears::session::files(root)`), used by search, `memory_sources` and
      `skill_usage`.
    - Remove the untrusted-tool names for tools that do not exist yet
      (`web_fetch`, `web_search`, `worker`).

### Gears simplifications

11. **Runtime and hooks.**
    - One `Runtime::new(…, Options)` replaces the four constructors.
    - One `Unattended` type replaces the two (`runtime.rs:143`,
      `ui/jsonl.rs:61`).
    - One provider/model resolution in `main.rs`, shared by `ask` and
      `agent`.
    - Remove the test-only `Manager::initialize`/`permission` wrappers;
      tests call the full forms.
12. **State and manifests.**
    - `tool_state.rs` and `permissions.rs` share one versioned-TOML load/save
      helper and one default directory. `Registry::load_config` uses it too.
    - The `gears-batteries` sibling name is resolved only in `process.rs`.
    - Approval identities are hashed once per registry load, not on every
      call and every `/permission` listing.
    - Remove the manifest fields no shipped tool uses:
      - `allowed_flags`;
      - `prompt`, both top-level and per platform;
      - per-platform `parameters` and `display`.

      Keep `[linux]`/`[motor]` `description` and `process.arguments`, and
      `command.common`/`linux`/`motor`. Update `external-tools.md` and the
      plan's "Tools" section.
13. **Tests.**
    - The 12 `shipped_*` tests become one table-driven test.
    - `lib.rs` hook glue: build the `ToolContext` once, and run the features
      through one merge helper instead of `context_at` and
      `observe_features`.
    - `policy.rs` checks `review_tool_allowed` once.
14. **Test scripts.**
    - `test-gears-batteries.sh` sets `CARGO_TARGET_DIR` instead of reading
      `cargo metadata` with Python, and uses `--offline`.
    - `test-gears-batteries-vm.sh` replaces its Python JSON asserts with exact
      string comparisons or `grep -F`.
15. **`workflow-smoke`.** It stays the native Motor OS gate.
    - Checks that call only pure library logic, such as option parsing and
      formatting, move into `#[cfg(test)]` in their modules.
    - Checks that touch files, processes or the binary stay in the example.
    - Modules that only those tests used become `pub(crate)`.
    - The main scenario's exact totals (17 requests, 8 tool calls, …) become
      checks on the specific events it is about.

### Learning-stack bugs (no restructuring)

These depend on question 2.

16. **Review evidence fits its limit.**
    - Denied changes are limited to this workspace and given as ids plus a
      short summary.
    - Turn records go in without their `events` list.
    - Evidence over the limit is truncated, oldest first, with a note.
    - One mark's failure no longer blocks the session's other marks.
17. **Hook state stays small.**
    - Tool events are appended to `turns.jsonl` as they happen.
    - Hook state keeps counters, the last entry id and the check receipt's
      hash, not the event list or output previews.
    - Readers accept the old state shape.
18. **Memory headers stop eating the limits.**
    - New entries get short ids (8 hex characters, extended on collision).
    - Only the entry text counts toward the size limit.
    - Provenance stays in the header but is not sent in the prompt.
    - Existing entries with long headers keep working.
19. **Eval arms by origin.** An entry belongs to the learned arm if its
    approval record came from a review or an agent proposal, whatever its
    `kind`.
20. **One bad record does not hide everything.**
    - `journal::visit` and `pending_files::list` skip and report a malformed
      line or file instead of failing the whole read.
    - `changes.jsonl` is parsed once per hook event, not once per lookup.

## Questions

1. **Process ownership (step 3).** Answered 2026-10-08: the recommended option.
   - **Recommended:** per-runner process groups plus subreaper on Linux, and
     no `exit` on Motor OS.
   - **Minimal alternative:** keep the shared Linux group; only remove
     Motor OS's `exit(1)`, and stop a nested leftover from poisoning the
     process. Linux and Motor OS then still differ on nested timeouts.
2. **Learning stack: fix its bugs (steps 16–20), or leave it untouched for
   now?**
3. **Commits: one commit per step, or leave everything uncommitted for you
   to commit?**
4. **Optional extras, not in the steps above:**
   - keep workspace pending proposals in the Gears directory instead of the
     cloned workspace;
   - condense `gears-batteries-notes.md` and `-progress.md`;
   - one `batteries.toml` parser with unknown-key errors.
