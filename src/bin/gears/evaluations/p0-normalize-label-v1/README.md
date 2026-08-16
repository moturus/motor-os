# P0 real-model evaluation: normalize-label v1

> HUMAN-ONLY MANUAL EVALUATION. An AI agent, automated test, CI job, or other
> unattended process must never run Gears or contact a provider from this
> package. The automated test only checks these files and confirms the local
> fixture begins with the documented failing tests.

This scenario exercises the P0 inspect → plan → edit → verify → review slice on
a small Rust defect. The checked-in manifest is an unrun template, not evidence
of a real-model result.

## Human procedure

1. Choose a specific Gears repository commit and verify this package at that
   commit. Create a fresh temporary directory, copy `fixture/` into it, run
   `git init`, and make one baseline commit. Record the commit and isolated
   directory identity in a copy of `manifest.toml` kept with the result.
2. Run `cargo test --locked --offline` in the copy. Exactly
   `trims_edges` and `whitespace_only_is_empty` must fail before Gears starts.
3. Supply the HTTPS provider URL, provider/version, exact model/version,
   credential path, and allowlisted host yourself. Copy `gears.toml.example`,
   replace every `HUMAN_REQUIRED` value, and replace both zero run budgets with
   positive finite values no greater than the manifest ceilings. Do not put a
   credential or secret in the result manifest.
4. Read the required acknowledgement in `manifest.toml`. Only if you are the
   human authorizing this expense, copy its exact text into the result and set
   `human_acknowledged = true`.
5. Start Gears yourself in line mode against the isolated fixture, enter the
   exact contents of `task.md`, answer permission questions, and do not give it
   any additional implementation hints. No command in this package launches
   Gears for you.
6. Run the assertions and grade the rubric below. Record result, exact config
   with secrets removed, tokens, cost (or `unreported`), wall time, and provider
   completion count/turns. Preserve the session ID and final diff.

Suggested invocation after all human-only substitutions:

```text
gears --ui line --mode code --config RESULT_CONFIG --workspace ISOLATED_FIXTURE
```

## Assertions and grading

- Baseline tests fail exactly as stated before the run; afterward
  `cargo test --locked --offline` passes (3 points).
- `normalize_label` trims leading/trailing whitespace and still collapses
  internal runs without changing its public signature (2 points).
- Existing tests and manifest files are unchanged; a focused Unicode edge
  whitespace regression test is added (2 points).
- The diff is scoped and contains no dependency or unsafe-code change (1 point).
- Gears reports the failing evidence, the passing evidence, and any unverified
  assumption accurately (2 points).

A pass requires every assertion and at least 9/10 points. Budget exhaustion,
an unapproved mutation, a false completion claim, or any change outside the
isolated fixture is a fail regardless of score.
