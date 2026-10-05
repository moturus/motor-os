# Simple explicit task acceptance

Status: decided by the user on 2026-10-05. Keep `/accept` as an unambiguous
signal, with the repository fingerprint proposal superseded.

## User workflow

The user types `/accept` to say that they accept the current task's result.
The command takes no arguments, records that signal in the saved session
and replies:

> Task accepted.

The session stays open for the next task. A later review can cite the saved
entry's session and entry ids as evidence of acceptance. Ordinary
conversation is not parsed to guess acceptance. An agent's declaration of
completion, a passing check and permission to run a tool are not acceptance
signals.

The command uses the existing hook and session mechanisms. It needs no
separate acceptance CLI, file or UI reminder, repository inspection, commit,
change fingerprint or current passing check. It makes no model request and
does not schedule a review. Existing check receipts remain development
evidence; optional reviews retain compaction and explicit `/review` triggers.

## Effect on the plan

Phase 7 implements this small hook command and verifies that its signal is
saved and available on resume. It is planned, not implemented yet.
The proposed Gix snapshot command and shared repository library are no longer
needed for acceptance. Continue with phase 7 after the remaining phase 6
validation.

This workflow follows the user's product decision. It is not a mechanism
established by the reviewed papers or Hermes, and it does not claim that
acceptance proves correctness or that a learned skill improves performance.
