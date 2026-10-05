# Simple explicit task acceptance

Status: implemented on 2026-10-05 following the user's decision. Keep
`/accept` as an unambiguous signal; the repository fingerprint proposal is
superseded.

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

Phase 7 implements this command using an existing hook context entry. Its
host and native workflow tests verify persistence, resume, branching and
the absence of model requests or checks. Installed-image validation still
awaits the SDK update described in [the runtime record](gears-yaml-runtime.md).
The proposed Gix snapshot command and shared repository library are no longer
needed for acceptance.

This workflow follows the user's product decision. It is not a mechanism
established by the reviewed papers or Hermes, and it does not claim that
acceptance proves correctness or that a learned skill improves performance.
