# Task acceptance through conversation

Status: decided by the user on 2026-10-05. This replaces the earlier
proposal for an acceptance command and repository fingerprints.

## User workflow

The user accepts a task's result by saying so in ordinary conversation:

> yes, I accept this

Equivalent clear statements work too; this is not an exact phrase to parse.
The normal saved user message is the evidence of acceptance, including when
the session is resumed. A later review can cite its session and entry ids.
An agent's declaration of completion, a passing check, and permission to
run a tool do not establish that the user accepted the task.

There is no acceptance command, CLI, hook event, status flag, separate
acceptance record or UI reminder. Acceptance requires neither repository
inspection nor a current passing check. Existing check receipts remain
development evidence. Acceptance itself does not schedule a review;
optional reviews read the conversation when they run through their existing
compaction or explicit `/review` triggers.

## Effect on the plan

Phase 7 needs no separate implementation. The proposed Gix snapshot command,
shared repository library and commit/change fingerprint are no longer needed
for acceptance. Continue with phase 8 after the remaining phase 6 validation.

The earlier formal acceptance mechanism was a Gears-specific proposal,
not a mechanism established by the reviewed papers or Hermes. The simpler
workflow follows the user's product decision; it does not claim that
acceptance proves correctness or that a learned skill improves performance.
