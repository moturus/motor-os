# Review context and prompt-cache reuse

Status: user approved keeping the stable prefix separately on 2026-10-06.

The stable prefix means system instructions and tool definitions, rather than
the entire previous request including history. Save it independently at actual
model requests, retain it across history compaction, and use the marked parent's
prefix for a review. Review instructions follow the shared prefix. The reviewer
may see the same tool definitions, but review permission policy still denies
commands and writes. Old sessions without a saved prefix use their reconstructed
instructions and report that exact historical reuse is unavailable.

Conversation summaries and retained messages replace oversized history; they
do not replace the stable prefix. Original history remains available through
session reading. The auxiliary summarization request has its own instructions
and is not itself the review request. Prefix tokens still count toward context
capacity. A prefix alone that exceeds the limit must be refused explicitly.

## Evidence

`Runtime::maybe_compact` compares the estimated prompt, history and tools
against `window_tokens - output_reserve_tokens` before requesting a completion.
`ensure_fits` refuses an oversized request if compaction is cancelled. With
the defaults, the input limit is 128,000 - 16,384 = 111,616 estimated tokens.

A hermetic probe creates a live saved parent, forks its marked entry and
runs a review with a 4,096-token window and a 512-token output reserve. Its
first captured request is the compaction prompt; the second reviews a summary
without the original task text. The parent remains byte-for-byte unchanged.
The fake provider makes no network calls.

Probe: `/tmp/gears-review-context-probe/src/main.rs`.
Successful log: `/tmp/gears-review-context-probe-pinned.log`.
The first temporary resolver selected an older cached crossterm revision;
using the repository's exact lock fixes that probe setup. No dependency,
SDK or external fork source changed.

## Earlier alternatives

These alternatives assumed the prefix included the entire previous request.
The user's separation of stable instructions from history resolves that ambiguity.

1. **Permit bounded compaction when needed.** Keep the full
   request prefix when it fits; otherwise review a summary and retained
   messages. The original saved history remains available through session
   reading, and proposal citations still refer to the marked parent branch.
   This permits long-session reviews, at the cost of losing cache reuse and
   some detail in the initial request. The prefix acceptance test becomes
   conditional on the history fitting.
2. **Preserve the prefix on every review.** Cancel automatic compaction and
   leave an oversized review due, with a visible explanation. This preserves
   the current acceptance rule but prevents many before-compaction reviews
   from running. Supporting a larger review context separately from the
   executor would need additional configuration; a model's actual capacity
   still bounds the request.

Neither option guarantees a provider cache hit. Reuse also depends on the
chosen provider and models; phase 9 measures its cost rather than assuming it.
