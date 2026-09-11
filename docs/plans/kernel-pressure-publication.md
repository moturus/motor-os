# Kernel memory-pressure publication race

2026-09-10. Diagnosis and implementation, authorized as part of the kernel-memory work.

The existing `mm/admission.rs::update_pressure(free_for_admission)` accepts a
previously sampled value and uses a CAS on the pressure bit alone. The CAS
protects the bit, not the observation that justified changing it.

A valid interleaving, even with sequentially consistent accesses:

1. Pressure is raised. CPU A observes at least 768 free-for-admission pages
   in `note_pages_freed` or `Admission::drop`, then pauses before clearing it.
2. CPU B admits and completes allocations, leaving at most 512 pages free.
   Its final pressure update leaves or restores the flag to 1. An intermediate
   clear/re-raise is invisible to CPU A's CAS on the single bit.
3. CPU A resumes and successfully changes the flag from 1 to 0 using its old
   observation. There need not be another allocation/free to refresh it.

The reverse ordering can also leave pressure raised after recovery: an
updater samples low free memory while the flag is down, another CPU frees
above the high watermark (its free notification skips the still-clear flag),
then the delayed updater raises pressure from its old sample. In addition, `Admission::drop` subtracts the reservation count returned by its
`fetch_sub`; other admissions can change that count before it reads physical
availability. A correction must resample live counters when publishing.

This is a source-proven race. It has not been established as the cause of the
observed filesystem-pressure timeout or the earlier quiet VM exit. Failure
records and diagnostic runs are under `/tmp/kernel-initrd-adjacent-gate.cRf0oY`.
The filesystem failure is specifically a live server handle after the existing
five-second refusal deadline, observed in both first and second FS episodes.

The desired behavior is that a delayed updater cannot leave its old pressure
state published after newer completed admission/free updates. Preserve the
existing 512/768-page hysteresis and admission floors.

The fix serializes pressure sampling and publication with a dedicated
`SpinLock<()>`. Every existing update site now samples reservations (Acquire)
and then physical availability inside that lock; callers cannot pass a stale
count. Small-page frees participate even while the flag is clear. Only actual
transitions write the shared flag, retaining the existing hysteresis.

A counter change concurrent with sampling may temporarily make the published
state stale, but its notification must acquire this same lock before completing.
After the final notification, the last publisher observes all completed updates
through the lock's acquire/release ordering. A delayed publisher samples after
acquiring the lock, so it cannot restore an earlier observation. Acquiring the
reservation count also observes physical allocations preceding released guards.
The two counters are not an instantaneous snapshot during concurrent mutations;
this fix guarantees ordered refresh, not instantaneous pressure or admission.

The critical section only reads counters and updates the flag: no allocation,
logging, callbacks, or other locks. Interrupts are disabled only around this
section to prevent interrupt-side frees from reentering it. The lock needs no
GS/per-CPU state. Early boot still returns before taking it when the shared
page is unavailable. There is no new boot scan or initialization pass. The
cost is shared synchronization on small-page frees, including normal-memory
frees; compare existing page-fault/churn timings and boot logs during validation.

No new race test or reproducer is proposed. Use the existing pressure,
admission, churn and full suites, plus authorized temporary observations and
existing boot-measurement methods. Remove temporary probes before final
validation. Keep this separate from the inactive block-shaping increment.

Validation so far: strict kernel Clippy passed in both profiles. One full
debug/release pair passed; page-fault timings were 11.574/6.340 microseconds,
within baseline ranges of 11.338–11.789/6.307–6.872. Debug-2 then reproduced a
quiet exit during the first network-pressure episode. At that point the full common gate
and 10+10 threshold were incomplete. This shows the publication fix has not
eliminated quiet exits, without identifying their cause. Original failure
and shutdown-only follow-up diagnostics remain in the evidence directory.

Related process/thread reader fixes are documented in
[kernel-process-readers.md](kernel-process-readers.md).

Clean main-image validation (`publication-lifetime-gate-2/`) passed ten debug
and ten release full-test.sh runs, without source probes or test retries.
All ten debug boots passed the shaping fixtures; all twenty runs passed both
pressure episodes and the shared-listener test containing the empty-buffer
regression. Recorded source hashes still match. Neither the quiet exit nor
the FS refusal timeout recurred. This meets the user's 10+10 threshold for
moving on; it does not establish either failure's root cause. The release
developer-image gate also passed, including native source builds and the
complete Lorry suite (2324 seconds overall). These results apply to the combined five-patch candidate, not independently
tested intermediate commits.

Across the ten runs, page-fault medians were 11.631 microseconds debug and
6.449 release, with ranges 11.533–12.109 and 6.310–7.561. The earlier three-run
baseline ranges were 11.338–11.789 and 6.307–6.872. The new medians are within
those ranges, but several new samples are slower; these are uncontrolled
full-suite observations, not proof that the extra shared synchronization has
no cost. The release kernel-log boot milestone assertion (at most 1000 ms)
passed in every run. No isolated phys::init timing or free-path contention
benchmark is claimed.
