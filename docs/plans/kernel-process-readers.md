# Kernel process/thread reader safety

2026-09-10. Fixes discovered during kernel-memory shutdown diagnosis.

Shutdown diagnosis exposed a process/thread reader lifetime defect:
`Process::list_tids`, `Process::get_thread_data`, `Process::self_object`,
`Process::self_pinned`, and `Thread::self_object` discard their status lock
guards at the acquisition statement. Exit paths mutate the thread map and
take the self-object under that lock, allowing readers to race with removal
and destruction. The fix retains a named guard through each read/Arc clone;
the thread-data call remains outside the process lock after cloning the Arc.
The fences in the self-object readers are redundant with a held lock and
cannot replace its mutual exclusion, so they are removed. Arc cloning and
`object_from_sysobject` acquire no additional locks. Existing process/thread,
handle/stats, churn and teardown tests exercise these paths. No new race test
is added. This defect is not established as the quiet exit's cause.

The sole external `main_thread()` reader had the same lifetime problem: its
getter returned a reference to an Option cleared on exit. It now clones the
thread Arc while holding the process status lock, then releases that lock
before the caller takes the thread status lock. The syscall still returns
E_INVALID_ARGUMENT if no main thread/self-object remains.

The same `list_tids` reader also indexed `buf[0]` before checking capacity.
`sys_dbg_list_threads` passes a caller-controlled length, including zero, so
an empty request on a nonempty thread map could panic the kernel. Bounded
zip iteration now handles empty, single-slot, and exhausted ranges. The
existing shared-listener lifecycle test attaches to its already-running
child and checks the empty-buffer request before detaching and performing
its original kill/restart assertions. Empty requests must be safe even when
a caller has not paused the debuggee; there is no added pause/resume or race
workload, and no new helper process. This runs transitively via full-test.sh.
The initial clean gate was intentionally canceled during prelude before this
additional fix/test;
it receives no acceptance credit and is not a regression.

The combined five-patch candidate passed ten debug and ten release full suites
and the release developer-image suite, without temporary probes or test retries.
The earlier quiet exit and filesystem-refusal timeout did not recur; their
causes remain unproven. These results apply to the combined candidate, not
independently tested intermediate commits. See
[kernel-pressure-publication.md](kernel-pressure-publication.md) for the
pressure fix and the combined timing results.
