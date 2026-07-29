# Kernel process/thread statistics teardown bug

Date observed: 2026-07-29.

Status: open investigation. This note records a pre-existing kernel defect
found while gating the networking Step 4 patch. It is not caused by the
netstack changes.

## Symptom

An ordinary debug `src/tests/full-test.sh` run reached the final pass marker,
but the kernel emitted:

```text
ERROR kernel::xray::stats - stats: process dropped with 1 active threads.
```

The message comes from `KProcessStats::process_dropped()`. At process
destruction, its per-process `active_threads` counter is required to be zero.
The condition used to be a debug assertion. Commit `60d275ac` changed the
assertion to an error log after it had fired more than once, but did not
resolve the underlying accounting or teardown defect.

## Attribution

The error is not emitted by the new `test_stats_provider()` server thread.
The full log places it after `test_ipc()` asks its child process to exit. That
child:

1. starts an XOR service on a spawned thread;
2. leaves that thread blocked forever in its service loop;
3. receives `exit 0` on its main thread; and
4. randomly exercises either ordinary `std::process::exit()` or
   `SysCpu::exit_process()` from a newly spawned non-main thread.

The non-main-thread exit case was added by `00451931` as a regression test for
process exit from any thread. The parent does not wait for this particular
child, so its kernel error appears after `test_ipc()` has printed its result.
Waiting would improve attribution and make the failure gateable, but it would
not correct the kernel state.

Exiting a process while other threads exist is valid. The kernel must kill and
account for those threads before dropping the process. The main systest
process also exits with a long-lived statistics-provider thread and does not
produce this error, so the existence of an unjoined server thread alone is
not sufficient to trigger it.

## What is established

- This is a kernel accounting/lifecycle invariant violation, not a false
  positive caused by an invalid test operation.
- `KProcessStats::on_thread_added()` increments both the process and system
  active-thread counters. `on_thread_exited()` decrements both. Observing a
  process-local value of one at destruction therefore implies an unmatched
  addition unless a separate counter corruption exists.
- `process_dropped()` does not repair the corresponding system counter, so an
  unmatched addition can leave global active-thread statistics inflated.
- The process exits and the suite continues. Current evidence proves
  incorrect accounting, but does not prove that a runnable thread survives
  process destruction.
- Relaxed atomic ordering is not a sufficient explanation by itself.
  Thread-exit bookkeeping precedes removal from the process thread map, and
  final process destruction follows that lifecycle synchronization.

## Likely area

The strongest correlation is the `exit_process()` path exercised from a
non-main thread while the process also owns the XOR worker. Relevant areas
are:

- `Process::exit()` posting kills to every process thread;
- `Thread::post_kill()` and its multiple asynchronous exit paths;
- `Thread::on_thread_exited()` reaching `Process::on_thread_exited()` exactly
  once;
- thread creation that calls `on_thread_added()` before insertion into the
  process thread map; and
- process self-object removal after the thread map becomes empty.

`Thread::post_kill()` already describes this design as fragile because
`on_thread_exited()` can be called more than once or not at all. The exact
unmatched path has not yet been isolated.

## Recommended next investigation

1. Split the randomized exit regression into deterministic main-thread and
   non-main-thread cases.
2. Make the parent wait for the XOR child so its exit result and kernel
   diagnostics belong to the test that caused them.
3. Include PID, process name, total threads, and active threads in the kernel
   diagnostic.
4. Before and after each focused case, read the per-process and system thread
   metrics to establish whether the global count remains inflated.
5. Trace each thread ID through `on_thread_added()`, `post_kill()`, and
   `on_thread_exited()`, then fix the first path that lacks an exact one-to-one
   transition.

Do not silence or downgrade the diagnostic, and do not make the test join the
infinite worker merely to avoid the valid multi-threaded process-exit case.
