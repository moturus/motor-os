# Future work -- recorded, deliberately not scheduled

Items moved out of active plans by explicit ruling. Each entry names
the ruling; nothing here should be picked up without a fresh call.

- **`channel.rs` SeqCst fence audit** (out of scope, ruled
  2026-08-15). The io_channel wake edges now carry their own ordering;
  the SeqCst fences predate that and are likely removable. Removing
  them is its own independently-tested step whose perf verdict should
  close promptly in the same sitting -- correctness-sensitive and
  unhurried, so it waits for a sitting dedicated to it.

- **Wire `sysbox syslog`** (moved out of the networking ledger,
  2026-08-15: not networking). `do_syslog` exists unwired; nothing on
  the image reads the kernel log remotely, which is where every
  headless daemon's output goes -- it has cost diagnosis time (the
  russhd exec round). The related console-buffer drain is worth a look
  in the same sitting: vdso panic text can be lost when the console
  buffer does not drain before teardown, which is why a vdso panic can
  present as silent exit-222.

- **Investigate and fix the intermittent `moto_async` channel wake-elision
  hang** (observed once during the 2026-08-20 networking debug gate).
  `systest` stopped after `test_local_notify_notify_all_cancel`; the next
  test, `test_wake_elision_counters`, never completed, while the VM remained
  alive until the gate's 600-second timeout. If it recurs, capture focused
  diagnostics around the cross-thread bounded-channel sender/receiver and
  `LocalRuntime` polling/committing/parked transition, and fix the underlying
  lost-progress race if the correction is clear. Do not hide it with retries
  or a longer timeout.
