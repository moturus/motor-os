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
