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
  2026-08-15: not networking). `do_syslog` exists unwired, and nothing on
  the image reads the kernel log remotely. Ordinary rt.vdso diagnostics now
  go to stderr first, and authorized service records go through System-role
  strobe to `/system/logs`; the kernel log remains relevant for kernel and
  direct `SysRay::log` records and for the capability-gated fallback when
  stderr fails. A remote reader is therefore still useful, but no longer the
  primary way to diagnose every headless daemon. The related console-buffer
  drain is worth a look in the same sitting: fallback panic text can be lost
  when the console buffer does not drain before teardown, which is why a vdso
  panic on that path can present as silent exit-222.

- **Resolved 2026-08-20: intermittent `moto_async` channel hang.**
  It recurred in `test_moto_channel_multithreaded`; a focused unchanged
  reproduction stalled on round 26. Two `mdbg` snapshots showed both sender
  threads had exited while the receiver alone remained parked. The last
  `Sender` used to wake the receiver from its `Drop` body before Rust
  dropped the underlying MPMC sender field, allowing the receiver to register
  after the early wake, still observe a connected empty channel, and sleep
  forever. Sender teardown now drops the underlying endpoint before the
  last-sender notifier. A deterministic regression holds teardown inside the
  old gap while the receiver re-registers; the fixed focused suite then
  passed 100 consecutive runs under the same stall detector. No retry or
  timeout workaround was added.

- **kernel `wait-set`** - a kernel-side wait-set/aggregation primitive
  (the structural fix). Beyond the cap, the current shape is O(n) per park: every SysCpu::wait
  re-validates and re-registers all ~1024 objects (the loop in sys_cpu.rs:78-121), on every one of sys-io's ~130k waits in this run. An
  epoll-like kernel object — register a handle once into a wait set, block on the set's single handle — removes both the cliff and the
  per-wait linear cost. This fits the netstack-scalability trajectory, but it's a significant kernel + moto-async project.
