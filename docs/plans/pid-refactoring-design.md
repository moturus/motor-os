# PID refactoring: 32-bit-safe process IDs (design)

2026-07-29. Status: **proposed, awaiting review**. Companion:
`docs/plans/pid-refactoring-step-by-step.md` (execution order and status).

## Problem

Motor OS pids are `u64`, allocated by a monotonically increasing counter and
never reused (`src/sys/kernel/src/uspace/process.rs`, `ProcessId::new`).
Existing software assumes pids fit 32 bits, and the compat layers paper over
the mismatch in three mutually inconsistent ways:

- Rust std (`library/std/src/sys/process/motor.rs`): `std::process::id()`
  truncates the real pid to `u32`; `Child::id()` returns a hardcoded `0`
  because the spawner never learns the child's pid (no handle-to-pid mapping
  exists anywhere). rush builds a synthetic job-id table around this
  (`src/bin/rush/src/jobs.rs`).
- moto-rt-cabi / mlibc (`src/sys/lib/moto-rt-cabi/src/lib.rs`):
  `moto_rt_getpid()` truncates to `pid_t` (i32), while `moto_rt_spawn` /
  `moto_rt_waitpid` use *process-local pseudo-pids* starting at `0x4000_0000`
  mapped to u64 handles. A child's own `getpid()` therefore never equals the
  pid its parent holds for it: pidfiles, `kill $(cat foo.pid)`, and any
  pid-reporting protocol are structurally broken in POSIX-land.
- Native tools (`sysbox kill`, mdbg, ps/stats) use the real u64 pid, which no
  POSIX-visible number matches.

Growth cliffs (pids increment per spawn, forever; at 100-1000 spawns/sec a
long-lived VM reaches these): at 2^30 real pids collide with the pseudo-pid
range; at 2^31 the i32 cast goes negative (negative pids have POSIX meaning);
at 2^32 the u32 truncation stops being unique.

## Decision

Bound kernel pids to the i32-positive range and reuse them after wrap,
Linux-style (Option A of the analysis). Rejected alternatives: keep u64
forever and widen `pid_t` to i64 (moves the cliff into every ported app's
`int` assumption; diverges from all mainstream Unixes); dual pid + instance
id (two numbers for every process forever; complexity not currently
justified); document-and-do-nothing (cliffs are reachable, and the
cross-process pseudo-pid inconsistency is broken today).

Invariants after this work:

1. Every pid fits in `i32` (values in `[0, 0x7FFF_FFFF]`); `u32` and `i32`
   views are exact, so `pid_t` and `std::process::id()` hold the real pid.
2. Pids below 4096 are never reused: boot-time system processes (sys-io = 2,
   drivers, services) keep forever-unique pids. `PID_SYSTEM`/`PID_KERNEL`/
   `PID_SYS_IO` constants are unaffected.
3. At any instant a pid maps to at most one process; reuse can begin only
   after the allocator has cycled through ~2^31 spawns.
4. Every layer reports the same number for the same process: kernel, stats,
   mdbg, sysbox, Rust std (`id()`, `Child::id()`), and the C runtime
   (`getpid`, `posix_spawn`, `waitpid`). Pseudo-pids are deleted.

## Design

### 1. Kernel: bounded pid allocation with liveness check

`SYSTEM_STATS.children` (`src/sys/kernel/src/xray/stats.rs`) already holds
every userspace process keyed by `ProcessId` and is pruned on
`KProcessStats::drop`. It becomes the single source of truth for "pid in
use". Allocation moves into `stats::allocate_pid()`:

- Under the `SYSTEM_STATS.children` lock: advance `NEXT_PID`; on reaching
  `PID_MAX = 1 << 31` restart from `FIRST_WRAP_PID = 4096`; skip pids present
  in the map; reserve the chosen pid by inserting a dead `Weak::new()`
  placeholder. `KProcessStats::new_impl` overwrites the placeholder when the
  process registers (asserting a dead placeholder was there). Allocation and
  registration are serialized by the same lock that defines liveness, so no
  duplicate pid can be handed out.
- Placeholders are invisible to existing consumers: `stats_from_pid` and
  `iterate` already skip entries whose `Weak` does not upgrade.
- If a full scan finds no free pid the kernel panics ("pid space exhausted");
  2^31 concurrently live processes cannot exist (each needs orders of
  magnitude more memory than any VM has).
- Behavior before the first wrap is byte-identical to today: sequential pids
  starting at 2, sys-io still gets pid 2.

### 2. Kernel + moto-sys: handle-to-pid query

New `SysRay` flag `F_QUERY_PID` under `OP_QUERY_PROCESS`, mirroring
`F_QUERY_STATUS`: given a *held* process handle, return its pid. No new
ambient authority: the caller must already own the handle. Userspace wrapper
`SysRay::process_pid(handle) -> Result<u64, ErrorCode>`. This is the missing
handle-to-pid mapping rush's jobs.rs laments, and the primitive the spawn
path uses next.

### 3. Runtime ABI: spawn returns the child's pid (no RT_VERSION bump)

`SpawnResult` (moto-rt/src/process.rs) turns its trailing `_reserved: i32`
into `pid: i32` — same size, same field offsets. Invariant 1 (pids fit i32)
is what makes the 4-byte slot sufficient. The vdso vtable and every shared
struct layout stay binary-identical, so `RT_VERSION` stays 16. rt.vdso's
`spawn` fills the slot via `SysRay::process_pid` on the just-created process
handle; `moto_rt::process::spawn` returns the full `SpawnResult` (a
source-level API change only). moto-rt goes 0.16.3 -> 0.16.4 and is
published to crates.io; the rust checkout then updates std against it and
the toolchain is rebuilt.

Motor OS is under development and owes no backward compatibility; the
layout-stable slot is a sequencing convenience, not a compat commitment.
Still, every mixed state is safe, which decouples the two repos: old
binaries on the new vdso ignore the written slot; a new std on an old vdso
reads 0 and `Child::id()` returns 0 exactly as today. In-tree crates use
path deps, and sys-io's runtime moto-rt-version cross-check keeps passing
(16 == 16), so the kernel/vdso/cabi changes land and pass full-test before
the toolchain moves.

One sequencing caveat: std's crates.io requirement resolves within 0.16.x,
so once 0.16.4 is published, rebuilding a rust checkout whose motor.rs still
expects the old tuple-returning `spawn` fails to compile. Land the std
update promptly after publishing.

### 4. Rust std

`Process` stores the pid from `SpawnResult`; `Child::id()` returns it
(nonzero, exact). `getpid()` keeps reading `ProcessStaticPage` but its
truncation caveat becomes a statement of the kernel invariant. No public API
changes; the existing `os::motor` `ChildExt` is untouched.

### 5. moto-rt-cabi: delete pseudo-pids

`SPAWN_TABLE` becomes a map from *real* pid (i32) to process handle;
`PSEUDO_PID_BASE` and `next_pid` are deleted. `moto_rt_spawn` writes the real
pid to `pid_out`; `moto_rt_waitpid` looks it up unchanged. The C ABI is
unchanged (same signatures); only the values become system-consistent, so
mlibc needs no source change. `docs/porting-libc/porting-libc-appendix-h.md`
is updated where it documents the pseudo-pid scheme.

## Accepted risks

- **Post-wrap pid reuse (ABA)** on the advisory pid-keyed surfaces:
  `SysCpu::kill_pid`, `SysRay::dbg_attach`, and the kernel's internal
  `post_kill_by_pid` (parent-death child cleanup posts a kill job by pid).
  A stale pid can name a new process only after the allocator cycles through
  ~2^31 further spawns while the stale reference is held; for the kernel job
  queue that window is microseconds, for human-driven kill/attach it is
  seconds. This is the same race every Unix has, made astronomically harder
  to hit. Native process management (wait/kill by handle) is unaffected.
- **Post-wrap log ambiguity**: a pid in kernel traces is unique per boot only
  until the first wrap (>= 2^31 spawns). Pids < 4096 stay unique forever.
- **The wrap path is not end-to-end testable** (it needs 2^31 spawns). The
  allocator is kept small enough to be audited by review; systest asserts the
  reachable invariants (pid bounds, uniqueness, cross-layer equality). A
  debug-only knob to preset `NEXT_PID` was considered and rejected for now
  (kernel test-only complexity); revisit if the allocator ever grows.

## Out of scope, natural follow-ups

- rush: replace synthetic job ids with real `Child::id()` values.
- mlibc `kill()` of own spawned children (the handle is in the table).
- `getppid()` via `ProcessInfoV1.parent_pid`.
- Relinking out-of-tree mlibc binaries: existing ones keep running unchanged
  (the ABI is stable); they adopt real POSIX pids when relinked against the
  updated moto-rt-cabi in the sysroot.
