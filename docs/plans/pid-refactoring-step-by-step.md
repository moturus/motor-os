# PID refactoring: step-by-step plan

2026-07-29. Execution order and status ledger for
`docs/plans/pid-refactoring-design.md`. Read that document first; where the
two conflict, the design document wins on intent and this document wins on
sequencing. Update the status section after every step.

## Current status

Overall state: **in progress**.

Current step: fixing two preexisting full-test flakes before Step 3.

- Step 1 (kernel: bounded pid allocation with reuse): **done** (commit
  "kernel: bounded pid allocation with reuse"). Gate: full-test 3x debug
  + 3x release, all pass, no flakes.
- Step 2 (kernel + moto-sys: F_QUERY_PID): **done** (commit "kernel,
  moto-sys: handle-to-pid query"). Gate: 1x debug + 3x release clean;
  2 debug runs lost to preexisting flakes unrelated to pids, both
  diagnosed and to be fixed next (see below). `test_process_pid_query`
  passed in every run that reached the VM.

Preexisting flakes found while gating Step 2, to fix before Step 3:

1. `udp_rebind_after_close_test` (`systest/src/udp.rs`): the documented
   cross-channel close/rebind race; `bind` after `close` returns
   `AlreadyInUse` (seen at iterations 1457 and ~1400, debug only so far).
2. `a_line_that_shrinks_off_a_row_takes_the_row_with_it`
   (`src/bin/rush/tests/phase8.rs`): host-side pty test; a fixed
   `sleep(150ms)` waits for rush's first prompt, and under host load the
   keystrokes land before the prompt is painted, shifting the whole
   expected screen left by the two columns of `"$ "`. Test-side bug.

## Ground rules

- Follow `AGENTS.md`. In particular: stop and ask on any non-obvious decision
  or any preexisting bug found along the way; no retries/timeouts/workarounds
  to mask failures; no new compiler or clippy warnings; format motor-os
  changes with `cargo +nightly fmt`.
- One step = one commit (each is well under 300 loc including tests). Before
  each commit, `src/tests/full-test.sh` must pass 3x as debug and 3x as
  release. Do not commit without explicit user approval if the session's
  workflow is unclear.
- Two repos are involved: `motor-os` (this repo) and the rust checkout at
  `../rust` (i.e. `/home/posk/motor-dev/rust`, toolchain
  `dev-x86_64-unknown-motor`). Only Step 5 touches the rust checkout.
- `RT_VERSION` stays 16 throughout. Do not touch it in `moto-rt/src/lib.rs`
  or `rt.vdso/src/main.rs`; the whole design avoids the bump by reusing the
  layout-compatible `_reserved` slot (design doc, section 3).
- Build commands: `make -j$(nproc)` (debug), `make -j$(nproc) BUILD=release`.
  Tests: `src/tests/full-test.sh` and `src/tests/full-test.sh --release`.

## Step 1 — kernel: bounded pid allocation with reuse

Goal: pids stay in `[2, 2^31)` forever; allocation skips live pids after
wrap; pids below 4096 are never reused. No ABI or behavior change before the
first wrap (sys-io must still get pid 2).

Files: `src/sys/kernel/src/xray/stats.rs`,
`src/sys/kernel/src/uspace/process.rs`,
`src/sys/tests/systest/src/spawn_wait_kill.rs`.

1. In `stats.rs`, add near the top-level statics (`SYSTEM_STATS` etc.):

   ```rust
   /// Pids fit i32 by design: see docs/plans/pid-refactoring-design.md.
   pub const PID_MAX: u64 = 1 << 31;
   /// Post-wrap allocation restarts here; boot-time pids are never reused.
   const FIRST_WRAP_PID: u64 = 4096;
   // Only read/written under the SYSTEM_STATS.children lock.
   static NEXT_PID: AtomicU64 = AtomicU64::new(PID_KERNEL + 1);

   pub fn allocate_pid() -> ProcessId {
       let mut children = SYSTEM_STATS.children.lock(line!());
       for _ in 0..=PID_MAX {
           let candidate = NEXT_PID.load(Ordering::Relaxed);
           if candidate >= PID_MAX {
               NEXT_PID.store(FIRST_WRAP_PID, Ordering::Relaxed);
               continue;
           }
           NEXT_PID.store(candidate + 1, Ordering::Relaxed);
           let pid = ProcessId::from_u64(candidate);
           if let alloc::collections::btree_map::Entry::Vacant(entry) =
               children.entry(pid)
           {
               // Reserve the pid; KProcessStats::new_impl replaces this
               // placeholder under the same lock discipline.
               entry.insert(Weak::new());
               return pid;
           }
       }
       // 2^31 concurrently live processes cannot exist (memory alone
       // forbids it), so a full scan without a vacancy is a kernel bug.
       panic!("pid space exhausted");
   }
   ```

   `PID_KERNEL` is already imported in stats.rs. Check the existing imports
   for `AtomicU64`/`Ordering`/`Weak` and add what is missing.

2. In `stats.rs`, `KProcessStats::new_impl`, the userspace branch currently
   asserts a fresh insert:

   ```rust
   assert!(SYSTEM_STATS.children.lock(line!())
       .insert(self_.pid, Arc::downgrade(&self_)).is_none());
   ```

   Replace the assert so it consumes the placeholder instead:

   ```rust
   let prev = SYSTEM_STATS
       .children
       .lock(line!())
       .insert(self_.pid, Arc::downgrade(&self_));
   // allocate_pid() reserved this slot with a dead placeholder.
   assert!(prev.is_some_and(|w| w.upgrade().is_none()));
   ```

   Do NOT change the `parent.children` insert above it (parents get no
   placeholder) and do NOT change `KProcessStats::drop` (the placeholder is
   gone by then — it was overwritten by the real entry).

3. In `process.rs`, delete `ProcessId::new()` (the `NEXT_ID` static moves to
   stats.rs conceptually) and change its single call site in `Process::new`
   from `ProcessId::new()` to `crate::xray::stats::allocate_pid()`. Keep
   `from_u64`/`as_u64` and the `KERNEL_PID`/`SYS_IO_PID` constants untouched.

4. Fixed-pid callers sanity check (read-only): `KProcessStats::new_impl` is
   also called from `stats::init()` with pids 0 and 1; both skip the
   `SYSTEM_STATS.children` insert (pid 0 via the `parent: None` branch,
   pid 1 via the `pid > PID_KERNEL` gate), so they never see a placeholder.
   Confirm this is still true after your edit; if it is not, stop and ask.

5. systest: in `spawn_wait_kill.rs` add a small `test_pid_invariants()`
   (wire it into that file's existing `test()`/entry function the same way
   its current tests are wired, so full-test picks it up transitively):
   - `assert!(moto_sys::current_pid() >= 3)` (systest is not sys-io),
   - `assert!(moto_sys::current_pid() < (1u64 << 31))`,
   - `assert_eq!(std::process::id() as u64, moto_sys::current_pid())`.
   Check `systest`'s Cargo.toml already depends on `moto-sys` (other systest
   files use it); add the dependency only if missing.

Verify: `make -j$(nproc)` (and release), clippy clean, full-test 3x+3x.
Expected size: ~80 loc.

## Step 2 — kernel + moto-sys: handle-to-pid query syscall

Goal: a process holding a process handle (e.g. a spawner) can ask the kernel
for that process's pid. Mirrors the existing `F_QUERY_STATUS` plumbing.

Files: `src/sys/lib/moto-sys/src/sys_ray.rs`,
`src/sys/kernel/src/uspace/sys_ray.rs`,
`src/sys/tests/systest/src/spawn_wait_kill.rs` (or a sibling),
`src/sys/tests/systest/src/main.rs` (subcommand dispatch only, if needed).

1. moto-sys `sys_ray.rs`: next to `F_QUERY_LIST_CHILDREN: u32 = 3`, add
   `pub const F_QUERY_PID: u32 = 4;`. Below `process_status`, add:

   ```rust
   /// Returns the pid of the process behind a held process handle.
   #[cfg(feature = "userspace")]
   pub fn process_pid(handle: SysHandle) -> Result<u64, ErrorCode> {
       let result = do_syscall(
           pack_nr_ver(SYS_RAY, Self::OP_QUERY_PROCESS, Self::F_QUERY_PID, 0),
           handle.as_u64(),
           0, 0, 0, 0, 0,
       );
       if result.is_ok() {
           Ok(result.data[0])
       } else {
           Err(result.error_code())
       }
   }
   ```

2. Kernel `sys_ray.rs`: add a handler modeled on
   `sys_query_process_status` (same file, top):

   ```rust
   fn sys_query_process_pid(
       thread: &super::process::Thread,
       args: &SyscallArgs,
   ) -> SyscallResult {
       if args.version > 0 {
           return ResultBuilder::version_too_high();
       }
       match super::sysobject::object_from_handle::<super::process::Process>(
           &thread.owner(),
           SysHandle::from_u64(args.args[0]),
       ) {
           Some(proc) => ResultBuilder::ok_1(proc.pid().as_u64()),
           None => ResultBuilder::result(moto_rt::E_INVALID_ARGUMENT),
       }
   }
   ```

   In `sys_ray_impl`'s `OP_QUERY_PROCESS` match arm, route
   `SysRay::F_QUERY_PID => sys_query_process_pid(thread, args)`.

3. systest: add `test_process_pid_query()`:
   - Spawn a child subcommand of systest itself that prints
     `moto_sys::current_pid()` to stdout and exits (follow the existing
     child-subcommand pattern, e.g. `io_channel.rs` `SPAWN_READ_CHILD` and
     its `is_...` dispatch from `main.rs`).
   - Parent: get the raw handle via
     `std::os::motor::process::ChildExt::sys_handle(&child)` (this needs
     `#![feature(motor_ext)]` on the systest crate root if not already
     present), call `moto_sys::SysRay::process_pid(handle.into())` **before**
     waiting, capture the child's stdout, then assert the queried pid equals
     the pid the child printed, and is `>= 3` and `< 2^31`.
   - Also assert `process_pid(SysHandle::SELF)` either returns this
     process's pid or a clean error — try it, observe which, and assert the
     actual behavior with a comment (SELF resolves to the caller's own
     process object; if it errors, that is acceptable, just pin it).

Verify: builds, clippy, full-test 3x+3x. Expected size: ~100 loc.

## Step 3 — moto-rt + rt.vdso: SpawnResult carries the pid (motor-os only)

Goal: the runtime hands the spawner the child's pid. No toolchain or rust
checkout involvement: `SpawnResult`'s trailing `_reserved: i32` becomes
`pid: i32` — same size, same offsets — so the vtable ABI is unchanged and
the prebuilt std (moto-rt 0.16.3) keeps working, merely ignoring the slot.

Files: `src/sys/lib/moto-rt/Cargo.toml`,
`src/sys/lib/moto-rt/src/process.rs`,
`src/sys/lib/rt.vdso/src/rt_process.rs`,
`src/sys/lib/moto-rt-cabi/src/lib.rs`,
`src/sys/tests/systest/src/spawn_wait_kill.rs`,
`src/sys/tests/systest/Cargo.toml` (dependency only, if needed).

1. moto-rt `process.rs`: in `SpawnResult`, replace `pub _reserved: i32` with
   `pub pid: i32` (same position, last field; the `Default` derive still
   zeroes it). Add a one-line comment: pids fit i32 by kernel invariant
   (design doc). Confirm with a `const _: () = assert!(...)` that
   `size_of::<SpawnResult>()` is unchanged (take the current size from the
   compiler by asserting the old value, 24; if the actual size differs, stop
   and ask — the layout-compatibility premise would be wrong).
2. moto-rt `process.rs`: change `pub fn spawn` to return
   `Result<SpawnResult>` instead of the `(u64, RtFd, RtFd, RtFd)` tuple —
   return the vdso-filled struct unmodified. moto-rt `Cargo.toml`: version
   `0.16.3` -> `0.16.4`. Do NOT touch `RT_VERSION`.
3. rt.vdso `rt_process.rs`, in `spawn_impl`, just before
   `result_rt.handle = process.take().as_u64();`:

   ```rust
   let pid = moto_sys::SysRay::process_pid(process.syshandle())
       .expect("pid query on a held process handle");
   result_rt.pid = i32::try_from(pid).expect("pid fits i32");
   ```

4. moto-rt-cabi: mechanical fix-up only — `moto_rt_spawn` destructures the
   new `SpawnResult` (`res.handle`, `res.stdin`, ...) and keeps the
   pseudo-pid table exactly as is (Step 4 replaces it).
5. systest `test_spawn_result_pid()` — exercises the new plumbing through
   the in-tree moto-rt (path dep; add `moto-rt` to systest's Cargo.toml if
   absent, matching how sibling in-tree crates declare it):
   - Child subcommand that does
     `std::process::exit(moto_sys::current_pid() as i32)` (exact: pids fit
     i32).
   - Parent: call `moto_rt::process::spawn` directly on
     `std::env::current_exe()` with that subcommand argument and
     `STDIO_INHERIT` stdio; assert `res.pid > 0` and `(res.pid as u64) ==
     SysRay::process_pid(res.handle.into())`; then
     `moto_rt::process::wait(res.handle)` and assert the exit status equals
     `res.pid`; finally `moto_rt::alloc::release_handle(res.handle)`.
   - Note: `Child::id()` still returns 0 in this step (prebuilt std) — do
     not assert on it yet; that lands in Step 5.

Verify: builds, clippy, full-test 3x+3x (runs against the *existing*
toolchain — that is the point). Expected size: ~110 loc.

## Step 4 — moto-rt-cabi: delete pseudo-pids; docs

Goal: POSIX-land pids are the real pids. C ABI signatures unchanged.

Files: `src/sys/lib/moto-rt-cabi/src/lib.rs`,
`docs/porting-libc/porting-libc-appendix-h.md`.

1. In `lib.rs`, the process spawn/wait section:
   - Delete `PSEUDO_PID_BASE` and the `next_pid` field; `SpawnTable` keeps
     only `children: BTreeMap<i32, u64>` (real pid -> process handle).
   - `moto_rt_spawn`: after a successful spawn, `assert!(res.pid > 0);`
     then insert `(res.pid, res.handle)` and write `res.pid` to `pid_out`.
   - `moto_rt_waitpid`: logic unchanged (lookup by the passed pid, wait by
     handle, remove on success).
   - Rewrite the section header comment: the table now exists only because
     Motor identifies children by handle while POSIX wait takes a pid; the
     pids in it are real and system-wide meaningful.
2. Update `docs/porting-libc/porting-libc-appendix-h.md` where it documents
   pseudo-pids and "Motor pids are small" truncation (the `GetPid` and
   `Kill` sysdep rows and any M9b spawn/waitpid text): pids are now
   guaranteed to fit `pid_t`, `posix_spawn`/`waitpid` use real pids, and a
   child's `getpid()` matches what the parent holds. Do not restructure the
   document; edit the affected statements only.
3. mlibc itself needs no change (same C ABI), and existing mlibc-linked
   binaries keep running (ABI-stable slot); they adopt real POSIX pids when
   relinked. If the mlibc test flow from the porting docs is set up on this
   machine, smoke-test a C program that spawns a child and compares
   `getpid()`-reported values; otherwise state in the commit message that
   C-side behavior relies on the out-of-tree mlibc suite.

Verify: builds, clippy, full-test 3x+3x. Expected size: ~60 loc.

## Step 5 — publish 0.16.4; rust checkout: real Child::id()

Goal: Rust std learns the pid from `SpawnResult`; `Child::id()` returns it.

Files (rust checkout): `library/std/Cargo.toml`, root `Cargo.toml`
(comment only), `library/std/src/sys/process/motor.rs`.
Files (motor-os): `src/sys/tests/systest/src/spawn_wait_kill.rs`.

1. **Owner action — stop and ask**: publish moto-rt 0.16.4 to crates.io
   from `src/sys/lib/moto-rt` (Steps 3-4 must be committed first). Do not
   proceed until the publish is confirmed. (For local iteration before the
   publish, a temporary `[patch.crates-io]`
   `moto-rt = { path = "../motor-os/src/sys/lib/moto-rt" }` in the rust
   root Cargo.toml works, but it must be removed before this step is called
   done; prefer simply waiting for the publish.)
2. Rust checkout:
   - `library/std/Cargo.toml`: tighten to
     `moto-rt = { version = "0.16.4", ... }` (keep features) so the new
     `spawn` API is guaranteed at resolution time.
   - Root `Cargo.toml`: update the comment that says moto-rt ">= 0.16.1"
     needs no patch (now ">= 0.16.4, which returns the child's pid from
     spawn").
   - `motor.rs`: `struct Process` gains `pid: u32`; `spawn()` destructures
     the `SpawnResult` (`result.handle`, `result.pid as u32`,
     `result.stdin`, ...); `Process::id()` returns `self.pid` with a
     one-line comment that the kernel guarantees pids fit i32 (reference
     the design doc by name). Update the stale comment in `getpid()`: the
     `as u32` cast is now exact by kernel invariant, not a truncation.
   - Format per the rust repo's tooling (`./x fmt` or rustfmt on the file).
3. Rebuild the toolchain (from `/home/posk/motor-dev/rust`):
   `./x.py build --stage 2 clippy library src/tools/remote-test-server`
   (the command from `docs/build.md`; the `dev-x86_64-unknown-motor` rustup
   link points at the stage2 dir, so no re-linking is needed). If vendoring
   rejects the new crate version, stop and consult `docs/build-rustc.md`.
4. motor-os systest: add `test_child_id()` next to the Step-2 test:
   - `child.id()` is nonzero, `< 2^31`, equals the pid the child printed
     (have the child print both `std::process::id()` and
     `moto_sys::current_pid()`), and equals
     `SysRay::process_pid(sys_handle)`.
   - Spawn two children; assert their ids differ.
5. Rebuild motor-os (debug + release), full-test 3x+3x. Commit the systest
   change here; commit the rust checkout separately in its repo.

Expected size: rust checkout ~40 loc, motor-os ~60 loc.

## Step 6 — wrap-up

1. Re-read both plan documents; update statements this work made stale, and
   record final status in this file (which full-test runs, counts, any
   flakes with root causes).
2. Leave the listed follow-ups (rush job ids, mlibc `kill()` of children,
   `getppid`, out-of-tree mlibc relinks) untouched unless separately
   requested.

## Known traps for the executor

- Do not use `pkill -f`/`grep -c` on your own command patterns when driving
  the VM harness (they match the tool's own command line); kill by pid and
  bracket the first character of patterns.
- `full-test.sh` needs host NAT for the VM's external DNS on this rig after
  a host reboot (`ip_forward=1` + MASQUERADE); see the memory notes if DNS
  tests fail with all else healthy.
- If a VM under test hangs, use `/sys/mdbg print-stacks <pid>` plus
  addr2line on the unstripped `build/obj` binaries before assuming a flake.
- Binaries link two moto-rt copies (std's crates.io copy and the in-tree
  path copy); that is the existing, intended state — sys-io's runtime
  version cross-check guards it and keeps passing at 16 == 16. Do not
  "deduplicate" it as part of this work.
