# Cold spawn optimization: sys-io loading

Status (2026-10-04): revised design; production implementation has not
started. sys-io constructs the child on the caller's behalf. The parent
keeps its stdio relays.

The goal is to read, allocate, and relocate only the executable pages a
program needs. The earlier prototype measured `rustc --version` at
374.542 ms versus 37.109 ms (10.09x), but did not move the complete loader
into sys-io. This architecture's additional benefit is unmeasured.
There is no numeric acceptance gate. Detailed evidence, experiments,
tuning, and the previous plan are in
[spawn-optimization-prototype.md](spawn-optimization-prototype.md).

## 1. Ownership and API

Applications keep the existing spawn API and moto-rt ABI. rt.vdso sends
one logical spawn request to sys-io; ELF segment descriptions and paging
operations are private to sys-io and the kernel. General-purpose mmap
and new public SysMem mapping/populate operations are not prerequisites.

| Component | Responsibility |
|---|---|
| Parent's rt.vdso | Package launch inputs; retain stdio descriptors, pipe endpoints, relays, terminal behavior, and relay draining for wait completion. |
| sys-io | Authorize and lock the executable; parse ELF; construct the child's address space, vDSO, arguments/environment, and startup data; serve demand faults and relocations. |
| Kernel | Authorize delegated creation; preserve parentage, capabilities, handles, and accounting; own mappings, fault suspension/completion, and teardown. |

The request carries the executable and lookup context, arguments,
environment, requested capabilities/detached mode, and transferable stdio
descriptions. Preserve current PATH, script, and working-directory
semantics. Caller-local pointers, fd numbers, and PIDs are not transferable
authority.

Add a privileged kernel operation for sys-io to create a child for the
authenticated IPC requester. Current `Process::new_child` uses the
calling process as parent; calling it unchanged from sys-io would use the
wrong authority. Check the original requester's spawn, capability, role,
and detached-child permissions, and charge work to the appropriate child
admission class. Return a process handle valid in the parent's handle
table, preserving wait, status, kill, and parent-exit behavior.

**Stdio relays stay in the parent.** sys-io installs the child-side
endpoints; rt.vdso retains the parent-side endpoints and relay tasks.
Keep borrowed descriptors open on success and failure. Finish startup
data, handle handoff, and stdio wiring before waking the child's main
thread. Private setup coordination is part of the spawn request, not a
new application API.

## 2. Loading, paging, and lifetime

- **File lock:** before any ELF read, sys-io authorizes read/execute access
  as the requester and locks the file identity. Reject every mutation with
  `E_NOT_ALLOWED`, including writes through already-open handles,
  truncate, deletion, rename, replacement, and metadata changes. A
  construction reference protects setup; kernel mapping references keep
  the lock afterwards. Multiple children share the exclusion.
- **Checked loading:** sys-io validates headers, arithmetic, segment/file
  bounds, entry point, protections, and supported relocations. Reserve
  sparse `PT_LOAD` ranges with their own offsets and R/RW/RX permissions;
  reject W+X. Preserve all currently supported binaries and scripts. A
  checked eager path in sys-io handles valid layouts outside paging
  support; corruption, authorization, I/O, and OOM errors are reported.
  Malformed ELF must never panic the service.
- **Demand pages:** the kernel parks/coalesces faulting threads and asks
  sys-io for missing pages. Zero each private page, copy its file bytes,
  apply all overlapping relocations, then publish it and resume waiters.
  Handle partial file tails, BSS, and relocations crossing page boundaries.
  Writable/relocated pages are private; complete clean read-only pages
  may share retained cache backing. Each child gets pristine private
  writable vDSO state, never a copy of sys-io's live runtime state.
- **Cleanup:** failed setup or cancellation releases all incomplete state.
  Once committed, the child follows normal parent/detached lifetime rules;
  its pager does not depend on the launcher's IPC connection. Unmap or
  exit revokes access, rejects stale fills, and queues reference release
  without waiting for sys-io. Only release the file lock after every
  construction/mapping reference, pending cleanup, and backing/I/O user
  is gone, including when a debugger retains a process handle.

Bound service work and retained memory using existing admission and
channel budgets. Keep pager dependencies resident, hold no kernel lock
across I/O, and safely prepare missing syscall-buffer pages before side
effects. Construction failures return errors; fatal demand failures
terminate the affected child and release its waiters, without panicking
sys-io or blocking unrelated clients.

## 3. Implementation sequence

Implement in reviewable 100–300-line patches, with tests alongside each
change. No implementation changes or commits during this planning task.

1. **Baseline and contract:** record the current build and cold timings;
   specify authenticated delegation, handle/stdio handoff, completion,
   cancellation, and resource charges. The filesystem sync fix is already
   in `14733ed8`; do not reapply the prototype's hunk.
2. **Delegate an eager spawn:** move checked executable loading and child
   construction to sys-io, with the executable locked throughout setup.
   Preserve the application ABI and parent relays. Keep the kernel's
   bootstrap loader of sys-io eager. Ensure
   sys-io can launch sys-init without recursive spawn-handler calls or
   additional boot-time preparation.
3. **Demand loading:** extend executable locks with kernel mapping
   references; add sparse reservations, private fault/reference queues,
   copied-page fills, and asynchronous cleanup.
   Initially prepare relocated writable pages eagerly as a correctness
   reference; demand-load read-only segments.
4. **Lazy relocation:** validate/index relocations and initialize only
   touched writable pages. Retain the approved runtime handoff in
   **`../toolchain-src/mlibc`**, outside this repository: remove redundant
   executable relocation walks and relink the developer-image tools.
   Existing binaries remain correct but may start more slowly. Rust std
   and moto-rt require no changes.
5. **Share and measure:** retain clean cache pages and sparse resident
   vDSO backing; measure the complete spawn path. Consider bounded
   read-ahead and other archived tuning only where new measurements
   justify it. No learned profiles, executable-specific hints, or added
   boot-time work.

Before dependent implementation, review the exact private handoff,
relocation validation/indexing and mlibc form, resource limits, and safe
syscall-buffer fault preparation. The archive's
[architecture notes](spawn-optimization-prototype.md#9-architecture-revision-2026-10-04)
explain these points and which historical questions are superseded.

## 4. Validation

Add hermetic `cold_spawn` coverage to the default systest suite reached
by `src/tests/full-test.sh`. Cover:

- Delegated parent identity and capability denial; caller-valid handles;
  wait/kill, detached children, parent exit, and cancellation during setup.
- Null, inherited, piped, file, and terminal stdio; borrowed descriptors,
  output draining, startup ordering, and failure cleanup.
- ELF errors, scripts, arguments/environment/cwd, constructors, BSS,
  relocation boundaries, sibling isolation, and eager/paged equivalence.
- Every denied file mutation, concurrent launches, both construction and
  mapping reference release, exit with pages absent, and eventual unlock.
- Concurrent faults, stale fills, cache retention, OOM/I/O errors, syscall
  buffer faults, repeated teardown, and ordinary I/O during spawning.

Follow [AGENTS.md](../../AGENTS.md): standard Rust/native APIs, repository
formatting, no new warnings, and at least three debug plus three release
full-test build/runs before committing core patches. The developer-image
gate is `src/tests/full-test-dev.sh --release`. No commits unless asked.

Use 50 alternating baseline/candidate pairs of the normal rustc wrapper,
one invocation per fresh VM, plus 10 pairs each for Clang and Rush.
Measure spawn through exit and output draining; require exact stdout,
empty stderr, and success. Run the same relinked target binaries on both
OS builds, preserve failures, and record hashes, host-cache conditions,
memory, CPU, and boot behavior. Investigate regressions. The archive's
[measurement method](spawn-optimization-prototype.md#2-measurement-method)
and Appendix D retain the detailed procedure and reporting requirements.
