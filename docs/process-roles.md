# Process Roles — System / Interactive / None

Status: **implemented**. Companion to
`src/sys/lib/motor-fs/PERMISSIONS_DESIGN.md`, which defines the FS-side
consumer of the three roles and deliberately leaves their *origin*
unspecified ("a trusted input supplied from above the FS").
Audience: an engineer maintaining or extending this feature.

This document describes how the kernel, `moto-sys`, `rt.vdso`, and sys-io
represent and consume three process privilege roles, how a role is assigned at
spawn, and how it is queried by the process itself and by a connected server.
It also describes the exec-time `x`-permission check deliberately left to a
consumer above motor-fs by `PERMISSIONS_DESIGN.md`. Section 1 records the
motivation, and §2 records the pre-implementation constraints. Code references
include current line numbers, which may drift — treat the named items as the
stable anchors.

---

## 1. Problem

Motor FS permissions are per-role: `async_fs::Role { None = 0, Interactive = 1,
System = 2 }` (`src/sys/lib/async-fs/src/filesystem.rs:52`), with one
permission byte per role persisted in every entry's `Metadata`. Before this
design, the OS itself distinguished only two classes of process: "system"
(`CAP_SYS` set) and everything else. The consequences were:

- sys-io passed `Role::System` unconditionally at **every role-taking** FS call
  site
  (`src/sys/sys-io/src/runtime/fs.rs:620–1165`, `util.rs`, `net/config.rs`),
  so the Interactive and None permission bytes are stored and cascaded but
  never consulted.
- `sysbox ps` could only render a binary `*` marker from the
  `ProcessInfoV1.system_process` byte. This design replaced that byte with a
  three-valued `process_role` byte (§4.2).
- There was no kernel notion of "logged-in user authority" vs "least
  privilege"; the interactive session is an informal capability bundle
  (`CAP_SPAWN | CAP_LOG | CAP_SPAWN_DETACHED`) re-spelled ad hoc by sys-tty,
  russhd, and rush.
- File `x` was persisted and reported but never enforced. `rt.vdso`'s
  ELF/script loader opened and read a program without checking
  `FileAttr.perm & PERM_EXEC`.

Required properties of the design:

1. **Unforgeable** — a process cannot claim a role; only its parent (bounded by
   the kernel) assigns it, and only the kernel reports it.
2. **Monotone under spawn** — below System, a child's role can never exceed its
   parent's.
3. **Cheap to query** — by the process itself (no syscall) and by a server
   about a connected peer (one syscall on the connection handle).
4. **Connection-bound** — sys-io obtains the role from the kernel-owned peer of
   the actual FS connection, never from a client-supplied field or pid scan.
5. **Session provenance** — an ordinary System service must not create an
   Interactive child merely by using the default spawn path. Interactive is an
   explicit session grant, not the generic downgrade target for System.
6. **Complete FS semantics** — role-aware `r`/`w`/directory-`x` enforcement in
   sys-io is paired with file-`x` enforcement in the program loader (the
   latter cooperative, not a security boundary — §5.3).
7. **No compatibility machinery** — new code ships only as part of a complete
   new image (kernel, userspace, and FS image built and deployed together);
   new code never runs against old images. The design therefore needs no
   migration logic or format/ABI versioning.

---

## 2. Pre-implementation state (facts the design builds on)

- Privilege is a single immutable `u64` capability word per process:
  `Process::capabilities` (`kernel/src/uspace/process.rs:149`), set once at
  creation (`process.rs:237`), mirrored into the read-only, user-mapped
  `ProcessStaticPage { version, pid, capabilities, active_threads }`
  (`process.rs:267–269`; `moto-sys/src/shared_mem.rs:67–95`), copied per-thread
  at thread start (`process.rs:1452–1454`). Nothing ever stores to it
  afterward: **caps are immutable for a process's lifetime.**
- Defined bits (`moto-sys/src/caps.rs`): `CAP_SYS = 1<<0`,
  `CAP_IO_MANAGER = 1<<1`, `CAP_SPAWN = 1<<2`, `CAP_LOG = 1<<3`,
  `CAP_SHUTDOWN = 1<<4`, `CAP_SPAWN_DETACHED = 1<<5`. Bits 6..63 are free.
- Before this design, rt.vdso's spawn path built a URL
  `process:entry_point=..;capabilities=<caps>;detached=..` and called
  `SysObj::create` (`rt.vdso/src/rt_process.rs:637–679`). The default grant was
  `CAP_SPAWN | CAP_LOG`; a `MOTOR_OS_CAPS` env var (hex) replaced the default
  outright and was stripped from the child's env. **There was no inheritance**
  — an unadorned spawn always yielded `CAP_SPAWN | CAP_LOG` regardless of the
  parent. Consequently a non-System parent that had `CAP_SPAWN` but not
  `CAP_LOG` asked for a non-subset default and its unadorned spawn was rejected
  by the kernel.
- Kernel escalation gate (`kernel/src/uspace/process.rs:310–320`): a `CAP_SYS`
  parent may grant anything; a non-`CAP_SYS` parent may grant only a **subset
  of its own caps** and never `CAP_SYS`/`CAP_IO_MANAGER`.
- `ProcessInfoV1.system_process` was a derived view of `CAP_SYS`, computed in
  exactly one place (`kernel/src/xray/stats.rs:579–584`).
- Self-query: `ProcessStaticPage::get().capabilities` (zero syscalls). A URL
  query also returned self caps, but `SysObj::get(h, 0, "capabilities")` was
  **unimplemented for non-`SELF` handles**
  (`kernel/src/uspace/sys_obj.rs:184–192`). `OP_QUERY_HANDLE/F_QUERY_PID`
  already resolves the process owning the sibling endpoint of a shared object;
  this is the correct peer-query precedent.
- Initial grant topology: the kernel gave sys-io all-ones caps; sys-io did the
  same for sys-init, and sys-init did the same for sys-tty. The console shell
  got `CAP_SPAWN|CAP_LOG|CAP_SPAWN_DETACHED`
  (`sys-tty/src/main.rs:94–101`). Both shipped sys-init configs used decimal
  masks and gave russhd `60`, while the main image gave dns-resolver `8` and
  sys-init gave strobe `CAP_LOG`. Ordinary commands got the vdso default. The
  design makes sys-tty, russhd, and their shells Interactive (§7).
- `sys-init::spawn_service` set `MOTOR_OS_CAPS` only when the parsed mask was
  nonzero. Thus an explicit `svc:0:...` received the vdso default
  (`CAP_SPAWN|CAP_LOG`) rather than zero caps, despite the logged/configured
  value. No shipped service used zero at the time, but this was a policy
  bug in the role-assignment path.
- Explicit replacement masks existed beyond those entry points. In particular,
  rush's trusted detached-spawn path constructed `CAP_SPAWN|CAP_LOG|
  CAP_SPAWN_DETACHED`, and the focused lifetime test in `full-test.sh` used
  `MOTOR_OS_CAPS=0x2c`. Every such mask needed an explicit role choice; the
  vdso default could not repair an explicit mask.

---

## 3. Design: the role is *derived* from the capability word

**One new capability bit; no new kernel state.** The role is a pure function
of the existing caps word.

```rust
// moto-sys/src/caps.rs

/// Interactive ("user") process: acts with the authority of the logged-in
/// user. See docs/process-roles.md. CAP_SYS takes precedence for role
/// derivation when both bits are present; CAP_SYS does not imply this bit.
pub const CAP_INTERACTIVE: u64 = 1 << 6;

/// Process privilege role: System > Interactive > None.
/// Discriminants deliberately equal `async_fs::Role`'s (which are persisted
/// on disk as the per-role permissions index) and the process-stats encoding.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ProcessRole {
    None = 0,
    Interactive = 1,
    System = 2,
}

impl ProcessRole {
    /// The single derivation rule. Highest applicable wins.
    pub const fn from_caps(caps: u64) -> ProcessRole {
        if caps & CAP_SYS != 0 {
            ProcessRole::System
        } else if caps & CAP_INTERACTIVE != 0 {
            ProcessRole::Interactive
        } else {
            ProcessRole::None
        }
    }
}
```

Role semantics:

| Role | Definition | Meaning | Typical holders |
|------|------------|---------|-----------------|
| `System` | `CAP_SYS` set | root-like; unkillable from userspace; unrestricted grant authority at spawn | kernel-spawned sys-io; sys-init; strobe |
| `Interactive` | no `CAP_SYS`, `CAP_INTERACTIVE` set | the logged-in user's authority | sys-tty; russhd; console/ssh shells; commands they run; user daemons (including detached ones) |
| `None` | neither bit | least privilege | dns-resolver, other services, deliberately sandboxed children |

### Why derived rather than stored

A separate "privilege level" field would be a second axis of truth alongside
caps: new kernel state, a new spawn-URL parameter, a new inheritance rule, new
query plumbing, and a consistency invariant between the two axes
(`privilege == System` ⇔ `CAP_SYS`?). Deriving from the caps word gets all of
that for free:

- **Immutability** — caps are already immutable per process.
- **Monotonicity** — for non-`CAP_SYS` parents the kernel already enforces
  `child_caps ⊆ parent_caps`, and `from_caps` is monotone under `⊆`:
  a subset can only produce an equal-or-lower role. An Interactive parent can
  mint Interactive or None children; a None parent only None children. A
  `CAP_SYS` parent is unrestricted (root-like) — unchanged, and intended.
- **Self-query** — `ProcessStaticPage.capabilities` already exposes it with
  zero syscalls; `ProcessRole::from_caps(ProcessStaticPage::get().capabilities)`.
- **Spawn ABI** — the `capabilities=` URL parameter already carries it.
- **Sandboxing falls out** — a shell that spawns an untrusted binary with an
  explicit `MOTOR_OS_CAPS` that omits `CAP_INTERACTIVE` demotes it to None; no
  new mechanism.

`CAP_SYS && !CAP_INTERACTIVE` and `CAP_SYS && CAP_INTERACTIVE` are both legal;
both derive to System and creation does not normalize the word. This matters
because the existing all-ones grants contain every future bit. Default spawn
inheritance must compare the *derived role*, not merely test whether the raw
interactive bit happens to be present (§5.1).

### Naming

`Interactive` is chosen to match the already-implemented, on-disk-documented
`async_fs::Role::Interactive` — one concept, one name. ("User" was the
alternative; a rename of the FS enum was rejected as churn against an
implemented design.)

### Two enums, same discriminants — deliberately

`async-fs` must keep building on the host (the imager links motor-fs/async-fs
natively) and therefore cannot depend on `moto-sys`. So
`moto_sys::caps::ProcessRole` and `async_fs::Role` remain distinct types with
identical discriminants. Convert with an exhaustive three-arm match rather than
an integer cast; a `const` assert in sys-io still pins the intentional wire/disk
mapping:

```rust
const _: () = {
    assert!(ProcessRole::None as u8 == async_fs::Role::None as u8);
    assert!(ProcessRole::Interactive as u8 == async_fs::Role::Interactive as u8);
    assert!(ProcessRole::System as u8 == async_fs::Role::System as u8);
};
```

---

## 4. Kernel implementation

### 4.1 Spawn gate: no change required

`Process::new_child` (`process.rs:294–362`) already implements exactly the
needed rule (§3). The comment at the subset check references this document so
the invariant is discoverable. The `CAP_SPAWN` documentation also reflects
that `sys_handle_create` checks it before creating an address space
(`kernel/src/uspace/sys_obj.rs:35–41`).

The unrestricted `CAP_SYS` branch is intentional: a System parent may
explicitly mint any role. The safer *default* for a System parent is addressed
in rt.vdso (§5.1), not by weakening this kernel authority.

### 4.2 Stats role encoding

`ProcessInfoV1` uses `process_role: u8` in the former
`system_process: u8` slot. There is no second compatibility flag: it would be
a redundant view of the same immutable capability word.

```rust
pub struct ProcessInfoV1 {
    pub pid: u64,
    pub parent_pid: u64,
    pub debug_name_bytes: [u8; MAX_DEBUG_NAME_BYTES],
    pub debug_name_len: u8,
    pub active: u8,      // 0 => zombie; 1 => active.
    pub process_role: u8, // ProcessRole as u8; see no-owner behavior below.
}
```

The field stays at the same offset and the struct remains 51 used bytes padded
to 56, so **no other field offset and no `size_of` change** — the kernel's
`size_of::<ProcessInfoV1>()` memcpy (`kernel/src/uspace/sys_ray.rs:83–87`)
is unaffected. The byte values are exactly the `ProcessRole` discriminants:
None = 0, Interactive = 1, System = 2. No `OP_QUERY_PROCESS` version bump or
parallel `ProcessInfoV2` is needed under this work's explicit no-compatibility
rule. A `size_of::<ProcessInfoV1>() == 56` const assertion pins the layout. The
field remains a raw `u8`; enum-invalid bytes must never be
materialized as a Rust enum, and consumers decode through a small
`ProcessRole::try_from`/`from_u8` helper.

Fill site — `KProcessStats::into_v1` (`kernel/src/xray/stats.rs:575–605`):

```rust
dest.process_role = ProcessRole::None as u8;
if let Some(proc) = self.owner.upgrade() {
    dest.process_role = ProcessRole::from_caps(proc.capabilities()) as u8;
}
```

Before the rename, `sysbox ps` was the only in-tree reader of `system_process`;
it now decodes `process_role`. The other `ProcessInfoV1` consumers needed no
source changes. `KProcessStats` holds only a weak process owner. Therefore
zombies, the `(total)` aggregate, and the kernel pseudo-process have no live
owner and report `process_role == None`; this field is observational only and
must never authorize access. Live peer authorization uses §4.3 instead.

### 4.3 Peer capability query

Servers need the caps of the process at the other end of an IPC connection.
The implementation extends the handle-query mechanism used for peer pid
lookup. It has two touchpoints and one rule:

- Kernel: in `OP_QUERY_HANDLE` (`kernel/src/uspace/sys_obj.rs:284–339`, where
  `F_QUERY_PID` lives), `F_QUERY_CAPS` resolves the peer owner of a shared
  object the caller owns (`shared::peer_owner`, same as `get_pid`) and returns
  `proc.capabilities()` in result slot 0. It does not extend the old
  `SysObj::get(..., "capabilities")` URL: it encodes an integer as a
  `SysHandle`, whereas `OP_QUERY_HANDLE` is already the typed precedent.
- moto-sys: `SysObj::get_capabilities(handle: SysHandle) -> Result<u64,
  ErrorCode>` sits next to `SysObj::get_pid`
  (`moto-sys/src/sys_obj.rs:225–241`). Both return information about the owner
  of the *peer/sibling endpoint*, not the owner of the caller's local handle.

Authorization: identical to `get_pid` — the caller must already own the
local handle and it must resolve to a live shared-object peer; there is no
pid-based ambient query. Capability bits are authority labels, not credentials
or secret material, and the result is limited to a process already connected
to the caller. A torn-down sibling normally returns `E_BAD_HANDLE`; a handle
that is live but has no resolvable shared peer returns an error as well. Per the
`check_same_process` precedent (`sys-io/src/runtime/net/tcp_listener.rs:482–521`),
callers must **fail closed** on error, never assume a role.

Why not pid → `ProcessInfoV1::list`? It works (sys-io already does the pid
half for logging) but is an O(processes) scan per lookup, returns the collapsed
role through a stats struct, and silently reports `None` for a just-died
process instead of an error. The direct query is one syscall, exact, and
fails loudly.

---

## 5. rt.vdso implementation

### 5.1 Default spawn caps inherit only an Interactive parent

An unadorned command spawned by an Interactive shell must act as the user, but
a System parent stays an explicit policy/grant point and must not accidentally
create a logged-in session. `default_child_capabilities`, used when
`MOTOR_OS_CAPS` is absent, implements that rule:

```rust
pub const fn default_child_capabilities(parent_caps: u64) -> u64 {
    let role = ProcessRole::from_caps(parent_caps);
    let mut child_caps = CAP_SPAWN;
    match role {
        ProcessRole::System => child_caps |= CAP_LOG,
        ProcessRole::Interactive => child_caps |= CAP_INTERACTIVE,
        ProcessRole::None => {}
    }
    if !matches!(role, ProcessRole::System) {
        child_caps &= parent_caps;
    }
    child_caps
}
```

Semantics:

- Interactive parent → Interactive child (shell → command, command → helper),
  without `CAP_LOG`. An Interactive holder passes `CAP_LOG` only through an
  explicit replacement mask, and only because the kernel subset rule proves
  that it already holds the bit.
- System parent → None child by default; either Interactive or System requires
  an explicit `MOTOR_OS_CAPS` grant. This matters for sys-init services with a
  zero/omitted mask and for all-ones System processes, whose raw word contains
  the Interactive bit even though their derived role is System. A System
  console rush is an explicit session boundary and supplies that grant for
  ordinary external commands (§7); this does not change the global default.
  The default None child does receive `CAP_LOG`, and System may also grant it
  explicitly regardless of its own raw capability word.
- None parent → None child without `CAP_LOG`, including when the parent itself
  holds `CAP_LOG`. The kernel also rejects an explicit `CAP_LOG` grant by a
  None-role parent. Such a process may use logging authority but is never a
  grantor.

`MOTOR_OS_CAPS` keeps its replace-wholesale semantics. The two transitions
that are not produced by the default rule are therefore straightforward:

- **System → Interactive:** the System parent supplies an explicit replacement
  mask that includes `CAP_INTERACTIVE` and omits `CAP_SYS`. A System parent is
  exempt from the subset restriction, so this is allowed. The concrete entry
  points are sys-init → sys-tty and sys-init → russhd (§7).
- **Interactive → None:** the Interactive parent supplies an explicit
  replacement mask that omits both `CAP_SYS` and `CAP_INTERACTIVE`. The
  remaining bits must be a subset of the parent's caps; `0` and an explicit
  `CAP_SPAWN | CAP_LOG` subset are valid examples. This is a deliberate
  demotion/sandboxing operation. An unadorned child instead stays Interactive.

Role None does not mean “has no capabilities”; it means that neither role bit
is set. Conversely, an explicit mask that is intended only to add
`CAP_SPAWN_DETACHED` must preserve `CAP_INTERACTIVE` explicitly (§7). The
default-capability calculation reads the vdso's own `ProcessStaticPage`; the
page is mapped in every process, so there is no ordering concern.

A present-but-unparsable `MOTOR_OS_CAPS` value fails the spawn with
`E_INVALID_ARGUMENT` instead of falling back to the default. An explicit mask
is a policy statement, so the demotion path must not fail open.

`CAP_LOG` admits its holder to both the kernel log syscall and strobe's
`sys-log` record channel. Strobe checks the connection-bound peer capability
word before accepting a tag. The bit does not grant access to
`/system/logs`; lower-role holders submit records through `moto_log` while
System-role strobe alone creates and rotates the files.

### 5.2 Client-side permission reporting uses the caller's own role

`rt_fs.rs` reports permissions to `std` using the process's own role:

```rust
let role = /* async_fs::Role from ProcessRole::from_caps(ProcessStaticPage::get().capabilities) */;
file_attr.perm = access_to_perm(metadata.access(role)?);
```

so `std::fs` permission views agree with enforcement.
(rt.vdso links moto-sys directly; no ABI involved.)

### 5.3 Enforce file execute permission in the loader

Motor-fs cannot enforce file `x` because it never executes a file; its design
assigns that check to the exec-time consumer above the FS. That consumer is
`rt.vdso/src/rt_process.rs`:

- In `spawn_impl`, the `FileAttr` fetched for the requested ELF or script is
  retained and rejected with `E_NOT_ALLOWED` unless
  `perm & PERM_EXEC != 0`.
- `run_script` opens the shebang interpreter and calls `run_elf`, which checks
  the interpreter's own `FileAttr.perm` as well.
  Both the script and interpreter must be executable.
- The check happens before allocating/loading the image. Subsequent server-side
  reads still enforce `r`; the permission lattice guarantees that `x` is never
  granted without `r`.

This uses the existing `FileAttr.perm` and `E_NOT_ALLOWED` surfaces. It does not
add a moto-rt API or vtable field.

Scope, stated plainly: this check is cooperative, not a security boundary.
Spawn on Motor is a pure userspace loader — any `CAP_SPAWN` holder can read a
file (the lattice gives `x ⇒ r`, not the converse) and assemble the child
address space with the same syscalls rt.vdso uses, bypassing the check
entirely. File `x` is enforced policy for the standard runtime and every
well-behaved program; the boundaries that hold against a malicious spawner
remain server-side `r`/`w`/directory-`x` and the unforgeable role (§1,
property 1). This matches PERMISSIONS_DESIGN.md, which calls file `x`
"metadata for an exec-time consumer above the FS".

### 5.4 Process diagnostics use stderr first

rt.vdso's `log` facade and the vtable operation historically named
`log_to_kernel` both use the process diagnostic sink. The sink clones stderr's
underlying `StdioPipe` and writes to it directly, bypassing the POSIX descriptor
table and `SelfStdio` claim. A negative `log_backtrace` descriptor selects the
same sink. This keeps loader warnings, panic text, backtraces, and debug records
visible to an ordinary Interactive command after its default loses `CAP_LOG`.
It does not add another level filter: a debug record admitted by the debug
rt.vdso logger reaches stderr.

The route is guarded per thread. Same-thread reentry skips stderr; concurrent
threads serialize rather than losing a record. A missing pipe, a hard write
failure, or a short write falls back to `SysRay::log` only for a `CAP_LOG`
holder. Without that bit the record is dropped. The helper never logs a pipe
failure, so neither failure path can recurse through itself.

---

## 6. moto-rt ABI unchanged

The role is enforced server-side (kernel, sys-io) and assigned via the existing
env-var spawn mechanism, so `std` needs no new API, no new error code
(`E_NOT_ALLOWED` exists), and no vtable slot. The diagnostic change reuses the
existing vtable operations; only the `log_backtrace` documentation changes.
There is therefore **no `RT_VERSION` bump and no toolchain-lag staging** (the
published-crate problem documented in
`docs/plans/networking-remaining-steps.md:41–52`). A program that wants its own
role reads `ProcessStaticPage` via moto-sys. If a `moto_rt::process::role()`
getter is ever wanted, it is a compatible append-at-end vtable addition.

---

## 7. Role grant policy

The bit's meaning comes from where it is granted. The default spawn rule covers
ordinary descendants of an Interactive process, but every explicit
`MOTOR_OS_CAPS` replacement mask makes its role choice deliberately:

1. **sys-init → sys-tty** (`sys-init/src/main.rs`, the tty spawn): accepts
   legacy `tty:COMMAND` as Interactive and `tty:ROLE:COMMAND` for `system`,
   `interactive`, or `none`. Its explicit replacement mask is the fixed
   `CAP_IO_MANAGER | CAP_SPAWN | CAP_LOG | CAP_SPAWN_DETACHED` operational set
   plus the selected role bit. The config cannot omit an operational bit or
   provide a numeric mask.
2. **sys-tty → console rush** (`sys-tty/src/main.rs`): derives its own role and
   passes the matching role bit with `CAP_SPAWN | CAP_LOG |
   CAP_SPAWN_DETACHED`. It does not pass `CAP_IO_MANAGER`; the console manager
   and command have the same role but distinct operational authority.
3. **russhd → ssh session shell** (`russhd/src/local_session.rs:200–217`):
   includes `CAP_INTERACTIVE` in the intersection mask
   (`{CAP_SPAWN, CAP_LOG, CAP_SPAWN_DETACHED, CAP_INTERACTIVE}` ∩ own caps).
   Because russhd is not `CAP_SYS`, the subset rule means **russhd itself must
   hold each bit** to pass it on. This explicit trust-boundary grant is why the
   shell holds `CAP_LOG`; its unadorned commands do not inherit that bit:
4. **Both shipped sys-init configs**:
   `img_files/motor-os/system/cfg/sys-init.cfg` and
   `img_files/motor-os-base/system/cfg/sys-init.cfg` grant russhd decimal mask
   `124` (`60 | 64`). dns-resolver (`svc:8`) stays role None. sys-init launches
   strobe separately with `CAP_SYS | CAP_LOG`; this makes strobe the only
   process that writes and rotates `/system/logs` while leaving its public
   stats-registry channel available to lower roles.
5. **sys-init zero-mask semantics** (`sys-init/src/main.rs`, `spawn_service`):
   because the documented `svc:<caps>:<cmd>` grammar requires a mask, sys-init
   always sets `MOTOR_OS_CAPS` for a parsed service, including `0`, and rejects
   a missing or malformed mask rather than silently selecting the vdso default.
   This corrects the pre-implementation mismatch noted in §2.
6. **rush command policy** (`rush/src/sys/motor.rs`): a System rush explicitly
   grants `CAP_SYS | CAP_SPAWN | CAP_LOG` from its own mask to ordinary external
   commands, because the global spawn default intentionally does not propagate
   System. An explicit per-command `MOTOR_OS_CAPS` assignment replaces that
   ordinary grant and may narrow the child. Rush-compatible shebang scripts run
   in-process and retain the shell's role. **Rush trusted detached spawn**
   (`detach_cap_grant`) sets `MOTOR_OS_CAPS`, so it does *not* receive
   the vdso default. It preserves either `CAP_SYS` or `CAP_INTERACTIVE` according
   to the shell's derived role while adding `CAP_SPAWN_DETACHED`; otherwise a
   trusted session daemon would be silently demoted.
7. **Tests and scripts with literal masks**: full systest and soak invocations
   use `0x4c` (`CAP_SPAWN | CAP_LOG | CAP_INTERACTIVE`) because the suite tests
   the logging service. The focused lifetime path in `src/tests/full-test.sh`
   keeps `0x6c` to add detached-spawn authority. Explicit test masks preserve
   the caller's Interactive bit when testing inheritance, or omit it with a
   comment when deliberate demotion is part of the test. The existing
   `CAP_SYS` escalation test deliberately remains unchanged.
8. **Unadorned spawns outside Rush's System-session boundary**: §5.1 carries
   Interactive only from an Interactive parent. The kernel's all-ones sys-io
   grant and sys-io's all-ones sys-init grant remain System because `CAP_SYS`
   wins. The chain deliberately selects a role at sys-init → sys-tty through
   item 1's explicit replacement mask.

Detached user daemons (spawned via `MOTOR_OS_DETACHED` + `CAP_SPAWN_DETACHED`)
keep the shell's Interactive or System role after the session ends only when
their explicit replacement mask includes the corresponding bit. That is
intended: they continue acting with the session's authority.

### 7.1 Decision: russhd is Interactive for now

The minimal grant above makes the entire long-lived, network-facing russhd
process Interactive, including pre-authentication code and its in-process SFTP
implementation. This is not equivalent to granting only an authenticated shell
child, and it conflicts with the general preference that network-facing
services run as None. It is nevertheless the only small change compatible with
the current architecture: a non-System parent cannot pass a capability it does
not hold, and SFTP performs filesystem operations inside russhd.

Current policy grants russhd `CAP_INTERACTIVE` and accepts that its
authentication boundary protects Interactive FS authority. Unauthenticated
requests must not reach FS operations. This is an explicit interim policy
choice, not an accidental consequence of shell inheritance.

A future hardening change may keep the network/auth front-end at None and move
each authenticated shell/SFTP session into an Interactive worker. That would
also need a narrowly designed trusted launcher or kernel grant mechanism and a
way to hand the authenticated session to the worker. A
`CAP_GRANT_INTERACTIVE` bit by itself is not meaningful isolation: compromised
russhd code holding that bit and `CAP_SPAWN` could simply launch an arbitrary
Interactive helper.

---

## 8. sys-io role attribution per FS connection

This is the consumer that motivated the design; the FS-side permission details
belong to `PERMISSIONS_DESIGN.md`:

- Each accepted FS io_channel has one peer process, and caps are immutable per
  process ⇒ **role per connection is a constant**. sys-io computes it once
  after the existing accept/memory-pressure refusal and before dispatch in
  `fs_listener`
  (`sys-io/src/runtime/fs.rs:367–445`):
  `SysObj::get_capabilities(sender.remote_handle())` →
  `ProcessRole::from_caps` → `async_fs::Role`.
- The `Copy` role is a local owned by that `fs_listener`, captured in each
  per-message task and passed through `on_msg` to the command handler.
  There is no need for a global map, lookup, or disconnect eviction: the
  listener task already defines exactly the connection lifetime. The existing
  lock manager still uses the handle-derived `ConnectionId` for lock ownership.
- **Fail closed at accept**: if the peer query errors, sys-io drops that
  connection before dispatching any message; it never defaults a role. The
  precedent is
  `check_same_process`.
- The `on_cmd_*` call sites use the connection's role. sys-io's *internal*
  FS calls (`util.rs`, `net/config.rs`) and the host-side imager legitimately
  remain `Role::System`.
- The existing `set_permissions` request carries `(entry_id, access)` and is
  interpreted as **target = caller role**. Thus ordinary
  `std::fs::set_permissions` changes the caller's own byte; motor-fs permits a
  narrowing or the exact `Rw` → `Rx` finalization transition, cascades removed
  permissions to lower roles, and rejects every other self-widen. A future
  administrative API that explicitly edits a lower role can add a distinct
  command/target field when it has a real consumer; it is not required to make
  chmod work correctly.

  Be explicit about what that deferral means: no client of sys-io — not even a
  System process — can restore `w` or any other removed permission through its
  own byte. The sole exception adds `x` while permanently dropping `w`.
  A Unix-style `chmod -w` → `chmod +w` round-trip, common in ported software
  and test suites, fails on the second step with PermissionDenied. This is
  accepted, not accidental — it is what makes sealing real
  (PERMISSIONS_DESIGN.md §4a) — but it must be called out in user-facing docs,
  The recovery idiom is an explicit read/create/write/delete/rename sequence:
  copying bytes into an ordinarily created writable staging file before
  replacing the sealed entry. `std::fs::copy` is not suitable because it
  preserves the source permission byte; delete still needs only
  parent-directory `w` (§10.7).
- Ordinary client create requests use creator-relative defaults: files are
  `Rw` for the creator, `Rwx` for higher roles, and `R` for lower roles;
  directories are `Rwx` for the creator and higher roles and `Rx` for lower
  roles. A distinct
  `create_entry_with_permissions` request carries a complete mode and asks
  Motor FS to validate creation authority and monotonicity before linking the
  entry; rejection is atomic.
- On Motor OS, `std::fs::copy` preserves the source permission visible to the
  caller and the source permissions of every lower role the caller controls.
  Lower bytes are intersected with the finalized caller byte to retain
  monotonicity. The destination is staged as `Rw` while contents move, then
  `R`, `Rw`, or `Rx` is restored; a legacy caller-role `Rwx` source is
  finalized as `Rx`. Higher-role bytes retain their creator-relative defaults
  because the caller cannot edit them. sysbox `cp` relies on that behavior for
  files and leaves copied directories at their creator-relative default.

---

## 9. Observability

`sysbox ps` (`src/sys/tools/sysbox/src/commands/ps.rs`) uses a role marker driven
by `ProcessInfoV1.process_role`: `*` System, `+` Interactive, and blank None;
the `--help` note documents the symbols. `ps` is the
only in-tree reader of the renamed `system_process` field; other
`ProcessInfoV1` consumers (`top`, `mdbg`, `gears`, `rush`) do not inspect that
byte. The layout remains unchanged. The `(total)` and kernel pseudo-rows have
no process owner and therefore display a blank role marker. Unknown raw role
values render `?`, not System or Interactive.

---

## 10. Regression requirements

Required coverage spans systest (alongside `test_caps`) and small pure tests:

1. **Derivation**: `ProcessRole::from_caps` for all four bit combinations of
   `{CAP_SYS, CAP_INTERACTIVE}` (System wins when both set), and safe raw-`u8`
   decoding of 0..=2/rejection of other values.
2. **Default inheritance**: an Interactive systest spawning with no
   `MOTOR_OS_CAPS` yields an Interactive child without `CAP_LOG` (child asserts
   via `ProcessStaticPage`); an explicit mask can preserve its held `CAP_LOG`,
   while one without `CAP_INTERACTIVE` yields a None child (demotion). A
   present-but-unparsable `MOTOR_OS_CAPS`
   fails the spawn with `E_INVALID_ARGUMENT` (§5.1) rather than falling back
   to the default. Exercise the default-cap helper with a
   System/all-ones parent and assert the default child is None, not Interactive.
3. **Default subset correctness**: a `CAP_SPAWN`-only parent can spawn an
   unadorned None child. A `CAP_LOG`-holding None parent also creates an
   unadorned child without that bit and is denied when it requests the bit
   explicitly. A None child requesting `CAP_INTERACTIVE` explicitly gets
   `E_NOT_ALLOWED`; the existing `CAP_SYS` escalation test stays green.
4. **Explicit-mask audit**: a trusted detached child launched through rush
   remains Interactive and detached; a mask intentionally omitting the bit
   produces None. Keep the focused full-test lifetime mask and its comment in
   sync with the constants. Verify a `svc:0` parser/spawn case actually gives
   the service zero caps rather than the vdso default.
5. **Peer query**: use a real child process connected over a shared/io_channel
   endpoint, not merely two threads in one process. Assert the exact peer word,
   failure for a non-shared/unowned handle, and an error after peer teardown.
   Callers test fail-closed behavior rather than depending on one error code for
   every invalid-handle shape.
6. **Reporting**: `ProcessInfoV1.process_role` matches actual caps for each
   live role. Assert that strobe reports System and that sys-tty, its console
   rush, russhd, and an authenticated ssh shell report Interactive. Assert the
   documented None result for zombie/aggregate/kernel entries and pin
   `size_of::<ProcessInfoV1>() == 56`.
7. **FS attribution**: create an entry while Interactive, narrow it with public
   chmod, and verify the Interactive and cascaded None bytes change while the
   System byte remains `Rwx`. Verify self-widening fails — including the
   Unix-style readonly round-trip (`set_permissions` readonly, then
   un-readonly fails on the second step) — and exercise the explicit
   read/create/write → delete → rename recovery idiom (§8). Spawn a None child and
   exercise read, write, resize, create/delete, move (both parents), and
   directory traversal/listing denial according to `PERMISSIONS_DESIGN.md`.
   Also verify a newly accepted connection cannot send a request when the peer
   capability query fails.
8. **Execute**: an ELF with the caller's `x` bit removed fails to spawn with
   `E_NOT_ALLOWED`; an executable script whose copied shebang interpreter lacks
   `x` also fails. Executable ELF/script controls continue to run. Check both
   before any child process is created.
9. **russhd policy**: cover unauthenticated denial, authenticated shell
   inheritance, in-process SFTP behavior, and detached rmux/rush descendants
   under the chosen Interactive-russhd policy.
10. **Diagnostics**: an Interactive child without `CAP_LOG` captures ordinary
    rt.vdso records, debug-build records, panic text, and a complete backtrace
    on piped stderr, while direct `SysRay::log` is denied. Exercise the route
    while stderr's normal state is claimed. A dead reader, a short write, and
    same-thread reentry drop without `CAP_LOG` and use the kernel fallback with
    it.
11. **Logging service**: claim a slot from the fixed eight-tag systest pool and
    derive every valid protocol-test tag from it. Verify System strobe accepts
    `CAP_LOG`-bearing Interactive and None clients, rejects unauthorized and
    malformed peers without losing service, and reports System through
    process stats. Verify `/system/logs` is `rwxr-x---`, current and rotated
    logs are `rw-r-----`, Interactive can read but cannot write or delete them,
    and None cannot read them. Match records with a PID and nonce rather than
    deleting old files or relying on timestamps.

---

## 11. Alternatives rejected

- **Keeping `system_process` beside a new role byte:** redundant state derived
  from the same capability word. With no backward-compatibility requirement,
  renaming the existing byte to `process_role` and assigning it the exact
  `ProcessRole` values is smaller and leaves the struct layout unchanged.
- **A stored per-process privilege field** (`privilege=N` in the spawn URL, a
  field in `Process` / `ProcessStaticPage`): second source of truth beside
  caps; needs its own inheritance rule, immutability argument, query plumbing,
  and a consistency invariant with `CAP_SYS`. All of it already exists on the
  caps axis.
- **A 2-bit numeric level packed into the caps word**: the kernel's subset
  check does not preserve numeric order (`0b01 ⊄ 0b10`) and `0b11` needs a
  separate validity/normalization rule. Independent capability markers plus
  highest-wins derivation preserve the existing `CAP_SYS` meaning and make
  `ProcessRole::from_caps` monotone under set inclusion without an encoded
  level field.
- **Deriving Interactive from ancestry** (walk `parent_pid` up to a sys-tty /
  russhd session leader): O(depth) racy stats scans per decision; detached
  processes are reparented and break the chain; no way to deliberately demote
  a child to None.
- **Exposing the role through moto-rt**: no consumer in `std`, and any moto-rt
  surface change pays the published-crate/toolchain-lag tax (§6).
- **System → Interactive as the default downgrade**: rejected. It makes any
  unannotated child of sys-init or another privileged service look like a
  logged-in session, and all existing System processes use all-ones masks that
  contain the new bit. Session provenance must be explicit.
- **A global sys-io role cache**: rejected. `fs_listener` already owns one
  accepted connection for its full lifetime; carrying one local `Copy` value is
  simpler and cannot suffer stale-handle reuse.
- **A target-role byte in the existing chmod request**: deferred. The existing
  API has no caller-facing way to choose a target role, and `target = caller`
  gives public chmod the natural safe behavior. Add an explicit administrative
  operation only with a concrete consumer and tests for the full `may_set`
  matrix.
- **`F_QUERY_ROLE` instead of `F_QUERY_CAPS`**: viable least-disclosure
  alternative. It centralizes derivation in the kernel and exposes only the
  needed value, but adds a role-specific syscall while the capability word is
  already the immutable source of truth and peer-capability lookup is generally
  useful. Prefer `F_QUERY_CAPS` unless capabilities are later classified as
  sensitive metadata.
- **Giving russhd only a `CAP_GRANT_INTERACTIVE` bit**: insufficient isolation
  by itself. A compromised spawner could launch a helper to exercise the same
  authority; meaningful isolation also requires post-authentication worker
  separation (§7.1).
- **`CAP_USER` naming**: interchangeable with Interactive; Interactive matches
  the implemented `async_fs::Role` and PERMISSIONS_DESIGN.md vocabulary.
