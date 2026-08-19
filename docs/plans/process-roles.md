# Process Roles — System / Interactive / None

Status: **proposed** (not implemented; codebase-reviewed 2026-08-18; review
findings folded in 2026-08-19). Companion to
`src/sys/lib/motor-fs/PERMISSIONS_DESIGN.md`, which defines the FS-side
consumer of the three roles and deliberately leaves their *origin*
unspecified ("a trusted input supplied from above the FS").
Audience: an engineer (human or LLM) implementing or reviewing this feature.

This document specifies how the kernel, `moto-sys`, `rt.vdso`, and sys-io
represent and consume three process privilege roles, how a role is assigned at
spawn, and how it is queried by the process itself and by a connected server.
It also closes the exec-time `x`-permission gap deliberately left to a consumer
above motor-fs by `PERMISSIONS_DESIGN.md`. Code references include current line
numbers, which may drift — treat the named items as the stable anchors.

---

## 1. Problem

Motor FS permissions are per-role: `async_fs::Role { None = 0, Interactive = 1,
System = 2 }` (`src/sys/lib/async-fs/src/filesystem.rs:52`), with one
permission byte per role persisted in every entry's `Metadata`. But the OS
itself only distinguishes two classes of process: "system" (`CAP_SYS` set) and
everything else. Consequences today:

- sys-io passes `Role::System` unconditionally at **every role-taking** FS call
  site
  (`src/sys/sys-io/src/runtime/fs.rs:620–1165`, `util.rs`, `net/config.rs`),
  so the Interactive and None permission bytes are stored and cascaded but
  never consulted.
- `sysbox ps` can only render a binary `*` marker from the current
  `ProcessInfoV1.system_process` byte. This design replaces that byte with a
  three-valued `process_role` byte (§4.2).
- There is no kernel notion of "logged-in user authority" vs "least
  privilege"; the interactive session is an informal capability bundle
  (`CAP_SPAWN | CAP_LOG | CAP_SPAWN_DETACHED`) re-spelled ad hoc by sys-tty,
  russhd, and rush.
- File `x` is persisted and reported but never enforced. `rt.vdso`'s ELF/script
  loader opens and reads a program without checking `FileAttr.perm & PERM_EXEC`.

Required properties of the fix:

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
   new code never runs against old images. So the design must not *need*
   migration logic or format/ABI versioning — simplicity over staging (§10).

---

## 2. Current state (facts the design builds on)

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
- Spawn path: rt.vdso builds a URL
  `process:entry_point=..;capabilities=<caps>;detached=..` and calls
  `SysObj::create` (`rt.vdso/src/rt_process.rs:637–679`). The default grant is
  `CAP_SPAWN | CAP_LOG`; a `MOTOR_OS_CAPS` env var (hex) **replaces** the
  default outright and is stripped from the child's env. **There is no
  inheritance** — an unadorned spawn always yields `CAP_SPAWN | CAP_LOG`
  regardless of the parent. Consequently a non-System parent that has
  `CAP_SPAWN` but not `CAP_LOG` currently asks for a non-subset default and its
  unadorned spawn is rejected by the kernel.
- Kernel escalation gate (`kernel/src/uspace/process.rs:310–320`): a `CAP_SYS`
  parent may grant anything; a non-`CAP_SYS` parent may grant only a **subset
  of its own caps** and never `CAP_SYS`/`CAP_IO_MANAGER`.
- `ProcessInfoV1.system_process` is a derived view of `CAP_SYS`, computed in
  exactly one place (`kernel/src/xray/stats.rs:579–584`).
- Self-query: `ProcessStaticPage::get().capabilities` (zero syscalls). A URL
  query also returns self caps, but `SysObj::get(h, 0, "capabilities")` is
  **unimplemented for non-`SELF` handles**
  (`kernel/src/uspace/sys_obj.rs:184–192`). `OP_QUERY_HANDLE/F_QUERY_PID`
  already resolves the process owning the sibling endpoint of a shared object;
  this is the correct peer-query precedent.
- Who holds what today: the kernel gives sys-io all-ones caps; sys-io does the
  same for sys-init, and sys-init does the same for sys-tty. The console shell
  gets `CAP_SPAWN|CAP_LOG|CAP_SPAWN_DETACHED`
  (`sys-tty/src/main.rs:94–101`). Both shipped sys-init configs use decimal
  masks and give russhd `60`, while the main image gives dns-resolver `8` and
  sys-init gives strobe `CAP_LOG`. Ordinary commands get the vdso default. The
  target policy changes sys-tty, russhd, and their shells to Interactive (§7).
- `sys-init::spawn_service` sets `MOTOR_OS_CAPS` only when the parsed mask is
  nonzero. Thus an explicit `svc:0:...` currently receives the vdso default
  (`CAP_SPAWN|CAP_LOG`) rather than zero caps, despite the logged/configured
  value. No shipped service uses zero today, but this is a pre-existing policy
  bug in the role-assignment path.
- Explicit replacement masks exist beyond those entry points. In particular,
  rush's trusted detached-spawn path constructs `CAP_SPAWN|CAP_LOG|
  CAP_SPAWN_DETACHED`, and the focused lifetime test in `full-test.sh` uses
  `MOTOR_OS_CAPS=0x2c`. Every such mask must be audited when adding a role bit;
  the vdso default does not repair an explicit mask.

---

## 3. Design: the role is *derived* from the capability word

**One new capability bit; no new kernel state.** The role is a pure function
of the existing caps word.

```rust
// moto-sys/src/caps.rs

/// Interactive ("user") process: acts with the authority of the logged-in
/// user. See docs/plans/process-roles.md. CAP_SYS takes precedence for role
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
| `System` | `CAP_SYS` set | root-like; unkillable from userspace; unrestricted grant authority at spawn | kernel-spawned sys-io; sys-init |
| `Interactive` | no `CAP_SYS`, `CAP_INTERACTIVE` set | the logged-in user's authority | sys-tty; russhd; console/ssh shells; commands they run; user daemons (including detached ones) |
| `None` | neither bit | least privilege | strobe, dns-resolver, other services, deliberately sandboxed children |

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

## 4. Kernel changes

### 4.1 Spawn gate: no change required

`Process::new_child` (`process.rs:294–362`) already implements exactly the
needed rule (§3). Add a comment at the subset check referencing this document
so the invariant is discoverable. Also fix the stale `CAP_SPAWN` doc comment
("not used"): `sys_handle_create` currently checks it before creating an
address space (`kernel/src/uspace/sys_obj.rs:35–41`).

The unrestricted `CAP_SYS` branch is intentional: a System parent may
explicitly mint any role. The safer *default* for a System parent is addressed
in rt.vdso (§5.1), not by weakening this kernel authority.

### 4.2 Stats: replace the binary flag with the role

Rename and reinterpret the existing `ProcessInfoV1.system_process: u8` field
as `process_role: u8`. Do not retain a second compatibility flag: this work has
no backward-compatibility requirement, and two fields would be redundant views
of the same immutable capability word.

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
rule. Add the missing `size_of::<ProcessInfoV1>() == 56` const assert while
touching the struct. Keep the field raw `u8`; enum-invalid bytes must never be
materialized as a Rust enum, and consumers decode through a small
`ProcessRole::try_from`/`from_u8` helper.

Fill site — `KProcessStats::into_v1` (`kernel/src/xray/stats.rs:575–605`):

```rust
dest.process_role = ProcessRole::None as u8;
if let Some(proc) = self.owner.upgrade() {
    dest.process_role = ProcessRole::from_caps(proc.capabilities()) as u8;
}
```

`sysbox ps` is the only in-tree reader of `system_process`, so it changes to
decode `process_role`; the other `ProcessInfoV1` consumers do not need source
changes. `KProcessStats` holds only a weak process owner. Therefore zombies,
the `(total)` aggregate, and the kernel pseudo-process have no live owner and
report `process_role == None`; this field is observational only and must never
authorize access. Live peer authorization uses §4.3 instead.

### 4.3 Peer capability query

Servers need the caps of the process at the other end of an IPC connection.
Extend the existing handle-query mechanism used for peer pid lookup. Two
touchpoints, one rule:

- Kernel: in `OP_QUERY_HANDLE` (`kernel/src/uspace/sys_obj.rs:284–339`, where
  `F_QUERY_PID` lives), add `F_QUERY_CAPS`: resolve the peer owner of a shared
  object the caller owns (`shared::peer_owner`, same as `get_pid`) and return
  `proc.capabilities()` in result slot 0. Do not extend the old
  `SysObj::get(..., "capabilities")` URL: it encodes an integer as a
  `SysHandle`, whereas `OP_QUERY_HANDLE` is already the typed precedent.
- moto-sys: `SysObj::get_capabilities(handle: SysHandle) -> Result<u64, ErrorCode>`
  next to `SysObj::get_pid` (`moto-sys/src/sys_obj.rs:225–241`). Correct the
  latter's stale doc comment at the same time: it returns the owner of the
  *peer/sibling endpoint*, not the owner of the caller's local handle.

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

## 5. rt.vdso changes

### 5.1 Default spawn caps inherit only an Interactive parent

`rt_process.rs:637–638` currently hardcodes `CAP_SPAWN | CAP_LOG`, which would
make every unadorned child of a shell role-None — wrong: a command the user
runs must act as the user. Change only the no-`MOTOR_OS_CAPS` default. A System
parent stays an explicit policy/grant point; it must not accidentally create a
logged-in session:

```rust
let self_caps = moto_sys::ProcessStaticPage::get().capabilities;
// TODO: remove CAP_LOG when the runtime is stabilized.
let mut caps = moto_sys::caps::CAP_SPAWN | moto_sys::caps::CAP_LOG;
let self_role = moto_sys::caps::ProcessRole::from_caps(self_caps);
if self_role == moto_sys::caps::ProcessRole::Interactive {
    caps |= moto_sys::caps::CAP_INTERACTIVE;
}
// A non-System default must always satisfy the kernel's subset rule, including
// the existing CAP_LOG corner case.
if self_role != moto_sys::caps::ProcessRole::System {
    caps &= self_caps;
}
```

Semantics:

- Interactive parent → Interactive child (shell → command, command → helper).
- System parent → None child by default; either Interactive or System requires
  an explicit `MOTOR_OS_CAPS` grant. This matters for sys-init services with a
  zero/omitted mask and for existing all-ones System processes, whose raw word
  will contain the new bit even though their derived role is System.
- None parent → None child. Intersecting the base default with its caps also
  avoids requesting `CAP_LOG` from a `CAP_SPAWN`-only parent.

`MOTOR_OS_CAPS` keeps its replace-wholesale semantics. The two transitions
that are not produced by the default rule are therefore straightforward:

- **System → Interactive:** the System parent supplies an explicit replacement
  mask that includes `CAP_INTERACTIVE` and omits `CAP_SYS`. A System parent is
  exempt from the subset restriction, so this is allowed. The concrete entry
  points are sys-init → sys-tty and sys-init → russhd (§7).
- **Interactive → None:** the Interactive parent supplies an explicit
  replacement mask that omits both `CAP_SYS` and `CAP_INTERACTIVE`. The
  remaining bits must be a subset of the parent's caps; `0` and the usual
  `CAP_SPAWN | CAP_LOG` subset are valid examples. This is a deliberate
  demotion/sandboxing operation. An unadorned child instead stays Interactive.

Role None does not mean “has no capabilities”; it means that neither role bit
is set. Conversely, an explicit mask that is intended only to add
`CAP_SPAWN_DETACHED` must now preserve `CAP_INTERACTIVE` explicitly (§7). This
is the vdso's first read of its own `ProcessStaticPage`; the page is mapped in
every process, so there is no ordering concern.

One correction must ride along: a present-but-unparsable `MOTOR_OS_CAPS`
value currently logs and falls through to the default
(`rt_process.rs:652–656`). Today that default is a fixed low mask; with
inheritance it can be Interactive, so a corrupted explicit mask — including
one intended as a demotion — would silently yield an Interactive child. An
explicit mask is a policy statement: fail the spawn with `E_INVALID_ARGUMENT`
instead of falling back. The demotion path must not fail open.

### 5.2 Client-side permission reporting uses the caller's own role

`rt_fs.rs:498` reports `metadata.access(Role::System)` to `std` regardless of
who is asking. Change to the process's own role:

```rust
let role = /* async_fs::Role from ProcessRole::from_caps(ProcessStaticPage::get().capabilities) */;
file_attr.perm = access_to_perm(metadata.access(role)?);
```

so `std::fs` permission views agree with what enforcement will actually do.
(rt.vdso links moto-sys directly; no ABI involved.)

### 5.3 Enforce file execute permission in the loader

Motor-fs cannot enforce file `x` because it never executes a file; its design
assigns that check to the exec-time consumer above the FS. That consumer is
`rt.vdso/src/rt_process.rs`:

- In `spawn_impl`, retain the `FileAttr` already fetched for the requested ELF
  or script and reject with `E_NOT_ALLOWED` unless `perm & PERM_EXEC != 0`.
- `run_script` opens the shebang interpreter and calls `run_elf`; check the
  interpreter's own `FileAttr.perm` in `run_elf` (or a shared helper) as well.
  Both the script and interpreter must be executable.
- Do the check before allocating/loading the image. The subsequent server-side
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

---

## 6. moto-rt: no changes

Deliberately none. The role is enforced server-side (kernel, sys-io) and
assigned via the existing env-var spawn mechanism, so `std` needs no new API,
no new error code (`E_NOT_ALLOWED` exists), no vtable slot, and therefore **no
`RT_VERSION` bump and no toolchain-lag staging** (the published-crate problem
documented in `docs/plans/networking-remaining-steps.md:41–52`). A program
that wants its own role reads `ProcessStaticPage` via moto-sys. If a
`moto_rt::process::role()` getter is ever wanted, it is a compatible
append-at-end vtable addition.

---

## 7. Policy and explicit-grant audit

The bit's meaning comes from where it is granted. The default spawn rule covers
ordinary descendants of an Interactive process, but every explicit
`MOTOR_OS_CAPS` replacement mask must make its role choice deliberately:

1. **sys-init → sys-tty** (`sys-init/src/main.rs`, the tty spawn): replace the
   all-ones mask with the explicit
   `CAP_IO_MANAGER | CAP_SPAWN | CAP_LOG | CAP_SPAWN_DETACHED |
   CAP_INTERACTIVE` mask. `CAP_IO_MANAGER` is required for sys-tty's kernel
   serial-console handle; the other non-role bits let it start rush and pass
   rush its intended session capabilities. Omitting `CAP_SYS` makes sys-tty
   Interactive rather than System.
2. **sys-tty → console rush** (`sys-tty/src/main.rs:94–101`): add
   `CAP_INTERACTIVE` to the existing
   `CAP_SPAWN | CAP_LOG | CAP_SPAWN_DETACHED` grant. The console manager and
   the shell it starts are both Interactive.
3. **russhd → ssh session shell** (`russhd/src/local_session.rs:200–217`): add
   `CAP_INTERACTIVE` to the intersection mask
   (`{CAP_SPAWN, CAP_LOG, CAP_SPAWN_DETACHED, CAP_INTERACTIVE}` ∩ own caps).
   Because russhd is not `CAP_SYS`, the subset rule means **russhd itself must
   hold the bit** to pass it on:
4. **Both shipped sys-init configs**:
   `img_files/motor-os/system/cfg/sys-init.cfg` and
   `img_files/motor-os-base/system/cfg/sys-init.cfg` each change
   `svc:60:...russhd` to `svc:124:...russhd` (caps are parsed as **decimal**;
   124 = 60 | 64). Update both comments enumerating the bits. dns-resolver
   (`svc:8`) and strobe (`CAP_LOG`) stay role None.
5. **sys-init zero-mask semantics** (`sys-init/src/main.rs`, `spawn_service`):
   because the documented `svc:<caps>:<cmd>` grammar requires a mask, always
   set `MOTOR_OS_CAPS` for a parsed service, including `0`; reject a missing or
   malformed mask rather than silently selecting the vdso default. Add a parser
   test for `svc:0`. This corrects the pre-existing mismatch noted in §2.
6. **rush trusted detached spawn** (`rush/src/sys/motor.rs`,
   `detach_cap_grant`): this path sets `MOTOR_OS_CAPS`, so it does *not* receive
   the vdso default. Include `CAP_INTERACTIVE` when the shell's derived role is
   Interactive (or equivalently intersect the full intended mask with the
   shell's caps). Otherwise a trusted detached user daemon is silently demoted
   to None.
7. **Tests and scripts with literal masks**: update the focused lifetime path
   in `src/tests/full-test.sh` (`0x2c` → `0x6c`) when it is meant to retain the
   ssh session role. Audit the explicit mask in
   `systest/src/stdio_file_input.rs` similarly: preserve the caller's
   Interactive bit when testing inheritance, or omit it with a comment when
   deliberate demotion is part of the test. The existing `CAP_SYS` escalation
   test deliberately remains unchanged.
8. **Unadorned spawns**: no call-site edit; §5.1 carries Interactive only from
   an Interactive parent. The kernel's all-ones sys-io grant and sys-io's
   all-ones sys-init grant remain System because `CAP_SYS` wins. The chain
   deliberately changes role at sys-init → sys-tty through item 1's explicit
   replacement mask.

Detached user daemons (spawned via `MOTOR_OS_DETACHED` + `CAP_SPAWN_DETACHED`)
keep Interactive after the session ends only when their explicit replacement
mask includes the bit. That is intended: they continue acting with the logged-
in user's authority.

### 7.1 Decision: russhd is Interactive for now

The minimal grant above makes the entire long-lived, network-facing russhd
process Interactive, including pre-authentication code and its in-process SFTP
implementation. This is not equivalent to granting only an authenticated shell
child, and it conflicts with the general preference that network-facing
services run as None. It is nevertheless the only small change compatible with
the current architecture: a non-System parent cannot pass a capability it does
not hold, and SFTP currently performs filesystem operations inside russhd.

For this implementation, grant russhd `CAP_INTERACTIVE`, accept that its
authentication boundary protects Interactive FS authority, and test that
unauthenticated requests cannot reach FS operations. This is an explicit
interim policy choice, not an accidental consequence of shell inheritance.

A future hardening change may keep the network/auth front-end at None and move
each authenticated shell/SFTP session into an Interactive worker. That would
also need a narrowly designed trusted launcher or kernel grant mechanism and a
way to hand the authenticated session to the worker. A
`CAP_GRANT_INTERACTIVE` bit by itself is not meaningful isolation: compromised
russhd code holding that bit and `CAP_SPAWN` could simply launch an arbitrary
Interactive helper.

---

## 8. sys-io: deriving `async_fs::Role` per FS connection

This is the consumer that motivated the design; sketch level (the FS-side
details belong to PERMISSIONS_DESIGN.md's world):

- Each accepted FS io_channel has one peer process, and caps are immutable per
  process ⇒ **role per connection is a constant**. Compute it once after the
  existing accept/memory-pressure refusal and before dispatch in `fs_listener`
  (`sys-io/src/runtime/fs.rs:367–445`):
  `SysObj::get_capabilities(sender.remote_handle())` →
  `ProcessRole::from_caps` → `async_fs::Role`.
- Keep the `Copy` role as a local owned by that `fs_listener`, capture it in
  each per-message task, and pass it through `on_msg` to the command handler.
  There is no need for a global map, lookup, or disconnect eviction: the
  listener task already defines exactly the connection lifetime. The existing
  lock manager still uses the handle-derived `ConnectionId` for lock ownership.
- **Fail closed at accept**: if the peer query errors, drop that connection
  before dispatching any message; never default a role. Precedent:
  `check_same_process`.
- Replace the hardcoded `Role::System` at the `on_cmd_*` call sites
  (`runtime/fs.rs:620–1165`) with the connection's role. sys-io's *internal*
  FS calls (`util.rs`, `net/config.rs`) and the host-side imager legitimately
  remain `Role::System`.
- The existing `set_permissions` request carries `(entry_id, access)`. Keep that
  wire format and interpret it as **target = caller role**. Thus ordinary
  `std::fs::set_permissions` narrows the caller's own byte; motor-fs cascades a
  narrowing to lower roles and rejects an attempted self-widen. Update the
  stale `moto_io::FsClient::set_permissions` comment, which currently says it
  changes the System byte. A future administrative API that explicitly edits
  a lower role can add a distinct command/target field when it has a real
  consumer; it is not required to make chmod work correctly.

  Be explicit about what that deferral means: with target = caller and
  `may_set` allowing only narrowing of one's own byte, **no client of sys-io —
  not even a System process — can widen any permission byte back through the
  public API**. Every public chmod is therefore permanently one-way and
  cascades downward. A Unix-style `chmod -w` → `chmod +w` round-trip, common
  in ported software and test suites, fails on the second step with
  PermissionDenied. This is accepted, not accidental — it is what makes
  sealing real (PERMISSIONS_DESIGN.md §4a) — but it must be called out in
  user-facing docs, and the runtime recovery idiom — copy, delete, rename;
  delete needs only parent-directory `w` — documented and tested alongside it
  (§11.7).
- Client create requests still use `[Rwx; 3]`. That array is monotonic and is
  legal for every caller role under `PERMISSIONS_DESIGN.md` §6.2. Initial
  restricted creation would require a separate protocol addition; do not mix
  it into role attribution.

---

## 9. Observability

`sysbox ps` (`src/sys/tools/sysbox/src/commands/ps.rs`): the `*` marker column
becomes a role marker driven by `ProcessInfoV1.process_role` — `*` System
(unchanged), `+` Interactive, blank None; update the `--help` note. `ps` is the
only in-tree reader of the renamed `system_process` field; other
`ProcessInfoV1` consumers (`top`, `mdbg`, `gears`, `rush`) do not inspect that
byte and need no source changes. The layout remains unchanged. The `(total)`
and kernel pseudo-rows have no process owner and therefore display a blank role
marker; document or special-case their labels in `ps` if that would otherwise
look surprising. Unknown raw role values should render `?`, not be treated as
System or Interactive.

---

## 10. Rollout sequencing

There are **no compatibility requirements**: new code ships only as part of a
complete new image (kernel, userspace, and FS image are built and deployed
together), and new code is never run against old images. Nothing here needs
migration logic, staged enablement, or version negotiation.

The interim russhd policy is fixed in §7.1. The sequencing below is for small
reviewable patches and bisection. Do not flip sys-io to client roles until the
query, inheritance, and all explicit grant sites are present in the same final
image:

1. **moto-sys + kernel**: `CAP_INTERACTIVE`, `ProcessRole`,
   `ProcessInfoV1.process_role`, `F_QUERY_CAPS` +
   `SysObj::get_capabilities`, plus pure derivation/query tests.
2. **rt.vdso default inheritance + explicit-mask audit** (§5.1, §7), including
   Interactive sys-tty, console rush, russhd, and ssh sessions. Add focused
   spawn tests in the same patch.
3. **sys-io derivation flip + own-role chmod + client-side reporting** (§5.2,
   §8). This is the point at which motor-fs enforcement becomes effective for
   real clients.
4. **Program `x` enforcement + observability** (§5.3, §9), with ELF and shebang
   tests.

The only external surface, moto-rt, is untouched (§6).

These changes touch core OS components under `src/sys`. Each implementation
patch must therefore be formatted with `cargo +nightly fmt`, introduce no new
compiler/clippy warnings, remain covered transitively by `src/tests/full-test.sh`,
and pass that script consistently at least three times each in debug and
release before commit, as required by the repository guidelines. Role lookup
adds one syscall per accepted FS connection, not per request and not as a new
eager boot scan.

---

## 11. Test plan

systest additions (alongside `test_caps`, `systest/src/main.rs:605–623`) plus
small pure tests where noted:

1. **Derivation**: `ProcessRole::from_caps` for all four bit combinations of
   `{CAP_SYS, CAP_INTERACTIVE}` (System wins when both set), and safe raw-`u8`
   decoding of 0..=2/rejection of other values.
2. **Default inheritance**: an Interactive systest spawning with no
   `MOTOR_OS_CAPS` yields an Interactive child (child asserts via
   `ProcessStaticPage`); explicit `MOTOR_OS_CAPS` without `CAP_INTERACTIVE`
   yields a None child (demotion). A present-but-unparsable `MOTOR_OS_CAPS`
   fails the spawn with `E_INVALID_ARGUMENT` (§5.1) rather than falling back
   to the default. Exercise the default-cap helper with a
   System/all-ones parent and assert the default child is None, not Interactive;
   a System integration case may require a small boot-launched test helper.
3. **Default subset correctness**: a `CAP_SPAWN`-only parent can spawn an
   unadorned None child (the default must not over-request `CAP_LOG`). A None
   child requesting `CAP_INTERACTIVE` explicitly gets `E_NOT_ALLOWED`; the
   existing `CAP_SYS` escalation test stays green.
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
   live role. Assert that sys-tty, its console rush, russhd, and an authenticated
   ssh shell report Interactive. Assert the documented None result for
   zombie/aggregate/kernel entries and pin `size_of::<ProcessInfoV1>() == 56`.
7. **FS attribution**: create an entry while Interactive, narrow it with public
   chmod, and verify the Interactive and cascaded None bytes change while the
   System byte remains `Rwx`. Verify self-widening fails — including the
   Unix-style readonly round-trip (`set_permissions` readonly, then
   un-readonly fails on the second step) — and exercise the copy → delete →
   rename recovery idiom (§8). Spawn a None child and
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

---

## 12. Alternatives rejected

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

---

## Implementation log

This section is a temporary rollout record and can be deleted after all four
patches in §10 are complete.

- **2026-08-19 — Patch 1 complete:** added `CAP_INTERACTIVE` and
  `ProcessRole`; renamed the stable `ProcessInfoV1` byte to `process_role`;
  added the peer `F_QUERY_CAPS` / `SysObj::get_capabilities` API and kernel
  implementation; updated `sysbox ps` for the renamed field and role markers;
  and added derivation, stats, and real-child peer-query coverage. Validation:
  `cargo +nightly fmt`, `make -j20`, and three successful
  `src/tests/full-test.sh` runs each in debug and release mode.
