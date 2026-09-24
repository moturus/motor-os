# Process capabilities

Each Motor OS process has an immutable `u64` capability mask, assigned when
the process is created. Set bits authorize operations in the kernel and
userspace services. The definitions and default child policy live in
[`moto_sys::caps`](../src/sys/lib/moto-sys/src/caps.rs).

A process cannot change its own capabilities. It can request a capability
mask for a new child, subject to the kernel's grant rules. Environment
variables used to request a child mask do not confer authority on the caller.

## Defined capabilities

Combine capabilities with bitwise OR (`|`).

| Capability | Bit | Hex mask | Authority |
| --- | --- | --- | --- |
| `CAP_SYS` | 0 | `0x01` | System role, protection from ordinary userspace process killing, and broad authority to grant child capabilities. |
| `CAP_IO_MANAGER` | 1 | `0x02` | IO-manager operations, including access to the serial console (COM1) and MMIO. |
| `CAP_SPAWN` | 2 | `0x04` | Spawn processes; the kernel checks this when creating a child address space. |
| `CAP_LOG` | 3 | `0x08` | Submit records to the kernel log and strobe's record channel. |
| `CAP_SHUTDOWN` | 4 | `0x10` | Shut down the system. |
| `CAP_SPAWN_DETACHED` | 5 | `0x20` | Spawn detached children whose lifetime is independent of the spawner. |
| `CAP_INTERACTIVE` | 6 | `0x40` | Act with the logged-in user's authority, selecting the Interactive role unless `CAP_SYS` is also set. |
| `CAP_VSOCK` | 7 | `0x80` | Create and listen on native virtio-vsock streams; also needs `CAP_NET`. |
| `CAP_NET` | 8 | `0x100` | Use sys-io's network API. |
| `CAP_FS_WRITE` | 9 | `0x200` | Modify the filesystem and use file locks through sys-io. |

`CAP_SYS` does not imply that the other bits are set. Operations that check
a particular bit still require it: for example, a System process needs
`CAP_SPAWN` to create a child address space and `CAP_SHUTDOWN` to shut down.
Its broader authority applies to granting capabilities at spawn, with the
`CAP_VSOCK`, `CAP_NET`, and `CAP_FS_WRITE` exceptions described below. It
does not substitute for `CAP_NET` or `CAP_FS_WRITE` at sys-io either.

`CAP_LOG` does not grant direct filesystem access to `/system/logs`.
That access is governed by filesystem permissions. Logging through the
kernel or strobe and ordinary stdout/stderr output are separate mechanisms.
See [kernel logs](kernel-logs.md) and the [native vsock API](vsock.md) for
details of those services.

## Network and filesystem-write access

Sys-io authorizes the actual connected peer, using the capability word the
kernel reports for the connection; nothing a client sends can widen it.

Without `CAP_NET`, sys-io drops a network connection when it accepts it,
before serving any request. This covers TCP, UDP, ICMP, loopback, and vsock,
including discovery. The IPC connect itself can succeed, so the denial shows
up as a disconnected channel rather than `NotAllowed`: native network RPCs
fail with `NotConnected`, and a raw `io_channel` client sees its channel
close, even if it never sends a request. `CAP_VSOCK` alone therefore grants
nothing; vsock needs both bits.

The DNS resolver independently checks its IPC peer for `CAP_NET`, returning
`NotAllowed` (`PermissionDenied` through `std`) when it is absent. A caller
cannot borrow the resolver's network authority. Numeric address parsing and
the runtime's local `localhost` mapping do not require this capability.

Without `CAP_FS_WRITE`, a process still connects to the filesystem and reads
under its role's permissions: stat, read, metadata, and directory listing.
Every other request fails with `NotAllowed` (`PermissionDenied` in `std`),
and the connection stays usable. That includes creating, writing, resizing,
copying into, deleting, moving, and changing permissions of entries,
flushing the filesystem, and all file-lock operations, including unlock.
Denying lock operations is a provisional policy, fixed for now. The runtime
also refuses opens with write, append, create, or truncate intent, even of an
existing file. `CAP_FS_WRITE` does not override filesystem permissions: a
modification needs both the capability and the role's permission.
Without `CAP_FS_WRITE`, `Write::flush` on a read-only `File` is a no-op;
flushing a writable file is denied. Processes with `CAP_FS_WRITE` retain the
native global filesystem flush, including through read-only file handles.

These checks follow the process that talks to sys-io. A file handed to a child
as a standard stream with `Stdio::from(file)` is used through the child's own
connection, so a child without `CAP_FS_WRITE` cannot write to it; `std`'s
`Stdout` and `Stderr` report every write error as success on Motor OS, so
such output is silently lost rather than failing. A child that
inherits a file-backed standard stream writes through its parent's relay,
with the parent's authority. Pipes carry no filesystem authority at all.

## Process roles and filesystem permissions

`ProcessRole::from_caps(mask)` derives the filesystem-facing role from two
bits, in this order:

| Condition | Role | Encoded value |
| --- | --- | --- |
| `CAP_SYS` is set | `System` | 2 |
| Otherwise, `CAP_INTERACTIVE` is set | `Interactive` | 1 |
| Neither bit is set | `None` | 0 |

Both bits may be present; `CAP_SYS` takes precedence without changing the
mask. A None-role process can still hold individual capabilities such as
`CAP_LOG` or `CAP_SPAWN`. Conversely, the Interactive role alone does not
grant logging, spawning, or shutdown authority.

Sys-io obtains a filesystem client's capabilities from the kernel through
the client's IPC connection and uses the derived role for permission checks.
The role selects the corresponding filesystem permission set; it is not
supplied by the client. See [process roles](process-roles.md) for the design
and [filesystem permissions](fs-permissions.md) for the image policy.

## Child capability grants

The kernel validates the requested child mask in
[`Process::new_child`](../src/sys/kernel/src/uspace/process.rs).

- A parent without `CAP_SYS` may grant only capabilities it already holds.
  It may never grant `CAP_SYS` or `CAP_IO_MANAGER`.
- A None-role parent may not grant `CAP_LOG`, even if it holds that bit.
  An Interactive parent can explicitly pass on `CAP_LOG` when it holds it.
- A System parent may grant capabilities it does not itself hold, except
  `CAP_VSOCK`, `CAP_NET`, and `CAP_FS_WRITE`. Every parent must hold each of
  these to grant it, so a process can only narrow them for its descendants.
- Spawning a detached child additionally requires the **parent** to hold
  `CAP_SPAWN_DETACHED`, including when the parent is System.

An unauthorized request fails with `E_NOT_ALLOWED`; the kernel does not
silently remove the forbidden bits. Below System, a child cannot receive a
higher role than its parent.

### Default mask

When no explicit mask is provided, the
[`rt.vdso` spawn path](../src/sys/lib/rt.vdso/src/rt_process.rs) uses
`default_child_capabilities(parent_caps)`:

| Parent's derived role | Default child mask |
| --- | --- |
| `System` | `CAP_SPAWN` and `CAP_LOG`, plus each of `CAP_VSOCK`, `CAP_NET`, and `CAP_FS_WRITE` the parent holds. |
| `Interactive` | `CAP_INTERACTIVE`, plus each of `CAP_SPAWN`, `CAP_VSOCK`, `CAP_NET`, and `CAP_FS_WRITE` the parent holds. |
| `None` | Only the parent's `CAP_SPAWN`, `CAP_VSOCK`, `CAP_NET`, and `CAP_FS_WRITE` bits. |

Defaults from non-System parents are always restricted to bits the parent
holds. Computing a default mask does not bypass the parent's own spawn
authorization.

`CAP_SYS`, `CAP_IO_MANAGER`, `CAP_SHUTDOWN`, and `CAP_SPAWN_DETACHED` never
propagate by default. `CAP_LOG` is included by default only for children of
System parents. A System parent's default child has the None role, even if
the parent also holds `CAP_INTERACTIVE`.

These are runtime defaults. Launchers can select explicit masks: sys-init
does so for configured services, and Rush explicitly preserves System
authority for ordinary commands launched by a System shell. Rush also has a
`spawn-detached` policy for passing detach authority to trusted programs.
These launch chains pass on `CAP_NET` and `CAP_FS_WRITE` where they hold
them. Services get only what they need: the shipped configuration gives the
DNS resolver `CAP_NET` but not `CAP_FS_WRITE`, and strobe the reverse.

An explicit `MOTOR_OS_CAPS` for a Rush process launch, as a command assignment or
an exported variable, suppresses both of Rush's automatic grants and reaches
the runtime unchanged. A command assignment wins over an exported value. For
example, `MOTOR_OS_CAPS=0x2ec rmux` runs rmux without `CAP_NET` and without
Rush's detach grant being applied on top. Assignments before `command` and
`exec` reach the program they run in the same way.

Foreground Rush-compatible scripts with an explicit mask also run in a new
Rush process. Their builtins use the requested capabilities, and unsetting
`MOTOR_OS_CAPS` cannot restore omitted network or filesystem-write authority
to their descendants. Scripts without an explicit mask retain Rush's usual
in-process execution and the shell's capabilities.

A mask requires a real child process. Rush refuses masked functions, `eval`,
`.` (source), other builtins, compound commands, and redirection-only commands
with status 126, before executing their bodies or opening their redirections.
`command` and `exec` can forward a mask to an external program; they cannot make an
in-process builtin honor it. Rush checks for the variable's presence without
parsing or intersecting masks, including empty, zero, and malformed values.

| Invocation | Behavior |
| --- | --- |
| `MOTOR_OS_CAPS=0x44 sh` | Start a shell with the requested capabilities. |
| `MOTOR_OS_CAPS=0x44 ./script.sh` | Run the executable script in a restricted child shell. |
| `MOTOR_OS_CAPS=0x44 eval '...'` | Refuse with status 126. |
| `MOTOR_OS_CAPS=0x44 . ./script.sh` | Refuse with status 126. |
| `MOTOR_OS_CAPS=0x44 function_name` | Refuse with status 126. |

The same rule applies to exported masks. All builtins, including `exit`,
`return`, `break`, `continue`, `wait`, `unset`, and `trap`, are refused while a
mask is exported; `if`, loops, and other compounds are refused too. A refusal
returns 126 and follows ordinary shell error handling: without `set -e`,
execution can continue past a refused `exit`, and a refused `wait` does not
wait. In-process commands in EXIT traps are subject to the same rule.
Prefer a command assignment. Rush's emulated subshells do not isolate general
exported-variable changes; use a separate shell process when an export must
not affect the caller. An assignment before `exec` is temporary even when
Rush emulates that invocation inside a background job or substitution.
Bare variable assignments without redirections remain ordinary shell setup.
The runtime consumes the mask when creating the child, so the refusal rule no
longer blocks functions, sourcing, and builtins inside the restricted shell.
Their operations still require the appropriate capabilities. Rush currently
stages pipelines and command substitutions through temporary files, requiring
`CAP_FS_WRITE`. If staging fails, the pipeline or substitution returns status 2;
it does not fall back to the shell's stdin/stdout or report an empty success.
For example, `MOTOR_OS_CAPS=0x44 sh -c 'x=$(printf hi)'` fails with status 2.

Refusal occurs when Rush reaches the offending invocation; it does not scan
an entire script in advance. Command-line expansions and the redirections of
permitted child launches still run with the calling shell's authority. To
restrict a whole shell body, put it inside `MOTOR_OS_CAPS=0x44 sh -c '...'`.

### Explicit mask with `std::process::Command`

Set `MOTOR_OS_CAPS_ENV_KEY` (`"MOTOR_OS_CAPS"`) in the child's command
environment to replace the entire default mask. The value is hexadecimal,
with an optional lowercase `0x` prefix. For example, `"44"` and `"0x44"`
both mean `CAP_SPAWN | CAP_INTERACTIVE`; `"0"` requests no capabilities.
Invalid hexadecimal or a value that does not fit in `u64` fails with
`E_INVALID_ARGUMENT`.

This helper launches a None-role child that can spawn further children,
assuming the caller is authorized to spawn and grant `CAP_SPAWN`:

```rust
use moto_sys::caps::{CAP_SPAWN, MOTOR_OS_CAPS_ENV_KEY};
use std::process::{Child, Command};

fn spawn_worker(program: &str) -> std::io::Result<Child> {
    Command::new(program)
        .env(MOTOR_OS_CAPS_ENV_KEY, format!("{CAP_SPAWN:#x}"))
        .spawn()
}
```

An explicit mask is a replacement, not an addition: omitting
`CAP_INTERACTIVE` drops Interactive authority; omitting `CAP_VSOCK`,
`CAP_NET`, or `CAP_FS_WRITE` denies that access even if the parent holds it.
The worker above therefore can read files but neither write them nor use
the network. The runtime consumes
`MOTOR_OS_CAPS`, so the child does not receive this environment variable.
The child's later spawns use their own defaults or explicit masks.

## Detached children

To request a detached child, set `MOTOR_OS_DETACHED_ENV_KEY`
(`"MOTOR_OS_DETACHED"`) to exactly `"true"` or `"TRUE"` in its command
environment. Other values do not request detachment. The runtime consumes
the variable regardless of its value; the child does not receive it.

The kernel owns a detached child, allowing it to survive the spawner's exit
and reaping. Ordinary non-System children are killed when their parent is
reaped. Detachment is separate from the child's capability mask:

- The spawner must hold `CAP_SPAWN_DETACHED` to request detachment.
- The child does not need that bit merely to be detached.
- Giving a child `CAP_SPAWN_DETACHED` permits it to detach its own children;
  it does not detach that child automatically.

For example, a caller with `CAP_SPAWN | CAP_SPAWN_DETACHED` can launch a
detached worker with no capabilities:

```rust
use moto_sys::caps::{MOTOR_OS_CAPS_ENV_KEY, MOTOR_OS_DETACHED_ENV_KEY};
use std::process::{Child, Command, Stdio};

fn spawn_detached_worker(program: &str) -> std::io::Result<Child> {
    Command::new(program)
        .env(MOTOR_OS_CAPS_ENV_KEY, "0x0")
        .env(MOTOR_OS_DETACHED_ENV_KEY, "true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}
```

The null standard streams avoid depending on the launching process for IO.
Grant detach authority explicitly only when the child must be able to
create further detached processes; it is absent from every default mask.

## Querying capabilities

A process can read its own mask without a syscall from the read-only
[`ProcessStaticPage`](../src/sys/lib/moto-sys/src/shared_mem.rs):

```rust
let caps = moto_sys::ProcessStaticPage::get().capabilities;
let role = moto_sys::caps::ProcessRole::from_caps(caps);
let can_spawn = caps & moto_sys::caps::CAP_SPAWN != 0;
```

For a connected peer, use
[`SysObj::get_capabilities(handle)`](../src/sys/lib/moto-sys/src/sys_obj.rs).
This syscall returns the mask of the process owning the peer endpoint of
the shared object. Servers should authorize the actual connected peer using
this kernel-supplied value, as sys-io and strobe do.

Process statistics expose the derived role through
`ProcessInfoV1.process_role`, not the full capability mask. Statistics are
for observation; use the connection-bound capability query for peer
authorization.
