# Network and filesystem-write capabilities

Status: implemented, following the plan below. This document describes the
behavior, code boundaries, patch sequence, and validation as reviewed; see
[process capabilities](../caps.md) for the resulting policy.

Decisions and instructions incorporated from U. Lasiotus's inline review
are attributed at the relevant sections below.

## Purpose

Add two process capabilities so a parent can restrict a child's access to
sys-io independently of its filesystem role:

| Capability | Proposed bit | Hex mask | Authority |
| --- | --- | --- | --- |
| `CAP_NET` | 8 | `0x100` | Access sys-io's network API. |
| `CAP_FS_WRITE` | 9 | `0x200` | Request filesystem modifications and file-lock operations through sys-io. |

Bits 0 through 7 are already defined in
[`moto_sys::caps`](../../src/sys/lib/moto-sys/src/caps.rs). The proposed bits
fit in the existing immutable `u64` capability word; no separate process
privilege state is needed. See [process capabilities](../caps.md) for the
current model.

Both capabilities should be inherited by default when `MOTOR_OS_CAPS` is
unset, provided the parent holds them. Existing explicit launch policies in
code (launch chains that lead to shells and sessions) must include both bits
where the parent holds them, so interactive use keeps its current behavior.
Service grants in `sys-init.cfg` are narrowed to what each service needs;
see [Existing explicit masks](#existing-explicit-masks). A caller can
deliberately omit either bit from an explicit mask to restrict the child and
its descendants.

Without `CAP_NET`, sys-io must drop the client's connection before serving
any network command. The initial shared IPC connect may succeed; it does not
authorize network access. Without `CAP_FS_WRITE`, the client may still
connect to the FS API and perform reads, but sys-io must deny filesystem
modifications and all file-lock operations.

Neither bit changes `ProcessRole::from_caps`. Having `CAP_FS_WRITE` does not
override filesystem permissions: a modification requires both the capability
and the existing role-based permission checks. Neither `CAP_SYS` nor
`CAP_INTERACTIVE` substitutes for either new bit at the sys-io boundary.

## Defaults and explicit grants

The default mask is computed by `default_child_capabilities` in
[`caps.rs`](../../src/sys/lib/moto-sys/src/caps.rs). The
[`rt.vdso` spawn path](../../src/sys/lib/rt.vdso/src/rt_process.rs), in
`run_elf`, replaces that mask when it finds `MOTOR_OS_CAPS` and consumes the
variable before starting the child. Keep the explicit-mask semantics: a
valid hexadecimal value is the complete requested mask, including zero.
Do not unconditionally add the new bits after parsing an explicit mask.

### Inheritance from a restricted parent

**Decision from U. Lasiotus:** capabilities may only be narrowed when
spawning; a process without `CAP_NET` or `CAP_FS_WRITE` cannot grant the
missing capability to a child. The kernel must enforce this restriction.

For each new bit, a child may receive it only if its parent holds it. This
applies to both default and explicit masks, including children of System
parents. Leaving `MOTOR_OS_CAPS` unset cannot restore a missing bit. An
explicit request to grant a missing bit fails with `E_NOT_ALLOWED`.

The default helper must preserve this restriction for every parent role:
include each new bit only when it is present in the parent's mask. Ordinary
launch chains retain both after the explicit-mask updates below, while
restricted descendants inherit the restriction without a failed default
spawn.

[`Process::new_child`](../../src/sys/kernel/src/uspace/process.rs) already
enforces a subset rule for non-System parents and separately requires every
parent to hold `CAP_VSOCK` before granting it. Apply the same unconditional
parent-ownership requirement to `CAP_NET` and `CAP_FS_WRITE`, before the
System exemption for other grants. This enforces the decision even when a
caller bypasses rt.vdso. The absence of either bit also denies the System
parent's own corresponding sys-io operations.

### Existing explicit masks

Every existing policy that constructs an explicit mask must account for both
new bits. Updating the default helper alone would leave these processes
restricted unintentionally. The two kinds of setter are updated differently:

- In code already computing `own_caps & allowed_caps` (russhd and Rush),
  extend `allowed_caps` with the new bits. In masks assembled by OR-ing
  individual grants (sys-init and sys-tty), add the bits the child needs as
  `own_caps & (...)`, never a bare literal. Both forms prevent a restricted
  launcher from requesting a bit it lacks. Under least privilege, sys-init
  grants strobe `CAP_FS_WRITE` only (it writes log files and uses no
  network) and grants sys-tty both bits, because the console shell and
  everything it launches descend from sys-tty.
- Configuration literals in `sys-init.cfg` are passed through by sys-init,
  which holds an all-ones mask, so they are rewritten by hand. Only the bits
  a service needs are added (see the examples below).

| Source | Existing grants affected |
| --- | --- |
| [sys-io startup](../../src/sys/sys-io/src/main.rs) | The all-ones grant to sys-init already includes both proposed bits. |
| [sys-init](../../src/sys/sys-init/src/main.rs) | The sys-tty grant, the strobe grant, and masks passed through `spawn_service`. |
| [sys-tty](../../src/sys/sys-tty/src/main.rs) | The console command's explicit mask. |
| [russhd](../../src/bin/russhd/src/local_session.rs) | The session mask intersected with the daemon's own capabilities. |
| [Rush](../../src/bin/rush/src/sys/motor.rs) | Extend `ordinary_child_cap_grant` and `detach_cap_grant`; fix [`jobs.rs`](../../src/bin/rush/src/jobs.rs) so explicit masks take precedence over both automatic grants. |
| [main image config](../../img_files/motor-os/system/cfg/sys-init.cfg), [base image config](../../img_files/motor-os-base/system/cfg/sys-init.cfg), [System-console test config](../../img_files/test-system-tty/system/cfg/sys-init.cfg), [vsock test config](../../img_files/test-vsock/system/cfg/sys-init.cfg) | Service masks and explanatory examples/comments, including DNS and SSH service grants. The developer image has no config of its own. |
| [systest sources](../../src/sys/tests/systest/src/main.rs) and [test scripts](../../src/tests/full-test.sh) | Explicit test launches, helper-generated masks, and expectations that compare complete capability words. |

**Decision from U. Lasiotus:** service grants follow least privilege. The
DNS resolver gets `CAP_NET` only: its configured mask `8` becomes `264`
(`0x108`), not `776`, because the resolver never modifies the filesystem.
russhd gets both bits, since in-process SFTP writes files: `252` becomes
`1020`. The commented-out stats-registry example (`svc:8`) needs neither
bit and keeps `8`. A shell/test mask `0xcc` becomes `0x3cc`. A None-role
test mask `0x0` becomes `0x300` when its purpose is to test the role rather
than the absence of the new capabilities. None remains the derived role
because neither new bit is a role bit.

The existing setter inventory also includes systest's `logging.rs`,
`diagnostics.rs`, `spawn_wait_kill.rs`, `admission.rs`, `stdio_file_input.rs`,
`net_driver.rs`, and `fs_permissions.rs`; and the scripts `test-sftp.sh`,
`stress-soak.sh`, `full-test-networking.sh`, `test-terminal-size.sh`,
`test-system-tty.sh`, `test-vsock.sh`, and `test-vsock-outgoing.sh`.
Documentation and developer-image examples that show masks/defaults need to
stay consistent with the new policy. The unit test in `caps.rs` that asserts
exact default words for an all-ones parent must be updated for the new bits.

These are changes to existing built-in launch policies and test inputs.
Explicit masks supplied by a user or service configuration must remain exact;
launchers must not silently widen an intentional restriction. Existing
parent-mask intersections must preserve the inheritance restriction above,
and launch policies must not request either new bit from a parent lacking it.
Malformed-mask tests must remain malformed, and tests of older capability
restrictions must continue to exercise those restrictions. New tests for
these capabilities will deliberately omit the relevant bits.

**Review correction requested by U. Lasiotus:** Rush must preserve explicit
masks for ordinary and trusted detached programs. Currently `jobs::spawn`
applies the detached-program grant after command assignments, overwriting
them. Its ordinary System grant checks only command assignments and can
overwrite an exported mask. Extending these grants without fixing their
precedence would silently restore omitted capabilities, for example in
`MOTOR_OS_CAPS=0x44 rmux`. The kernel cannot prevent this because the shell
holds the bits it requests.

A command assignment takes precedence over an exported value; either
suppresses both automatic grants. If neither exists, prefer the existing
detached-program grant, then the ordinary grant, then the runtime default.
Pass explicit values through unchanged, including zero and malformed values;
rt.vdso and the kernel already validate them. Use a presence check, with no
mask parser or merging. An explicit mask that omits detach authority also
forgoes the automatic detach grant.

Rush follow-up: a mask supplied by an assignment or export requires a real
child process. Executable shell scripts use a child Rush; functions, `eval`,
source, and other in-process commands are refused with status 126 before their
bodies or redirections run. `command` and `exec` may forward a mask to an
external program. This remains a presence-only check; no function capability
ceiling, mask parser, or intersection is needed. See `docs/caps.md` for shell
setup and command-line expansion behavior.

## Network API admission

Follow-up: the DNS resolver is another network service boundary. It must check
the kernel-reported capabilities of its sync IPC peer before resolving a
request, since its own sockets are authorized with its own `CAP_NET`.
Unauthorized requests return `NotAllowed`; numeric/localhost parsing that
does not contact the resolver remains available. The resolver self-test covers
raw IPC and `std::net::ToSocketAddrs` denial without issuing network queries.

The network endpoint is `"sys-io"`. Its server is `NetRuntime::net_listener`
in [`runtime/net.rs`](../../src/sys/sys-io/src/runtime/net.rs). Currently,
the listener admits a channel into `clients` after resource checks, while
peer capabilities are queried lazily for vsock authorization.

The proposed admission rule is to obtain the actual peer's capability word
through `SysObj::get_capabilities(sender.remote_handle())` before registering
or serving a network client. If the query fails or `CAP_NET` is absent, drop
the connection without admitting the client or dispatching any network
command. A request's claimed PID, role, or mask is never an authorization
source. The admitted mask can be cached for the connection because process
capabilities are immutable; existing vsock checks can use the same value.

This gate covers the entire network protocol in
[`api_net.rs`](../../src/sys/lib/moto-sys-io/src/api_net.rs): TCP, UDP, ICMP,
loopback networking, and virtio-vsock, including discovery queries.

**Decision from U. Lasiotus:** `CAP_VSOCK` requires `CAP_NET` to function.
Vsock operations therefore require both bits; holding `CAP_VSOCK` alone
cannot bypass the connection gate. No socket, listener, port or listener
reservation, channel-budget admission, or network IO should be created for a
denied client.

### Sys-io enforcement after IPC establishment

**Decision from U. Lasiotus:** sys-io enforces network admission by dropping
unauthorized connections after the initial connect. Keep this enforcement
out of the kernel. The client may observe a disconnected error rather than
`NotAllowed`; that outcome is explicitly acceptable and supersedes the
earlier requirement to report `NotAllowed` for this admission failure.

The existing transport matters to the meaning of "cannot open a connection":

- [`io_channel::ClientConnection::connect`](../../src/sys/lib/moto-ipc/src/io_channel.rs)
  returns after the kernel links the shared channel. It does not wait for
  sys-io to authorize the peer.
- [`moto_io::net::connect`](../../src/sys/lib/moto-io/src/net/channel.rs)
  immediately wraps that channel in a `NetClient`/`NetDriver` pair.
- [`IcmpEchoClient::connect`](../../src/sys/lib/moto-sys-io/src/icmp.rs)
  uses the raw channel directly, as do protocol tests.

A check after `listen().await` protects dispatch while allowing the initial
raw connection to succeed. The client may therefore receive a connection
object and then discover that sys-io has disconnected it. This is the chosen
behavior, including for clients that use the raw protocol directly. Keep
the existing connection-establishment behavior; no kernel shared-object
admission check, client-side precheck, or new authorization handshake is
part of this design.

Do not translate the resulting disconnect into `NotFound` or
`OutOfMemory`, or add a retry path for a capability-denied connection.
The current `NetRuntime::refuse_client` specifically reports resource
exhaustion and is not the capability-denial path; a denied connection is
simply dropped.

**A denial must not take the listener backoff path.** In
`NetRuntime::spawn_new_listener`, an `Err` from `net_listener` means a slot
that did not turn into a served client because of resource exhaustion, and
the slot is re-armed only after exponential backoff (10 ms, 100 ms, then
1 s). If a capability denial returned `Err` the same way, a restricted
process that repeatedly opened sockets would stall accepts for authorized
clients. Instead, a denied peer is handled like a served one for pool
purposes: `net_listener` calls `spawn_new_listener` to replenish the accept
pool, drops the channel, and returns `Ok(())`. The check runs after the
armed-listener floor and memory-pressure refusals (so sys-io's own
protection still comes first) and before `channel_budget.admit_net`, so a
denied client never holds a budget slot or a `clients` entry.

Native network RPC waiters are failed with `E_NOT_CONNECTED` by
[`NetChannel::fail_rpc_waiter`](../../src/sys/lib/moto-io/src/net/channel.rs).
Raw IPC and ICMP clients can instead expose lower-level handle/wait errors.
`moto_io::net::connect` may return successfully before the denial; its
`NotFound` retry loop does not itself prove that a subsequent operation
completes promptly. Test both native and raw-client completion without
requiring every interface to expose the same error code.

The [rt.vdso connection pool](../../src/sys/lib/rt.vdso/src/net/pool.rs)
can share channels between calls and provision new ones after teardown.
There is no exact one-accept-per-socket-call guarantee. Rejected connections
must release their resources and must not trigger automatic denial retries;
repeated caller attempts still cost admission work. This is not a rate
limit. Tests should verify terminal errors, resource cleanup, and continued
service for authorized clients under bounded repeated denials.
The existing resource-pressure refusals retain their own error behavior.

## Filesystem request authorization

The FS endpoint remains `"sys-io-fs"`, defined by `api_fs::FS_URL` in
[`api_fs.rs`](../../src/sys/lib/moto-sys-io/src/api_fs.rs). Absence of
`CAP_FS_WRITE` must not prevent connection or otherwise-authorized reads.

[`fs_listener`](../../src/sys/sys-io/src/runtime/fs.rs) already queries the
peer's capabilities and derives the role before dispatching requests. Keep
both the derived role and whether the peer holds `CAP_FS_WRITE` as immutable
connection context. The existing failure to query a peer remains a reason
to refuse that connection; it is not equivalent to a known read-only peer.

Enforce the capability restriction centrally in `on_msg`, before invoking a
mutating or file-lock handler or acquiring filesystem state for that
operation. Existing filesystem role/permission checks still run for
permitted requests. The current command surface divides as follows:

| Operation | FS commands | Without `CAP_FS_WRITE` |
| --- | --- | --- |
| Read and inspect | `CMD_STAT`, `CMD_STAT_PATH`, `CMD_READ`, `CMD_METADATA`, `CMD_GET_FIRST_ENTRY`, `CMD_GET_NEXT_ENTRY`, `CMD_GET_NAME` | Allowed subject to existing permissions and resource checks. |
| Create entries | `CMD_CREATE_FILE`, `CMD_CREATE_DIR`, `CMD_CREATE_WITH_PERMISSIONS` | Denied. |
| Modify file contents or size | `CMD_WRITE` in both single-page and multi-page forms, `CMD_RESIZE` | Denied. |
| Copy into a destination | `CMD_COPY_FILE_RANGE` | Denied, including copies performed entirely by the server. |
| Modify directory entries | `CMD_DELETE_ENTRY`, `CMD_MOVE_ENTRY`, `CMD_MOVE_NOREPLACE` | Denied. |
| Modify permissions | `CMD_SET_PERMISSIONS`, `CMD_SET_ALL_PERMISSIONS` | Denied, including requests from System-role clients. |
| Flush filesystem state | `CMD_FLUSH` | Denied with `NotAllowed`. |
| Advisory file locking | `CMD_FILE_LOCK`, including lock, try-lock, and unlock | Denied with `NotAllowed`; provisional policy fixed for this work. |

**Decision from U. Lasiotus:** `CMD_FLUSH` returns `NotAllowed` for clients
without `CAP_FS_WRITE`. `on_cmd_flush` currently flushes the whole filesystem,
including dirty state created by other clients; a restricted client may not
request that writeback.

**Provisional decision from U. Lasiotus:** deny all FS locking operations
for clients without `CAP_FS_WRITE`. This covers shared and exclusive locks,
blocking and nonblocking acquisition, and explicit unlock requests. Check
the capability before `on_cmd_file_lock`, including its unlock fast path.
Automatic cleanup on connection teardown remains server housekeeping, not
a client locking operation.

Locks change transient coordination state rather than persisted filesystem
contents, so this policy may be reconsidered in separate future work. It
must **not** be reopened while designing or implementing the new
capabilities.

A capability denial should return `moto_rt::Error::NotAllowed`
(`E_NOT_ALLOWED`, surfaced as `std::io::ErrorKind::PermissionDenied`) while
keeping the FS connection available for later reads. Refused mutations must
not partially change contents, lengths, names, or permissions. Denial should
happen before the ordinary memory-pressure gate so a forbidden modification
is reported as an authorization failure.

Requests may donate shared IO pages. An early denial must release them via
the existing `api_fs::release_donated_pages` helper, just as the current
memory-pressure refusal does. This includes multi-page writes and
page-carrying create/rename requests. Unknown commands remain protocol
errors; every future command needs an explicit read/write classification.

### File opens and the enforcement boundary

**Instruction from U. Lasiotus:** rt.vdso must read the caller's capabilities
from `moto_sys::ProcessStaticPage` and deny opening files for write when
`CAP_FS_WRITE` is absent. The page is available to every process without a
syscall; see
[`ProcessStaticPage::get`](../../src/sys/lib/moto-sys/src/shared_mem.rs).

There is no FS `OPEN` command. `AsyncFsClient::file_open` in
[`rt_fs.rs`](../../src/sys/lib/rt.vdso/src/rt_fs.rs) resolves a path and
constructs a local file object; create and truncate options issue separate
mutating RPCs. Add the capability check before returning a writable file
object or issuing any create/truncate request. Write intent includes
`O_WRITE` and `O_APPEND`; create and truncate requests (`O_CREATE`,
`O_CREATE_NEW`, and `O_TRUNCATE`) also require `CAP_FS_WRITE`. Deny these
opens with `NotAllowed` even when the file already exists and opening it
would not immediately modify its contents. Read-only opens and executable
loading remain possible under the usual permissions.

The rt.vdso check provides the required early error for normal file opens.
Sys-io must still independently deny modifications from clients that bypass
rt.vdso and send the FS protocol directly.

These capabilities authorize the process at the sys-io connection. They do
not revoke another process's authority when it receives work through a
separate service or an inherited pipe. Existing role checks and service
authorization remain separate from these two gates.

File-backed stdio has two paths in
[`stdio.rs`](../../src/sys/lib/rt.vdso/src/stdio.rs). Explicitly passing an
open file with `Stdio::from(file)` gives the child a snapshot (entry id,
offset, and access mode). The child uses its own FS connection, so its
capabilities govern the IO. Inheriting an existing file-backed standard
stream instead goes through `prepare_inherited_stdio`, which creates a
parent-side relay using the parent's FS connection and capabilities.

Rush passes a solely-used redirect target as an explicit file. Thus
`restricted_cmd > out.txt` is denied at the child's filesystem writes with
`NotAllowed` (`PermissionDenied`). The current Motor stdlib suppresses stdout
and stderr errors, so Rust printing can silently lose output and exit zero;
this is an error-reporting defect, not permission to write. Native write-error
checks cover the actual denial while the external stdlib fix is tracked
separately. The shell can still create or
truncate `out.txt` before spawning the child; those are the shell's own
operations. `restricted_cmd < in.txt` remains readable under the usual
permissions, and pipe-backed output remains usable. An inherited file relay
can write when its parent has the necessary authority even if the child
lacks `CAP_FS_WRITE`. These outcomes follow authorization of the actual
sys-io peer. Keep the existing stdio paths; do not make Rush interpret masks
or select a different output path based on them.

## Scope and review

The intended changes are within the main Motor OS repository: capability
definitions and defaults, explicit launch policies, sys-io authorization,
rt.vdso file-open checks, kernel enforcement of the new bits' inheritance
restrictions, and the associated documentation and tests. No Rust stdlib,
moto-rt, or external dependency changes are proposed. Network admission stays
in sys-io; the kernel changes are for capability inheritance, not shared IPC
connection authorization.

The design should reuse the existing FS peer query and perform network
authorization once per connection. It should add no startup scan, background
task, or new boot-time handshake. Any chosen approach that adds boot work
needs review before implementation.

The implementation plan below is for review before code changes begin.

## Review status

All review questions (network admission after connect, file-lock policy,
listener-pool handling of denied peers, and least-privilege service grants)
have been answered by U. Lasiotus and incorporated above. The plan retains
the shorter sequence, least-privilege strobe grant, and focused test matrix.
U. Lasiotus requested the subsequent review corrections: restore explicit
mask precedence in Rush, distinguish file snapshots from inherited relays,
and retain idle-peer and System-role network denial tests without claiming
that progress alone proves the absence of listener backoff. The settled
locking policy is not to be reopened during this work.

## Implementation plan

Six steps, each one or more patches of roughly 100–300 changed lines
including tests. Keep a launch-mask change and its exact-mask test
expectations in the same patch. No gate is enabled while a required grant is
still missing. Ordinary cases run inside systest, which `full-test.sh`
launches over SSH; System-role cases run from
[`test-system-tty.sh`](../../src/tests/test-system-tty.sh), which the full
test also runs, because an SSH session cannot grant `CAP_SYS`. New systest
child modes must dispatch before the normal full run. Hygiene and gates
(`cargo fmt`, no new clippy warnings, the debug and release full tests three
times each, the release developer-image test, no retries or weakened
assertions) are as in `AGENTS.md`. No commits are authorized by this plan.

### 1. Define the bits and default inheritance

1. Add `CAP_NET = 1 << 8` and `CAP_FS_WRITE = 1 << 9` in
   [`caps.rs`](../../src/sys/lib/moto-sys/src/caps.rs), documenting sys-io
   admission, write/lock denial, and the unconditional parent-ownership rule.
2. In `default_child_capabilities`, keep the role rules and replace the
   single-bit vsock conditional with
   `parent_caps & (CAP_VSOCK | CAP_NET | CAP_FS_WRITE)`. This is equivalent
   for vsock under the existing non-System intersection. No System special
   cases, and no change to explicit-mask parsing in rt.vdso.
3. Update the host unit test: a System parent with neither bit, with each
   bit, and all-ones; Interactive and None parents with and without the
   bits. Assert unchanged role, logging, vsock, and detach defaults.

### 2. Migrate launch grants and existing tests coherently

1. Before extending Rush's automatic grants, fix `jobs::spawn` to suppress
   both grants when `MOTOR_OS_CAPS` is present in the command assignments or
   exported environment. Command assignments still win over exported values.
   Without an explicit value, prefer the detached grant, then the ordinary
   grant, then the runtime default. Preserve explicit values byte-for-byte;
   do not parse them or add detach authority.
2. Update sys-init's sys-tty grant (both bits) and strobe grant
   (`CAP_FS_WRITE` only), sys-tty's console grant, russhd's session grant,
   and Rush's two automatic grants using the parent-mask rules above.
   Explicit user and configuration masks stay exact.
3. Update configuration literals: DNS `8` to `264`, russhd `252` to `1020`;
   the stats-registry example stays `8`. Keep the comments in the main,
   base, and test-image configs consistent. The developer image shares the
   base configuration.
4. Update `FULL_RUN_CAPS`, explicit test masks, expected defaults, shell
   scripts, and documentation examples together with the grants they test.
   The full-run mask `0xcc` becomes `0x3cc`, the detach-capable stdio suite
   mask `0xec` becomes `0x3ec`, the DNS launches in `full-test.sh`,
   `full-test-networking.sh`, and `stress-soak.sh` become `0x108`, and the
   System-console script's masks gain the bits their cases need. Existing
   role, logging, and vsock denial cases keep both new bits unless the new
   restriction is their subject. Update
   [`admission.rs`](../../src/sys/tests/systest/src/admission.rs)
   expectations without changing the memory-admission assertions.
5. Add a Rush regression that reports the child's actual
   `ProcessStaticPage.capabilities`. Copy the systest probe to a private
   temporary directory under the trusted basename `rmux`, with read/execute
   permissions, to exercise the shipped policy without launching rmux or
   editing its configuration. Verify explicit masks omitting each new bit
   and both, zero, an exported mask, a command assignment overriding an
   export, and malformed input reaching spawn validation. Without a mask,
   the automatic grant still applies and cannot supply bits the shell lacks.
   Use a dedicated systest mode launched by `full-test.sh` with `0x3ec`:
   ordinary full-run systest lacks detach authority. Use the System-console
   fixture with an ordinary probe name to cover exported-mask precedence
   over the ordinary System grant too. Keep the Rush host suite in the gate.
6. Re-run the setter inventory (`rg 'MOTOR_OS_CAPS' src img_files`) and the
   current full gate before enabling either IO gate.

### 3. Enforce narrowing in the kernel

1. In [`Process::new_child`](../../src/sys/kernel/src/uspace/process.rs),
   extend the unconditional vsock ownership check to all three bits: reject
   with `E_NOT_ALLOWED` when
   `child_caps & !parent_caps & (CAP_VSOCK | CAP_NET | CAP_FS_WRITE) != 0`,
   before the non-System grant rules. Do not clamp the request.
2. Extend the spawn probes in
   [`spawn_wait_kill.rs`](../../src/sys/tests/systest/src/spawn_wait_kill.rs):
   for each new bit, a child spawned without it cannot regain it explicitly
   and does not receive it by default, and the failed explicit spawn never
   starts the child. Keep `CAP_SPAWN` in the child so the probe reaches the
   kernel check. Compare the child's actual
   `ProcessStaticPage.capabilities`, not just exit status.
3. Repeat the explicit regain attempt once from the System-console fixture,
   which catches placing the check inside the non-System branch. System
   children must exit normally; they cannot be killed for cleanup.

### 4. Enforce FS capability checks and write-intent opens

1. In [`fs_listener`](../../src/sys/sys-io/src/runtime/fs.rs), derive a
   `can_write` boolean from the same successful peer-capability query as the
   role and pass both to `on_msg`. No extra syscall, PID lookup, or mutable
   cache.
2. Add one early gate before the memory-pressure gate: a client without the
   bit may issue only the seven read/inspection commands listed above. For
   any other `api_fs::known_cmd`, release donated pages with
   `release_donated_pages`, reply `NotAllowed` via `empty_resp_encode`, and
   return. Unknown commands keep the `InvalidData` path. A read allowlist is
   safer than a list of mutating commands: a newly added command is denied
   to restricted peers until deliberately allowed. All `CMD_FILE_LOCK`
   operations, including unlock, hit this gate; disconnect cleanup is
   unchanged.
3. In [`AsyncFsClient::file_open`](../../src/sys/lib/rt.vdso/src/rt_fs.rs),
   after the existing flag validation and before path lookup, reject write,
   append, create, create-new, and truncate intent with `NotAllowed` when
   `ProcessStaticPage::get().capabilities` lacks `CAP_FS_WRITE`. One bit
   test over the open flags; no new syscall.
4. Tests, in
   [`fs_permissions.rs`](../../src/sys/tests/systest/src/fs_permissions.rs),
   with a parent-created fixture whose role permissions allow the operations:
   - Through `moto_io::fs::FsClient`, which bypasses rt.vdso's open check,
     one denied call per command outside the allowlist (both write forms,
     resize, the three create forms, delete, both moves, copy, both
     permission setters, flush, lock, try-lock, unlock), each followed by a
     read on the same connection to show it stays usable. Use raw encoders
     only where the client does not expose a format.
   - The same fixture with the capability as the positive control, and one
     denied write from a System child without the bit, run from the
     System-console mode, to show `CAP_SYS` does not substitute.
   - After the denials, the parent verifies bytes, lengths, entries, and
     permissions are unchanged.
   - More denied page-carrying writes than the channel's page capacity, then
     one valid request: a leaked donated page shows up as an allocation
     failure without any counters.
   - Through `OpenOptions`: write, append, and truncate on an existing file
     and create on a missing one fail with `PermissionDenied` and leave no
     entry or change; a read-only open succeeds.
   - A restricted child given an explicit file as stdout fails to write it;
     the same child with a pipe as stdout succeeds. Also give an authorized
     helper file-backed stdout and have its restricted child inherit that
     stream: the parent's existing relay can write. Verify the resulting
     bytes to distinguish the two file paths. Fixture creation/truncation
     by the authorized parent is outside the denied child operation.

### 5. Enforce network admission

1. In [`NetRuntime::net_listener`](../../src/sys/sys-io/src/runtime/net.rs),
   query peer capabilities after the armed-listener-floor and
   memory-pressure refusals and before `channel_budget.admit_net`. A failed
   query or a missing `CAP_NET` takes one branch: call `spawn_new_listener`
   once, drop both channel halves, return `Ok(())`. Do not call
   `refuse_client`, insert a client, take a budget slot, or process
   requests. Inspect the return paths to verify that capability denial
   cannot enter `spawn_new_listener`'s `Err` backoff branch or also reach
   the authorized path's replenishment.
2. Pass the capability word into `ClientConnection::new` and store a plain
   `u64`, replacing the lazy `Option<Result<..>>` used by the two vsock
   checks. Admission already proved the query succeeded.
3. Tests, in the existing systest network modes, each with a fixed deadline
   where a timeout is a failure:

   | Case | What it proves |
   | --- | --- |
   | Restricted child, native TCP connect on loopback | A prompt terminal error (`NotConnected` for native RPCs), no hang. |
   | Restricted child, raw `io_channel` connect, first RPC | The same for clients that bypass the library. |
   | Restricted child, raw connect without sending a request | Sys-io drops an idle denied peer without waiting for its first RPC; observe peer closure within the deadline. |
   | System child without `CAP_NET`, using the System-console fixture | `CAP_SYS` does not bypass network admission; the request fails and the child exits normally. |
   | More sequential denials than `NUM_LISTENERS`, while an authorized sibling exchanges loopback data | Denials complete and authorized traffic continues within the deadline. This alone does not prove that backoff was never entered. |
   | `CAP_VSOCK` without `CAP_NET`, and `CAP_NET` without `CAP_VSOCK` | The stored word feeds the vsock check: the first is dropped, the second serves TCP and answers vsock with `NotAllowed`. |

   TCP, UDP, ICMP, and vsock discovery share the one admission branch, so
   one protocol suffices for protocol coverage. Keep the native/raw client,
   idle-peer, and System-role cases because they exercise distinct lifecycle
   or authority requirements. Do not remap errors so every client reports
   one code or introduce tight timing assertions to infer the backoff path;
   verify that branch directly in step 1 above.

### 6. Documentation

Update `docs/caps.md`, the current-policy sections of
`docs/process-roles.md` and `docs/vsock.md`, and the image config comments.
Document Rush's explicit-mask precedence, that a raw net connect may succeed
before denial, and which process performs IO for file snapshots versus
inherited file relays. Keep the locking policy marked provisional but fixed
for this work.

### Corner cases: prefer the smaller mechanism

| Corner case | Simple handling and why |
| --- | --- |
| Explicit mask on an ordinary or trusted detached program | Preserve the exact value; a command assignment wins over an export, and either suppresses automatic grants. A presence check suffices; do not parse or merge masks. |
| System parent lacks a new bit | The same kernel bitmask check applies before the System exemption. No role-specific grant table is needed. |
| `CAP_VSOCK` is set without `CAP_NET` | Keep the mask valid but unusable for networking. Deny at net admission instead of normalizing masks or rejecting unrelated spawns. |
| Peer caps cannot be queried | Drop the net/FS connection. Do not cache a failure as an authorized or read-only identity, retry the query, or fall back to PID lookup. |
| Net peer is denied after raw connect succeeds | Close it and preserve the existing listener lifecycle. No admission handshake, client denial cache, new backoff mode, or kernel endpoint ACL. |
| FS request uses pages but is refused before decoding | Reuse the existing donated-page cleanup helper. Do not duplicate wire parsing or build a new ownership layer. |
| Known FS command is not on the read allowlist | Require the capability, including zero-length writes and no-op resizes. Avoid exceptions based on whether a request might change data. |
| Invalid FS command or invalid open flags | Keep the existing protocol/argument error path. Permission checks must not become a new input-normalization scheme. |
| Locks, unlock, and flush on a restricted connection | Deny uniformly. Do not special-case shared locks, track historical write ownership, or reopen the provisional policy. |
| Parent or another service performs IO on behalf of a child | Authorization follows the actual sys-io peer. Pipes and relays are the parent's IO; a file-backed stdio snapshot is the child's. No transitive IPC tracking. |
| Concurrent tests need synchronization | Use existing IPC readiness and completion signals with fixed test deadlines. Do not add sleeps, production timeouts, or retries to conceal races. |
