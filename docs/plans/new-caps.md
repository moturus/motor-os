# Network and filesystem-write capabilities: follow-ups

## Resolve before rmux or further IPC work

Go through this list before starting the rmux transport or other IPC changes.
It is ranked from most to least severe. Line numbers are as of the IPC
prerequisite commit.

1. **High.** Phantom endpoints disable sync-IPC services. When `map_shared`
   fails in `get`, the popped listener becomes a phantom "connected" endpoint
   that `LocalServer` keeps in `active_conns` for the rest of the server's
   life. Any process can cause this by connecting with an address that is not
   a mapped page. After `max_connections` of these, the server stops refilling
   listeners and no client can connect until it restarts. This affects every
   sync-IPC service, including sys-log and dns-resolver. Phantoms now also
   keep the name reserved.
2. **High.** A refused listener refill panics the server: `LocalServer::wait`
   unwraps `add_listener` (`sync.rs:597`). Listener creation is admitted like
   any user allocation, and any process may push memory down to the user
   floor, so ordinary memory pressure can take down dns-resolver or a future
   rmux server. Strobe and sys-io are protected by the privileged reserve.
   The name loss in item 5 ends in the same panic.
3. **Medium.** Closed listeners accumulate in kernel memory. They stay in
   `Service.pending` while other endpoints remain open, so a process that
   keeps one endpoint open can create and close listeners until admission's
   user floor starts refusing ordinary allocations system-wide. The entries
   are freed only when its last endpoint closes. `release_name` already holds
   the `Service` and could remove its own entry (a `VecDeque` supports
   `retain`).
4. **Medium.** The rebased tree is ungated. Neither the main-image nor the
   developer-image gates have run on it, and the release developer-image
   suite (`src/tests/full-test-dev.sh --release`) last passed before the two
   review fixes. A baseline run first would also separate existing failures
   from ones the fixes below introduce.
5. **Medium, latent.** A `LocalServer` with `max_listeners == 1` can still
   lose its name while alive. In `wait()`'s `E_BAD_HANDLE` path a dead
   listener is closed (`sync.rs:634-636`) before any replacement exists, and
   refills happen only at the start of the next `wait()` (`sync.rs:594-598`).
   If a client connects and drops while the server is outside `SysCpu::wait`
   and that listener was the only endpoint, the name is released; another
   process can register it and the next refill panics (item 2). With two or
   more listeners a refill always precedes the next close, so current
   services (xor, both stats servers, the stats registry, sys-log,
   dns-resolver) are safe. Rmux must use at least two, or `LocalServer`
   should retire dead listeners only after the next refill.
6. **Low.** `OP_DUP` can return a handle to an already-closed endpoint. It
   needs a dup and a close of the same handle racing in one process, so only
   that process is affected. In `sys_obj.rs:467-468`, the lookup
   (`get_object`) and the handle-count increment (`add_object`) are separate,
   so a concurrent last-handle `put_object` can run between them: the count
   drops to zero, the endpoint closes and its peer sees a disconnect, then the
   dup raises the count again and returns success while `closed` stays set.
   With the name-release logic (`shared.rs:120`), that close also releases the
   service name. The release is consistent with the endpoint being closed; the
   defect is the successful dup. The race predates this work (process-handle
   closing, `a3be0fed`), and the new test duplicates before closing, so it
   does not cover this interleaving. Fix: serialize dup's lookup and count
   increment with last-handle removal under the process's `wait_objects`
   lock, keeping endpoint cleanup outside it. That lock suffices because all
   of an endpoint's handles live in one process table (`OP_DUP` is
   same-process only).
7. **Low.** The takeover-before-cleanup path is untested. No test reliably
   exercises the new-owner reset in `create` (`shared.rs:166-179`) or the
   owner-mismatch return in `release_name` (`shared.rs:116-119`):
   `Child::kill()` (plain `SysCpu::kill`) waits until the target has fully
   exited (`sys_cpu.rs:566-579`), by which point exit cleanup has released the
   name (`process.rs:766-773`). The takeover at `ipc_service.rs:159-163`
   therefore only creates a fresh entry, and `test_shared_listener_restart`
   behaves the same. Kill the peer with the non-blocking `SysCpu::kill_pid`
   before taking over; the existing `ipc-service-busy` check after `wait()`
   then covers the mismatch return. Coverage is probabilistic, but the test
   cannot flake because both orders must pass.
8. **Low.** Hardening, not current bugs. `get()` upgrades each pending
   listener and drops that reference while holding LISTENERS
   (`shared.rs:227`). This is safe only because every named endpoint gets a
   process handle right after `create` and is closed before its last
   reference drops. If `add_object` ever becomes fallible, a failed
   registration racing `get` would self-deadlock in `release_name`, so
   document the invariant or drop the reference after unlocking. `get` also
   maps from `service.owner` rather than the listener's own `owner`
   (`shared.rs:214-221`, `248-251`). That is correct because takeover clears
   `pending`, but a `debug_assert!` would keep the invariant visible where it
   is relied on.
9. **Low.** Error codes (decision pending with the user): should a
   conflicting `create` return `E_ALREADY_IN_USE` rather than
   `E_INVALID_ARGUMENT`, and a `get` on a live server with an empty pool
   return `E_NOT_READY` rather than `E_NOT_FOUND`? `ipc_service.rs` pins the
   current codes; changing them means updating those assertions.
10. **Low.** Document the contract. The `shared:url` comment in
    `src/sys/lib/moto-sys/src/sys_obj.rs:32-38` still says only "can be
    duplicates". It should state that each URL has one live owner, which
    holds the name while it has any listening or connected endpoint and
    releases it on its last close or death, and that a conflicting CREATE
    fails.

## Status

`CAP_NET` and `CAP_FS_WRITE` are implemented, and the resulting policy is in
[process capabilities](../caps.md). This file replaces the completed
implementation plan and tracks the follow-ups from reviewing the branch
through `2790ef8c`.

Status, 2026-09-25: every finding from the 2026-09-24 review is resolved. The
fixes are committed as `d294f17a` (Rush capability masks), `0f86c328` (test VM
sizes), `03fc1e3c` (DNS peer authorization, read-only flush, capability
cleanups) and `9f419d06` (stdlib rollout, using the user-pushed external Rust
commit `b111eff318c3`). The IPC prerequisite for rmux is committed as
`13d09377`. Hashes are from after the user's rebase onto dev (`88ee73d3`); the
review baseline `2790ef8c` was `be799a34` before it. What remains is the list at
the top, then the rmux transport.

Workflow: new changes stay uncommitted until the user has reviewed them. This
tracking file also stays uncommitted.

Declined findings, recorded so they are not raised again:

- 8, fresh-boot placement budget: the existing budget still bounds additional
  spread relative to the initial fragmentation; a global split-event delta
  tests a different property.
- 14, vsock credit on undecodable headers: no credit stall was established,
  advertisements are cumulative, and malformed headers must not become trusted
  credit input.

## Rmux: approved sync IPC design (not started)

The user approved using the standard `moto-ipc::sync` channel instead of TCP
for the Motor client/server connection. The IPC prerequisite below is
committed; the transport itself has not started.

Client-only routing does not close the escape: an untrusted client can bypass
`rmux new` and send the protocol directly to the more privileged server.
The server must authenticate the client's actual capabilities before allowing
any session operation or terminal input. The TCP interfaces inspected expose
addresses, not the local peer's kernel-authenticated capabilities.

Existing `moto-ipc` channels and `moto_sys::SysObj::get_capabilities` provide a
connection-bound peer mask. Apart from the prerequisite's kernel fix and its
`ClientConnection::handle()` accessor, no new kernel, syscall, or stdlib API is
needed. Keep the Unix host transport and rmux's existing session
protocol/terminal behavior.

- Derive a server profile from the caller's immutable process capabilities,
  preserving the existing default-child grant policy without granting any
  extra bits. Separate server discovery by that profile and the existing
  temporary-directory namespace.
- Both ends verify the peer through the IPC connection. A server refuses
  clients missing any of its capabilities before processing a request.
  Never trust a mask or PID supplied by the client as authentication.
- A client whose profile differs starts or finds its own narrower server;
  session names are local to that server. Attaching cannot transfer an
  existing privileged session into a restricted server.
- Use the IPC rendezvous for discovery rather than writing a port/lock file.
  A server without `CAP_FS_WRITE` or `CAP_NET` can then operate without
  borrowing those capabilities for discovery or transport.
- Starting a persistent server still requires `CAP_SPAWN` and
  `CAP_SPAWN_DETACHED` in its launcher. If either is absent, fail clearly;
  do not borrow authority or silently change session lifetime semantics.
- Reject unauthenticated legacy TCP clients on Motor; leaving the old
  privileged listener reachable would preserve the escape.
- Give the server's `LocalServer` at least two listeners; with one, a live
  server can still lose its name (item 5 at the top).

Implement in small increments: authenticated connection and discovery,
profile selection/startup, then adversarial native regressions. No external
repository changes are proposed.

Validation must show that reduced clients cannot create, attach to, type into,
list, or kill privileged sessions even using a direct protocol client. Also
check narrower-server creation, permitted reattachment, actual pane masks,
missing spawn/detach authority, and existing rmux host/native behavior. Include
new tests in `full-test.sh`. Any developer-image run remains release-only.

## IPC prerequisite: service-name ownership (committed as `13d09377`)

Problem, confirmed natively (`/tmp/new-caps-rmux-ipc-probe.log`): the kernel
dropped a URL's registry entry as soon as its pending-listener queue emptied
(`shared.rs::get`), so another process could register the URL while the
original server and its connections were alive. The original server then
panicked on its next refill (`LocalServer::wait` unwraps `add_listener`). For
rmux, a competing server could take the name and the live server would lose
its sessions.

Fix, as approved: each URL records its owner process and a count of that
owner's open server endpoints, listening or connected. Connecting consumes a
pending listener but keeps the name. Closing the owner's last endpoint releases
it, including when duplicate handles delay that close. Cleanup compares owner
identities, so a dead owner's late cleanup cannot remove a successor's
registration; another process may take over once the owner is not alive.
`moto-ipc` gains a read-only `ClientConnection::handle()` so clients can
authenticate their server with `SysObj::get_pid`/`get_capabilities`.

Files: `src/sys/kernel/src/uspace/{shared,process}.rs`,
`src/sys/lib/moto-ipc/src/sync.rs`, and
`src/sys/tests/systest/src/{ipc_service,main}.rs`. `systest::ipc_service`
(`test_ipc_service_ownership`, also runnable as
`systest test-ipc-service-ownership`) covers exhaustion and refill,
authenticated peer queries, duplicate handles, same-process cleanup, retained
client handles, and takeover after death. It runs in the ordinary full suite
beside the existing `test_shared_listener_restart`, and it fails on the
original kernel (`/tmp/new-caps-ipc-before.log`).

The final sources include two fixes from the 2026-09-25 review:
`Process::put_object` releases its wait_objects lock before endpoint cleanup,
which avoids a lock-order deadlock with `spawn_thread`, and `shared::get` no
longer unwraps a possibly closed listener after a failed mapping. Three release
and three debug `full-test.sh` runs passed on exactly these sources, and both
kernel builds, including clippy, were clean. Formatting and whitespace checks
pass. Gate record and source hashes:
`/tmp/claude-1000/-home-posk-motor-dev-motor-os/a6f42c78-bfe3-4493-88d0-aa03f8d7dc4d/scratchpad/gates/`.
The release developer-image suite last passed before these two fixes
(`/tmp/new-caps-ipc-final-full-dev-release.log`). All of these gates predate
the rebase: they ran on the pre-rebase commit `de448355`. `13d09377` has
byte-identical IPC files, but the rebased tree adds 14 dev commits, including
kernel changes, and has not been gated.
