# Motor OS whole-file locking plan

Status: approved design; ready for implementation.

## Motivation and scope

Motor OS's Rust standard-library backend currently reports `Unsupported` for
`std::fs::File::{lock, lock_shared, try_lock, try_lock_shared, unlock}`. Motor OS
needs a system-wide implementation of those standard APIs with semantics that
work across processes and duplicated descriptors.

The first implementation will provide system-wide, advisory, whole-file locks:

- exclusive and shared modes;
- blocking and non-blocking acquisition;
- explicit unlock;
- release on the last close of a duplicated file description; and
- release when a client process exits or loses its filesystem connection.

It will not initially provide byte-range locks, mandatory locking, persistent
lock state, lease timeouts, lock upgrades/downgrades, or new POSIX `flock` or
`fcntl` interfaces. Those features have substantially different semantics and
are not needed by Rust's `File` API. The internal protocol should be
extensible, but extensibility should not make the initial state machine more
complicated.

## User-visible semantics

Locks coordinate only with the five Rust file-locking operations. They do not
prevent reads, writes, truncation, rename, or deletion by code which does not
participate in locking. This advisory model is both the simplest model and the
one most portable applications expect.

An exclusive lock conflicts with every lock held through a different open file
description. A shared lock conflicts with an exclusive lock, but multiple
shared owners may coexist. Locks are associated with an open file description,
not merely a process or descriptor number:

- two independent opens of the same file are different owners, even in one
  process;
- `File::try_clone`/descriptor duplication shares the owner and lock; and
- closing one duplicate does not release the lock while another duplicate
  remains open.

The file is identified by the filesystem's `EntryId`, not its path. A rename
therefore does not change the locked object. If a locked file is deleted, the
lock remains associated with that existing entry until it is released; a newly
created file at the same path has a different generation-bearing `EntryId` and
does not inherit the old lock.

Both shared and exclusive locks will be allowed on a regular file regardless of
whether that handle was opened for reading or writing. Locking is coordination,
not data access, and imposing a write requirement would add little protection
while reducing portability. The current Motor OS file backend opens only
regular files as `File`; directory and special-handle locking remain outside
this first version.

`unlock` on an unlocked description succeeds as a no-op, making cleanup
idempotent. Re-locking an already locked description returns `InvalidArgument`;
it does not silently convert between shared and exclusive modes.

## Architecture

The operation crosses the existing filesystem layers:

```text
Rust std File API
    -> moto-rt filesystem ABI
    -> rt.vdso descriptor/open-description state
    -> moto-io filesystem client and moto-sys-io protocol
    -> sys-io in-memory lock manager
```

The lock manager belongs in `sys-io`, alongside the system-wide filesystem
service. Putting it in `rt.vdso` would coordinate only threads in one process;
putting it in `motor-fs` would incorrectly persist or couple transient process
state to the on-disk filesystem. No on-disk format or `motor-fs` transaction
change is needed.

### Lock identity and state

Each independently opened `rt.vdso` `File` receives a process-local `OpenId`.
Duplicated descriptors already share the same `Arc<File>`, so they naturally
share that ID. `sys-io` assigns every filesystem IPC connection a `ConnectionId`.
The server-side owner is the pair `(ConnectionId, OpenId)`; clients cannot name
an owner belonging to another connection.

The lock manager maintains a map keyed by `EntryId`. Each entry contains either
one exclusive owner or a set of shared owners, plus any queued acquisition
requests. A reverse index from `ConnectionId` to held and queued locks makes
process-disconnect cleanup bounded by that client's activity rather than by all
locked files. Empty entries are removed promptly.

Motor OS process spawning currently constructs stdio pipes rather than
inheriting arbitrary regular file descriptions, so cross-process inheritance
does not need a more expensive global open-description registry in the first
version. The existing spawn paths should still be audited during implementation.
If general inheritance is added later, the protocol will need a server-issued
owner ID (or an explicit alias operation) so two connections can refer to the
same open description. Adding inheritance itself remains out of scope here.

### Runtime and protocol APIs

The ABI uses one appended VDSO function taking an fd and a small operation code
(`shared`, `exclusive`, their two non-blocking variants, or `unlock`). Typed
`moto_rt::fs` wrappers keep invalid operation codes out of normal Rust callers.
One entry point keeps the ABI and `rt.vdso` dispatch small without losing any
semantic capability.

The VDSO field should be appended to `RtVdsoVtable`, rather than inserted among
the existing filesystem fields, so existing offsets do not move unnecessarily.
`moto_rt` and `rt.vdso` must advance `RT_VERSION` together because version
matching is currently exact.

The `moto-sys-io` request carries the `EntryId`, `OpenId`, and operation. The
`moto-io::fs::FsClient` exposes the corresponding asynchronous operation, while
`rt.vdso` uses its existing filesystem runtime thread to present a synchronous
ABI to Rust std. No new Motor OS error code is needed: a non-blocking conflict
returns `moto_rt::Error::NotReady`, which the standard library already maps to
`io::ErrorKind::WouldBlock`; the std backend then returns
`TryLockError::WouldBlock`.

### Blocking without blocking `sys-io`

A blocking acquisition must not hold the filesystem lock, block the single
threaded `sys-io` executor, or consume one of a connection's in-flight request
tickets indefinitely. The command handler will register a deferred response in
the lock manager and return its dispatch ticket immediately. When the request
becomes eligible, the manager records ownership first and then sends the saved
response. A failed response send releases the just-granted lock or is handled
by connection cleanup.

Wait queues must be bounded so a client cannot consume unlimited `sys-io`
memory. The exact limit can follow existing per-connection resource limits; an
exhausted queue returns a normal resource error rather than dropping existing
locks.

### Close, unlock, and failure cleanup

`rt.vdso::File` will hold a small mutex-protected lock state. It serializes lock
operations issued concurrently through duplicates and records state only after
the server confirms acquisition. An acquisition attempted while that open
description already holds either lock mode returns `InvalidArgument`. Explicit
`unlock` reports an IPC or server error and retains the local state if release
was not confirmed.

Normal last-close cleanup belongs in `Drop for File`, because `PosixFile::close`
is called for every descriptor and cannot itself tell that the last shared
`Arc` is gone. Drop performs a best-effort release and logs unexpected failure;
when a failed IPC connection is the cause, server-side disconnect cleanup is
authoritative.

When the filesystem receiver observes that a client has disconnected, it will
atomically remove that client's queued requests, release all of its held locks,
and grant newly eligible waiters. This covers normal process exit, abort, kill,
and failure before an acquisition response is consumed. Lock state is
deliberately lost if `sys-io` itself restarts; its client connections and open
descriptions are invalid at that point as well.

## Contention policy

The policy is FIFO order per file, with batching of consecutive shared requests
at the head of the queue. A later shared request does not bypass an older
exclusive waiter. A non-blocking request succeeds immediately only if it is
compatible with current holders and does not bypass an older queued waiter;
otherwise it returns `WouldBlock`.

This policy is slightly more code than waking every waiter to race again, but it
is deterministic, prevents writer starvation, and avoids a retry storm in
`sys-io`. It does not promise scheduler-level fairness after a client is woken;
ownership has already been assigned before the response is sent.

## Error behavior

- A bad or non-file descriptor returns the existing bad-handle error.
- A malformed operation or a repeated operation rejected by the chosen policy
  returns `InvalidArgument`.
- A conflicting try-lock returns `NotReady`/`WouldBlock`, not
  `AlreadyInUse`/`AlreadyExists`.
- A disconnected filesystem service returns `NotConnected`.
- Unlocking an unlocked description succeeds under the idempotent policy.

The standard-library Motor OS backend will map only the expected
`WouldBlock` result into `TryLockError::WouldBlock`; all other failures remain
`TryLockError::Error(io::Error)`.

## Implementation stages

Each stage should be a separately reviewable commit.

1. Add the protocol representation and a standalone `sys-io` lock-manager
   state machine with unit tests for compatibility, ordering, cancellation, and
   cleanup. This stage does not expose the feature to applications.
2. Connect the manager to filesystem IPC, including deferred responses,
   connection identity, disconnect cleanup, queue bounds, and `moto-io` client
   calls.
3. Add the versioned `moto-rt` ABI and `rt.vdso` file ownership/lifecycle
   plumbing. Verify independent opens, duplicates, explicit unlock, final
   close, and failed connections at this layer.
4. Implement the five Rust standard-library backend methods and add Motor OS
   system tests using the public `std::fs::File` API.
5. Run the full Motor OS test suite and native VM integration tests, including
   coordination between independently executed processes.

## Test plan

Tests should cover:

- exclusive/exclusive, exclusive/shared, and shared/shared compatibility;
- blocking acquisition waking only after release;
- both try-lock variants returning `TryLockError::WouldBlock`;
- independent opens in one process conflicting correctly;
- duplicated descriptors retaining a lock until the last close;
- explicit unlock and idempotent unlock;
- process exit and forced termination releasing held locks and cancelling
  waiters;
- FIFO ordering and consecutive shared batching;
- rename preserving a lock, and delete/recreate not transferring it;
- concurrent calls through one duplicated description returning the specified
  repeated-operation error; and
- two real processes coordinating access to one file while locks on unrelated
  files proceed independently.

Timing-only tests should be avoided where an explicit child-process handshake
can prove that a request is blocked or has been released.

## Resolved design decisions

- Contention uses FIFO ordering with consecutive shared batching. This prevents
  starvation and makes behavior deterministic without promising scheduler-level
  fairness.
- Re-locking an already locked open description returns `InvalidArgument`.
  Lock conversion and re-entrant behavior are not part of the first state
  machine.
- The runtime ABI appends one operation-coded VDSO entry point, with typed Rust
  wrappers presenting the five standard operations.
