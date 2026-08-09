# File-backed child stdio plan

Status: v9 implementation plan. The ripgrep-specific code is complete; this OS
work has not started. All review decisions through v9 are resolved below.

## Changes from v4

The v4 snapshot design was sound for one immediate child, but its claim that
`rush` could keep snapshots out of every shared-offset case was too strong. A
child given a direct file can itself spawn children with `STDIO_INHERIT`. If
each generation takes another independent snapshot, sequential grandchildren
can start at the same unchanged offset and overwrite each other. For example,
an outer shell can give a file to an inner shell, after which both commands in:

```sh
rush -c '/bin/echo one; /bin/echo two' > out.txt
```

can snapshot offset zero from the inner shell. The second write can replace the
first. A marker local to the outer `rush::exec_simple()` cannot prove anything
about descendants.

V5 therefore uses two distinct transports:

- a positive regular-file fd is transferred as a direct file snapshot; and
- `STDIO_INHERIT` of an already file-backed canonical fd is a pipe relayed
  through the parent's live `File`.

The direct child sees a real file, which is required by ripgrep. The process
that owns that file remains the offset authority for its descendants, so their
relayed writes advance one shared in-process offset instead of forking stale
snapshots.

The review also found and this revision corrects these independent v4 issues:

- a full vectored operation must hold the position mutex once; calling public
  scalar methods in a loop would unlock between slices;
- Motor Rust `std` currently implements `FileDesc::{read,write}_vectored` with
  scalar fallbacks, so the VDSO vector `todo!()`s are reached by the direct
  `moto_rt`/C APIs, not by ordinary Rust `Write::write_vectored` as v4 said;
- `From<io::Stdout>` and `From<io::Stderr>` cannot duplicate fd 1 or 2 inside
  an infallible conversion. V7 answered that by mirroring Unix `std`'s
  borrowed/static-fd variant; V8 answers it with parent-stream sentinels, so
  there is nothing to duplicate and nothing that can fail. See "Changes from
  the v7 review and v8 decisions";
- `SelfStdio::close()` is a pre-existing pipe-stdio abort. File stdio would
  make it inconsistent: `close(1)` would abort or succeed depending on how the
  process was invoked. V7 includes the small descriptor-close fix in its final
  compatibility stage;
- `2>&1` copies the source and its transport provenance at that point. A later
  redirect such as `2>&1 1>f` intentionally splits the streams; and
- the plan no longer claims every unaffected case is byte-identical or that
  no behavior changes anywhere. Relays can affect scheduling and stdout/stderr
  interleaving even when their final bytes are unchanged.

## Changes from the v5 review

The v5 hybrid was accepted; the descendant hole it identified is real and v4
described it as a feature. Review then added these corrections, all folded into
the sections below:

- The relay's nonblocking position acquisition is a private `rt.vdso` lock
  rather than a new `Mutex::try_lock()`. Superseded in v8: relays hold no lock
  across an await, so no nonblocking acquisition is needed at all.
- The relay buffer must be sized for a filesystem sink. The existing relays use
  an 80-byte stack buffer, which would make each redirected line its own
  filesystem request.
- Stage 2 must reject file-backed `STDIO_INHERIT` outright, because it is
  separately committable and the relay does not arrive until later stages.
- An active input relay excludes the *parent's* own position-dependent I/O on
  that `File`, not only other children. The behavior must be chosen explicitly.
- Process wait must include relay finalization, whose descendant-lifetime and
  wall-clock properties must be stated precisely.
- File stdio does make `SelfStdio::close()` inconsistent rather than leaving it
  untouched.

## Changes from the v6 review and v7 decisions

V7 closes the remaining review questions:

- While an inherited-input relay owns a `File`, all other position-dependent
  operations on that same open description return `E_ALREADY_IN_USE`; they do
  not wait for the child. This deliberately differs from Linux shared-open-
  description behavior and avoids a hidden child-lifetime block.
- File relays use one reusable 4 KiB buffer. Output batching fills it across
  pipe reads under sustained load, but flushes a partial buffer after one
  bounded yield cycle when no more bytes are immediately available. Superseded
  in v8: the buffer matches the pipe ring and there is no batching policy.
- Relay finalization is descendant-lifetime-bounded but has no wall-clock
  bound: a filesystem request or an unrelated ordinary position holder may
  still stall. `wait()` intentionally waits for finalization without a timeout.
  Superseded in v9 for the second case: registration waits for an existing
  ordinary holder on the spawning thread before the child wakes, after which
  ordinary operations return `E_ALREADY_IN_USE`.
- The completion group supports multiple simultaneous process waiters with an
  atomic completion word and futex wake-all, rather than the single-waiter
  `SyncWaiter` primitive.
- Correct scalar-fallback-independent vectored file I/O is an approved
  prerequisite.
- The public `moto-rt` spawn comment is approved. Functional `moto-rt` code
  remains unchanged.
- The pre-existing `SelfStdio::close()` abort and stdout/stderr `Stdio`
  conversion panics are fixed and tested in a final stage rather than deferred.

## Changes from the v7 review and v8 decisions

V7 was written under a constraint that `moto-rt` must not change. That
constraint is lifted: `std` and toolchain changes are already required, so
`moto-rt` may change too. A second rule replaces it — **Motor-specific code in
Rust `std` must be a thin wrapper over `moto-rt` calls** — and reshapes three
parts of the plan. The `moto-rt` delta is three ABI constants and one comment;
no new `moto-rt` function is added, because `moto-rt` is itself a thin
forwarding layer over the VDSO table and is not where behavior belongs.

- **Positive stdio fds are borrowed, not consumed.** V7 had `std` clone each
  configured `Stdio::Fd` per spawn, convert it with `into_raw_fd()`, and rely on
  a VDSO entry guard to close every unique positive input on every path — three
  mechanisms answering one question. Spawn simply does not take ownership. This
  deletes the VDSO ownership guard, `std`'s per-spawn `try_clone()`, and the
  partial-clone-cleanup fix.
- **`Stdio::StaticFd` is replaced by parent-stream sentinels.** V7 mirrored Unix
  `std` with a `BorrowedFd<'static>` variant and a fallible duplication during
  spawn, after which the VDSO had to recognize the result as a canonical
  duplicate by `Arc` comparison. Three constants state the source directly.
  This deletes both halves: the fallible conversion in `std` and the
  canonical-duplicate classification, alias detection, and direction inference
  in the VDSO.
- **`std` must forward vectored file I/O to `moto-rt`.** `moto_rt::fs::{read,
  write}_vectored` already exist and `std` ignores them, substituting
  `io::default_write_vectored` with `is_write_vectored()` returning `false`.
  That is `std`-side logic standing in for an available call.
- **The relay buffer matches the pipe ring at 2 KiB**, which removes v7's
  yield-cycle output batching policy entirely. See "Relayed inheritance of a
  canonical file fd".
- **Position serialization is one ordinary mutex, and nothing else.** V7 built
  a custom lock with an ordinary mode and an input-relay mode, which then needed
  a pending state, a re-check-on-wake rule, and a priority rule to be correct.
  All of that was machinery for a case the plan deliberately answers with an
  error and does not otherwise support. V8 replaces `File::pos: AtomicU64` with
  `Mutex<PosState { pos, input_relay }>`, checks the flag inside the lock, and
  is done: no new locking API in `moto-rt` or in `rt.vdso`, no states, no
  waiters, no priority or starvation rules. The output relay reserves its range
  in a brief lock section instead of holding the lock across its await, so
  `Mutex::try_lock()` is not needed either. Superseded in v9 only by adding the
  output-relay count to that same state and extending the error rule to the
  output-relay lifetime. See "Position serialization".

## Changes from the v8 review and v9 decisions

V9 retains the v8 architecture and resolves its last concurrency ambiguity
without adding another lock or a fairness protocol:

- The 2 KiB relay buffer is deliberate. It equals the current pipe ring, so a
  relay can use a plain read/write loop; a 4 KiB buffer would need a batching
  policy to decide when to stop waiting for a second fill.
- The toolchain changes make a small `moto-rt` ABI-vocabulary update necessary,
  so the three parent-stream constants and the borrowed-fd comment remain in
  scope. No `moto-rt` behavior is added.
- Vectored forwarding must preserve the whole-operation position guard and
  normal short-I/O semantics, but its private helper structure is an
  implementation detail.
- A file relay of either direction now excludes ordinary position-dependent
  operations for its full registered lifetime. `PosState` records both the
  input claim and the output-relay count. Registration occurs on the spawning
  thread before the child wakes; competing parent operations then return
  `E_ALREADY_IN_USE`. Output relays may still overlap each other and reserve
  disjoint ranges. This closes the v8 hole in which a parent seek and write
  could target a range that an output relay had reserved but not yet written.
  It also ensures the single relay executor never blocks behind an ordinary
  filesystem operation after registration. The design still uses one existing
  mutex, with no custom states, nonblocking lock, waiter queue, priority, or
  starvation rule.

## Problem

Motor OS cannot currently attach a regular file descriptor to a child's stdin,
stdout, or stderr. `moto_rt::process::SpawnArgs` stores those streams as
`RtFd`s, and Motor Rust `std` has a `Stdio::Fd` variant, but `rt.vdso` accepts
only `STDIO_INHERIT`, `STDIO_NULL`, and `STDIO_MAKE_PIPE`. A positive fd reaches
a catch-all panic. `From<File> for Stdio` is consequently also a panic.

`rush` works around this by pumping files through child pipes. It preloads file
input into a pipe. For output it drains the pipe into a `Vec` and writes that
buffer to the file after the child exits. Thus:

```sh
rg --files-with-matches alpha . >> results.txt
```

sees a pipe as fd 1 rather than `results.txt`. Ripgrep cannot compare stdout's
file identity with entries in its directory walk and can report the output
file as an input. The delayed write avoids an unbounded read/write feedback
loop, but changes normal redirection semantics and consumes memory
proportional to the command's output.

`rush` pipelines are separately non-streaming: stages run sequentially through
a temporary file and an in-memory input. This plan does not redesign them.

The issue belongs below ripgrep. Passing a path in an environment variable or
teaching ripgrep about `rush` would remain wrong across rename, fd duplication,
and non-shell launchers.

## Scope and semantic model

The implementation stays on the process-runtime side. It changes `rt.vdso` and
the private stdio-pipe helper. It does not change the `moto-io` or `sys-io` wire
protocol, add a filesystem service object, or add boot-time work.
`moto_ipc::stdio_pipe` explicitly exists only to support and test the VDSO
stdio implementation, so exposing one existing counter there does not create a
new general IPC facility. `moto-ipc` is an in-tree crate and is not a
dependency of Motor Rust `std`.

### Layering rule

`moto-rt` is a thin forwarding layer over the VDSO table plus the ABI vocabulary
both sides agree on. Behavior lives in `rt.vdso`. Motor-specific code in Rust
`std` must in turn be a thin wrapper over `moto-rt` calls: it maps `std` types
onto `moto-rt` calls and constants and does not reimplement or substitute for
them. Every design choice below follows from that rule, and a future revision
that puts logic in `std` — or functionality in `moto-rt` — is drifting off it.

The complete `moto-rt` delta for this work is three constants in
`moto_rt::process`, beside the three already there:

```rust
pub const STDIO_PARENT_STDIN:  RtFd = -((ErrorCode::MAX as RtFd) + 4);
pub const STDIO_PARENT_STDOUT: RtFd = -((ErrorCode::MAX as RtFd) + 5);
pub const STDIO_PARENT_STDERR: RtFd = -((ErrorCode::MAX as RtFd) + 6);
```

plus a comment on `moto_rt::process::spawn` recording that positive stdio fds
are borrowed. **No new `moto-rt` function is added.** Every error code this plan
returns — `E_BAD_HANDLE`, `E_INVALID_ARGUMENT`, `E_NOT_IMPLEMENTED`,
`E_NOT_ALLOWED`, `E_ALREADY_IN_USE`, `E_NOT_READY` — already exists in
`moto_rt::error`, and `moto_rt::futex_wait`/`futex_wake_all`, used by the
completion group, already exist and are re-exported at the crate root.

One sequencing consequence must be planned for rather than discovered. The rustc
fork takes `moto-rt` from crates.io; it is *not* in the fork's
`[patch.crates-io]` table, which holds only `libloading`, `stacker`, `libc`, and
`ctrlc`. The three constants must therefore be published before any `std` change
can reference them: publish `moto-rt`, run `cargo update -p moto-rt` in the
fork, then rebuild the toolchain. Adding `moto-rt` to the patch table for local
development is an alternative, but it edits the fork's `Cargo.toml` and should
be decided deliberately.

The core scope is regular files on child fds 0, 1, and 2. There are two
deliberately different cases. The final compatibility stage additionally accepts
the three parent-stream sentinels; other positive descriptor kinds remain
unsupported.

### Direct transfer of a positive file fd

For a positive fd in `SpawnArgsRt`, the parent snapshots its `rt_fs::File`.
A positive fd is now always an independent file transfer: a caller asking for
one of this process's own streams says so with a parent-stream sentinel rather
than by duplicating a descriptor, so there is no aliasing case to detect here.
The snapshot carries:

- the generation-bearing filesystem `EntryId`;
- its current offset;
- readable and writable access bits; and
- its `open_id`, used only to recognize aliases within this spawn.

The child constructs its ordinary `rt_fs::File` around that snapshot and uses
its own existing filesystem client. It has exact file identity and normal file
metadata, seek, flush, and I/O behavior. No path is reopened, so rename cannot
retarget it and a delete/recreate generation mismatch cannot silently select a
replacement file.

This is a new Motor open description. Parent and child positions and lock
owners are independent after spawn. If stdout and stderr came from duplicate
descriptors for one parent `File`, equal parent `open_id`s cause the child to
construct one shared `Arc<File>` for both, so they share one child-side offset.
The child gets a fresh `open_id` because filesystem advisory locks are owned by
`(connection, open_id)`.

This direct route provides the behavior ripgrep needs and lets a detached
direct child outlive its parent. It is not a general implementation of POSIX
open-file-description inheritance.

### Relayed inheritance of a canonical file fd

For `STDIO_INHERIT`, the VDSO must inspect the actual canonical parent fd. A
pipe or terminal keeps the current relay. Null produces null bootstrap data
without starting a useless relay. When the descriptor is a regular `File`, the
child receives a stdio pipe and the relay reads or writes through the parent's
live `File`.

`STDIO_INHERIT` is the case where the source stream matches the destination
slot. The three parent-stream sentinels generalize it by naming the source
explicitly, and resolve through the identical path: `create_stdio_pipes()`
already takes the destination `kind`, so a sentinel supplies the source kind
while `kind` stays the destination. `STDIO_PARENT_STDOUT` in the stderr slot is
therefore the ordinary relay from canonical fd 1 into the child's stderr. If the
named canonical descriptor is closed, spawn returns `E_BAD_HANDLE` from that one
resolution point. Concretely, the task retains the descriptor table's
`Arc<dyn PosixFile>`, after validating its `File` downcast, so closing the
parent descriptor cannot free the target mid-relay.

For stdout and stderr the path is:

```text
child pipe writer -> parent relay -> parent's File -> filesystem
```

Every filesystem write advances the parent's position under the same mutex as
the parent's own writes and seeks — the relay reserves its range under that
mutex and then writes outside it, as "Position serialization" describes.
Multiple descendant-output relays sourced from one `File`, including stdout
and stderr, therefore serialize on one authoritative offset. While any relay
is registered, the immediate parent's position-dependent operations return
`E_ALREADY_IN_USE`; it can write before relay registration, after relay
finalization, or between sequential children once the prior wait has returned.
No parent seek can retarget a range that a relay has reserved but not yet
written.

Each file relay owns one reusable 2 KiB buffer, matching the stdio pipe ring:
`make_pair()` maps one 4096-byte page and `PipeBuffer` uses half of it, so
`work_buf_len` is 2048 bytes and one drain can never yield more. The current
pipe-to-pipe relays use an 80-byte stack buffer, which is reasonable when the
destination is another ring buffer and ruinous when each chunk becomes a
filesystem request.

Sizing the buffer to the ring keeps the output relay a plain loop: nonblocking
read into the buffer, write what it got, repeat, handling short writes without
discarding the remainder; on child close, drain and complete. There is no
partial-flush policy, no yield-cycle heuristic, and no sparse-output latency
question, because there is never a reason to wait for a second fill.

An earlier draft used a 4 KiB buffer, which is exactly twice the ring and
therefore *requires* a batching heuristic to decide when to stop waiting for the
second fill. That trades one filesystem request per 2 KiB for one request plus
one scheduling round trip per 4 KiB — a real but modest gain, bought with a
policy that has its own latency failure mode and needs its own tests. If
measurement later shows the relay needs larger filesystem writes, the correct
lever is a larger ring for file relays, with the buffer resized to match.
`make_pair()` currently always maps one small page, so that future change would
first have to add an explicit size or page-count parameter. Buffer and ring
should stay equal, so the heuristic never has to come back.

For stdin the direction is reversed:

```text
parent's File -> parent relay -> child pipe reader
```

The relay exclusively claims the file's position until EOF has drained or the
child endpoint dies, matching the existing inherited-stdin relay's exclusive
`SelfStdio` claim. The relay claim is installed before the child wakes and is
accepted only when that `File` has no other active relay. While it exists, no
second input or output relay may start on the same open description. The relay
reads ahead only into its reusable 2 KiB buffer and the child's bounded pipe.
It records the guarded starting position, and the private `StdioPipe` API
exposes the shared reader counter to its writer as the number of bytes the
immediate child has removed from this new pipe.

When the child closes or exits, that counter is stable. The relay sets the
guarded position to `start + peer_bytes_read` before dropping the pipe, so
bytes still in the ring and bytes never written from the local buffer do not
advance the parent's position. Using the peer-read counter is important:
`nonblocking_write()` can put bytes in the ring and then report a wake error,
so summing a still-pending local slice and the ring's unread count could count
the same bytes twice.

At file EOF, the relay cannot drop the writer immediately and later inspect
what the child consumed. It keeps the writer alive until the pipe drains, then
drops it to deliver EOF. If the child dies first, it performs the same
`start + peer_bytes_read` reconciliation. A source read error follows the same
drain-or-child-death rule for bytes from earlier successful reads before the
pipe is closed; the current stdio-pipe protocol cannot carry the filesystem
error itself to the child. The ring counters already exist; this change only
exposes the direction-neutral count needed by the VDSO.

Every file relay is exclusive against ordinary position-dependent operations
on the parent open description, and this plan chooses an explicit error rather
than an implicit child-lifetime wait. While an input or output relay is
registered, every scalar or vectored read/write, seek, and direct-stdio snapshot
through that `File` or any of its duplicates returns `E_ALREADY_IN_USE`.
Position-independent operations such as metadata lookup remain available;
advisory locking follows the separate relay-exclusion rule below. A separately
opened `File` for the same `EntryId` is a different open description and is
unaffected.

This differs deliberately from Linux. After `fork()` or `dup()`, Linux file
descriptors referring to one open file description share an offset, and parent
and child syscalls interleave without a child-lifetime exclusion error. A Motor
input relay reads ahead into a pipe and may later have to return unread bytes;
allowing a concurrent position change would make that reconciliation overwrite
the newer position. A Motor output relay must release the mutex while its
asynchronous absolute-offset write is in flight; allowing a concurrent seek
could then direct a later parent write into the reserved range before the relay
fills it. Returning `E_ALREADY_IN_USE` in both cases is safer and more
observable than either silent overwrite or blocking an otherwise ordinary
parent operation until a long-running child exits.

The input relay treats the first regular-file EOF as final: after the already
read bytes drain, it closes the child pipe. Consequently, a process receiving
a regular file through `STDIO_INHERIT` cannot follow later growth through
stdin. A fresh simple `rush` redirect such as `tail -f < logfile` takes the
direct-file route and retains regular-file behavior; `tail -f logfile` opens
the path independently. Neither case registers a file relay, so neither is
subject to `E_ALREADY_IN_USE`. `producer | tail -f` also does not use a file
relay, but `rush` pipelines remain the existing non-streaming staged
implementation: `tail` does not start until the producer exits, and a
never-exiting producer therefore prevents that stage from running. Redesigning
that behavior is explicitly outside this plan. A nested or otherwise inherited
file stdin is the narrower pipe/EOF case described here.

There is one limit to that stdin guarantee. If the child itself relays stdin
to a grandchild, its VDSO can remove bytes from the outer pipe and keep
grandchild-unconsumed bytes in the child's private `SelfStdio::overflow`. If
that intermediate process then exits, the outer relay cannot see that private
stash. This is already a limitation of nested Motor stdio relays. V5 prevents
offset restarts and returns unread bytes from each immediate pipe, but it does
not claim exact deepest-consumer POSIX semantics across an arbitrarily nested
relay chain.

### Why this is better than snapshotting `STDIO_INHERIT`

Snapshotting an inherited file preserves metadata and parent independence in
every generation, but it silently loses data when a process uses the same
file-backed stdio for sequential children. The relay instead makes the process
holding the real `File` the serialization point. That closes the v4 descendant
hole without putting open descriptions in `sys-io`.

The tradeoff is explicit:

- the directly transferred child sees a file, but its children that merely
  inherit the stream see pipes;
- inherited descendants cannot seek or query the destination's metadata;
- an inherited child depends on its parent's relay lifetime, as all inherited
  Motor stdio does today;
- a filesystem error after a child write has entered the pipe cannot be
  reported as that write's synchronous error. The relay closes the pipe so a
  subsequent write fails, but already accepted bytes can be lost; and
- child flush drains only according to current stdio-pipe semantics, not as a
  direct filesystem `flush()`.

Those costs make relaying unsuitable for the positive-fd transfer and acceptable
for `STDIO_INHERIT`, whose current implementation is already a relay with the
same metadata, error-reporting, flush, and lifetime boundaries. A parent-stream
sentinel also relays, because that form explicitly requests the parent's
existing stream rather than an independent file transfer.

### Unsupported alias combinations

Transport is selected per parent open description, not independently per fd.
If one spawn names the same parent `File` both through a positive fd (direct)
and through `STDIO_INHERIT` (relay), using both routes would create independent
positions and reintroduce silent overlap. The initial implementation rejects
that mixed alias group with `E_NOT_IMPLEMENTED` before waking the child.

Likewise, relaying the same read/write `File` as both stdin and output is not in
scope. The stdin relay must retain read-ahead ownership until the child exits;
an output relay for the same position could then deadlock or make unread-input
rewind cross already committed output. Reject that bidirectional relay group.
Two separately opened `File`s for the same `EntryId` have different `open_id`s
and are intentionally independent, so they are not rejected.

An inherited-input relay may start only while the `File` has no active relay.
A second input relay, or an output relay started while the input claim exists,
returns `E_ALREADY_IN_USE` rather than queuing. Conversely, an input relay
request returns `E_ALREADY_IN_USE` while any output relay is registered. This
prevents an already-dead child's finalization from depending on a different,
still-running child. Output-only relays may overlap each other. Sequential
children work: process wait includes relay finalization before returning, after
which the next relay starts at the consumed position.

A file with an active advisory lock is also not accepted as a relay source in
the initial implementation, and acquiring a lock while that `File` has active
relays returns `E_NOT_ALLOWED`. A relay task owns the descriptor table's trait
object `Arc` and finishes on a `LocalRuntime` thread. If the parent closes its
last descriptor meanwhile, that task can perform the final `File::drop()`; the
current drop path releases a lock through `blocking_run()`, which is forbidden
on a LocalRuntime. Relay admission checks the existing atomic `lock_state`
while holding the position mutex. Lock acquisition takes the position mutex,
checks the relay fields, and changes `lock_state` from unlocked to acquiring
before releasing the mutex and making the filesystem request. Those two short
sections make relay admission and lock acquisition mutually exclusive without
holding the position mutex across that request. A relayed `File` is therefore
guaranteed unlocked when its last relay-side `Arc` drops. Making locked-file
drop generally async is separate filesystem-lifetime work and is not needed by
ripgrep.

## Runtime design

### Tagged child bootstrap data

Make `StdioData` an internally tagged null, pipe, or file record. The file
variant carries the snapshot's two-word `EntryId`, offset, access flags, and
parent `open_id`. `StdioData` therefore grows from four payload words to a tag
and five payload words. `SpawnArgsRt`, `SpawnResult`, and the public VDSO table
do not change.

This private bootstrap layout does not need a versioned public ABI: the parent
maps its own VDSO image into the child, so both ends always use the same build.
`FLAG_TERMINAL` is meaningful only for a pipe and must be clear for a file.

The child mapping of `ProcessData` is read-only, but the snapshot is not a new
security capability. `sys-io` currently serves filesystem requests as
`Role::System` and does not enforce per-connection file grants; `EntryId` is
already exposed through file attributes. The reconstructed `readable` and
`writable` bits preserve normal VDSO behavior but are enforced in the
child-controlled VDSO. The accurate security claim is therefore that this
transfer adds no new identifier exposure, not that its access bits create a
service-enforced grant.

Classify all three stream arguments and resolve their source `Arc`s before
creating pipe pairs. That permits alias grouping, mixed-transport rejection,
one snapshot per parent `open_id`, and cleanup without partially installed
relays.

### Child initialization

`stdio::init()` constructs each canonical descriptor from its tagged record:

- null uses the current empty `SelfStdio` behavior;
- pipe uses the current pipe-backed `SelfStdio`; and
- file calls `rt_fs::File::from_stdio_snapshot()`.

Only a file-backed slot is absent from `SELF_STDIO`; null remains an actual
empty `SelfStdio`, avoiding v4's contradictory description of a null
descriptor with an empty `SELF_STDIO` slot. `STDIO_INHERIT` dispatches from the
descriptor returned by `posix::get_file()` and never blindly unwraps the slot.

Snapshot validation rejects a zero `EntryId`, unknown flags, or neither access
mode before application entry. Equal parent `open_id`s in the three file
records reuse one child `Arc<File>`. The parent's numeric `open_id` is never
installed as the child's lock owner.

The result is the existing `File`, not a metadata facade. In particular,
`get_file_attr(FD_STDOUT)` downcasts it and returns live metadata for the
snapshot `EntryId`, which is the identity ripgrep uses.

### Position serialization

Replace `File::pos: AtomicU64` with one ordinary mutex over a small struct:

```rust
struct PosState {
    pos: u64,
    input_relay: bool,
    output_relays: usize,
}
// File::pos: moto_rt::mutex::Mutex<PosState>
```

That is the entire mechanism. `moto_rt::mutex::Mutex` already exists and
`rt_fs.rs` already uses it for `cwd` and `ReadDir::cursor`, so this adds no
locking API anywhere — not to `moto-rt` and not privately to `rt.vdso`.

An ordinary operation locks, returns `E_ALREADY_IN_USE` if `input_relay` is set
or `output_relays` is nonzero, and otherwise performs the complete operation
before unlocking: the filesystem request and position update for read/write,
all seek calculations, a direct-stdio snapshot, and an entire vectored
operation. Holding it only for each vector slice is incorrect because another
operation could interleave inside one `readv` or `writev`. Use private unlocked
scalar helpers once the caller holds the guard: scalar methods lock once and
call one helper, while vectored methods lock once and preserve normal short-I/O
behavior. This also closes the existing duplicated-fd lost-update race that
becomes unavoidable when a child's stdout and stderr share one `Arc<File>`.

All relay admission and ordinary-operation checks use those fields under the
same mutex, so the `E_ALREADY_IN_USE` answer is race-free. Before waking the
child, the spawning thread finishes any ordinary operation that already holds
the mutex and then registers the complete relay set for each `File`. An input
registration requires both fields to be clear, sets `input_relay`, and records
the starting position. An output registration requires `input_relay` to be
clear and increments `output_relays`; several output relays may be registered
together. If later spawn setup fails, rollback decrements or clears exactly
what that spawn registered before releasing its retained descriptor references.
No child is woken with a partially registered relay set.

The input relay then runs holding no position lock. At finalization it locks
once, writes `start + peer_bytes_read`, clears `input_relay`, and unlocks; that
single release publishes both changes. Each output relay decrements
`output_relays` on every finalization path after its last filesystem write has
completed or failed. Registration uses the ordinary mutex on the spawning
thread and makes no stronger fairness guarantee than that mutex provides.

The relay runtime is a single-threaded `LocalRuntime`, so a relay task must not
call `File::read()` or `File::write()`: those call
`AsyncFsClient::blocking_run()`, whose `block_on_sync()` explicitly forbids a
LocalRuntime thread.

Add a runtime-internal asynchronous FS dispatch alongside `blocking_run()`.
It sends the existing `IoTask` to the core I/O runtime and awaits its oneshot
result without blocking the relay thread. Relay reads and writes transfer one
owned, reusable buffer through that task, so no borrowed stack slice crosses
runtimes and there is no allocation per chunk. No `moto-io` API or protocol
change is required.

A relay must never hold the position mutex across that await, because another
task on the same executor may be holding the position while awaiting its own
dispatch — a task that blocks the executor waiting for the mutex would deadlock
against it. The output relay therefore reserves its range instead of holding the
lock: lock, take `start = pos` and advance `pos` by the chunk length, unlock,
then write the buffer at `start`, looping on short writes until every reserved
byte lands. There is one brief reservation section per chunk and one final
unregistration section per relay, nothing held across an await, and no
nonblocking acquisition. Ordinary operations cannot interleave because relay
registration makes them return `E_ALREADY_IN_USE`; output relays simply reserve
disjoint ranges, which is the relay-scheduling ordering the plan already
documents. A permanently failing relay write leaves its reserved range
unwritten; the relay closes the child pipe and logs, as it does for any relay
failure.

Registration occurs on the spawning thread before the child can produce relay
traffic. If an ordinary operation already owns the mutex, registration waits
there for that operation to complete. After registration, ordinary operations
only take the mutex long enough to observe the relay fields and return, while
relay tasks hold it only for the non-awaiting sections above. Thus a relay task
does not block the single-threaded relay executor behind an ordinary filesystem
request; no `try_lock()`, asynchronous mutex, or reservation waiter protocol is
needed.

Resolve the `&'static AsyncFsClient` while preparing the child on the spawning
thread and capture it in the relay task. Do not lazily call
`AsyncFsClient::get()` for the first time on the relay `LocalRuntime`, because
client creation calls `io_runtime::spawn()`, whose synchronous bridge is also
forbidden there. In practice process loading has already initialized the FS
client, but the construction site must make this invariant explicit rather
than rely on that incidental ordering.

### Relay completion and process wait

Sharing one position prevents overlap but does not by itself preserve the
order of sequential children. The kernel can report child A exited while its
relay still has bytes to write. If the parent immediately spawns and waits for
child B, B's relay could acquire the file first and produce `two\none\n` rather
than `one\ntwo\n`.

Associate file relays with the child process handle in a small VDSO-local
completion group installed before the child is woken. A relay completes only
after it has drained the child's output into the `File`, or reconciled input
after child death. `rt_process::wait()` must wait for that group after observing
kernel process exit, and `status()`/`try_wait()` must continue to return
`E_NOT_READY` until it is complete.

The group uses an `AtomicU32` pending/complete word. Any number of waiters may
loop on an acquire load followed by `moto_rt::futex_wait()`; the last relay
stores complete with release ordering and calls `moto_rt::futex_wake_all()`.
Do not use `moto_async::SyncWaiter`, whose contract permits only one waiting
thread, and do not implement completion with a timeout or polling retry loop.

Finalization is bounded with respect to process descendants, not wall-clock
time. The pipe being drained connects this process to its immediate child; the
child's death closes that endpoint, so no new bytes arrive and a grandchild's
separate pipe cannot retain it. The remaining buffered byte count is finite.
However, completion may still wait indefinitely for a filesystem request.
`wait()` intentionally includes that finalization and applies no timeout. State
both halves in the implementation and test a child that spawns a longer-lived
grandchild; descendant lifetime must not extend the wait.

The last relay marks the group complete and wakes all waiters before removing
the registry entry. A waiter that already holds the group `Arc` observes the
completion word; a later waiter finding no entry knows that either no group
existed or removal followed completion. Spawns with no file-backed inheritance
pay no registry or waiting cost. This ordering applies to parents using the
VDSO process API; a program that bypasses it and inspects the kernel process
object directly also bypasses runtime stdio finalization.

The existing process result has no place for both a kernel exit status and a
delayed relay error. The plan preserves the kernel status exposed through
`status()`/Rust `Child::wait()`, closes the child pipe on a relay failure so
later child I/O fails, and logs the first relay error once. Bytes the pipe
accepted before the failure still cannot be retroactively reported as a failed
child write. Adding a structured process-finalization error is deferred rather
than overloading an unrelated exit code.

### Spawn ownership and errors

Positive stdio fds are **borrowed** inputs to spawn. Spawn reads the descriptor,
takes its snapshot, and never closes it; the caller keeps ownership and closes
whenever it likes. This matches POSIX, where `posix_spawn_file_actions` leaves
the parent's descriptors alone, and it removes the question v7 answered three
times over — `std` needs no per-spawn `try_clone()`, there is no raw fd to leak
on a partial-clone failure, and the VDSO needs no ownership guard,
deduplication, or close-on-every-path rule. Record the borrowing rule as a
comment on `moto_rt::process::spawn`.

There is no compatibility risk in choosing borrowing over consuming: a positive
fd panics today, so no caller depends on either rule.

An invalid positive fd returns `E_BAD_HANDLE`; a valid unsupported descriptor
kind returns `E_NOT_IMPLEMENTED`. Neither panics. Snapshot construction has no
remote filesystem resource to roll back. Relay pipe pairs and tasks must be
armed only after validation and must use the existing remote-process cleanup on
later spawn failure.

A file relay also validates direction before child wake: an input source must
be readable and an output source writable, otherwise spawn returns
`E_NOT_ALLOWED`. This check applies to `STDIO_INHERIT` and the parent-stream
sentinels. Every positive file fd takes the direct route, retains its access
bits, and lets the child's attempted operation report the access error, as a
directly passed descriptor normally does.

A spawn that would relay an already locked source returns `E_NOT_ALLOWED`.
Once a relay is registered, `file_lock()` on that source returns the same error
until its active-relay count reaches zero; unlocking a lock that predates a
relay is impossible because such a relay is never registered.

An input relay conflicts with every other active relay for one `open_id` and
returns `E_ALREADY_IN_USE`; a new output relay receives the same error while an
input claim exists. Output-only relays may overlap and serialize per filesystem
write. While either kind is registered, competing parent position operations
and direct snapshots return `E_ALREADY_IN_USE`.

`File::set_nonblocking()` should accept and ignore the flag, as a regular file
is always ready, and its read/write `todo!()` branches should disappear in the
same patch. File polling already returns `E_INVALID_ARGUMENT`, which the libc
layer treats as always ready; pin that behavior with a test.

## Rust standard library and `rush`

Every change below keeps Motor code in `std` a thin mapping onto `moto-rt`
calls and constants, per the layering rule above.

`Stdio::into_rt()` takes `&self` and returns `fd.as_raw_fd()` for the
`Stdio::Fd` arm, because spawn borrows. `Command::spawn()` therefore drops its
per-stream `try_clone()` — three `moto_rt::fs::duplicate()` calls per spawn that
existed only to feed a consuming conversion. A `Command` stays reusable because
nothing takes the descriptor away from it.

Implement `From<File> for Stdio` by moving the file's `FileDesc` into
`Stdio::Fd`. That is the whole change: the variant already converts to a
positive `RtFd`.

The final compatibility stage fixes `From<io::Stdout>` and `From<io::Stderr>`
with the parent-stream sentinels rather than a borrowed-fd variant. Add a
payload-free `Stdio::ParentStdin`/`ParentStdout`/`ParentStderr`; each conversion
selects one, and `into_rt()` maps it to the matching
`moto_rt::process::STDIO_PARENT_*` constant. The conversions are infallible by
construction — nothing is duplicated, so nothing can fail — and the new
`into_rt()` arms are the same shape as the three already there for `Inherit`,
`Null`, and `MakePipe`. `.stderr(io::stdout())` states its source explicitly
instead of leaving the VDSO to infer it, and a closed canonical fd surfaces as
`E_BAD_HANDLE` from spawn rather than from a clone.

`FileDesc::read_vectored()` and `write_vectored()` must forward to
`moto_rt::fs::read_vectored()` and `write_vectored()`, and
`is_read_vectored()`/`is_write_vectored()` must return `true`. Those `moto-rt`
calls already exist and are already wired to the VDSO table; `std` currently
ignores them and substitutes `io::default_write_vectored` over the scalar path,
which is exactly the `std`-side logic the layering rule forbids. Note the
consequence: once `is_write_vectored()` is `true`, buffered writers take the
vectored path, so the `rt.vdso` vectored implementation added in stage 1 becomes
load-bearing for ordinary Rust output rather than reachable only from the C API.
That is a net reduction in round trips, and it means stage 1's whole-vector
position guard must be correct before this flip lands.

No other `std` change is required. `Child::wait()` and `try_wait()` already call
`moto_rt::process::wait()`/`try_wait()`; relay finalization changes those
functions' behavior inside `rt.vdso`, so the `std` call sites are untouched.

Fix `SelfStdio::close(rt_fd)` in the same stage by applying the existing
`ChildStdio` model: remove that descriptor's poll registrations through
`event_source.on_closed_locally(rt_fd)` and return success. Closing one fd does
not close the shared stdio pipe or invalidate duplicates; `SELF_STDIO` may keep
its internal `Arc`, while all user-facing dispatch—including `STDIO_INHERIT` and
the parent-stream sentinels—continues to resolve the actual descriptor table.
Thus closing canonical fd 1 makes later inheritance and sentinel resolution fail
with `E_BAD_HANDLE`, but an earlier duplicate remains usable.

Resolving a parent-stream sentinel needs one small VDSO detail. When the named
source is a canonical `SelfStdio`, the relay must read its immutable
`StdioKind` directly from `SelfStdio` rather than taking or inspecting its
optional `inner`, which an input relay may have claimed. Record the kind on
`SelfStdio` at construction. An output source may feed child stdout or stderr; a
source/destination direction mismatch returns `E_INVALID_ARGUMENT`. A
file-backed canonical source uses the corresponding file relay, which is what
preserves the live offset when a process whose stdout is already a file passes
`io::stdout()` to sequential children instead of reopening the v4 overwrite
hole.

### Sole-use descriptors in `rush`

`rush` cannot use the direct snapshot route for every redirection file.
`exec_compound_cmd()` can hand one `Arc<File>` to several commands, and
functions, loop bodies, and pipeline staging have similar lifetimes. Today the
pump writes each completed child's buffer through the shell's one advancing
`File` offset. Giving each immediate child a direct snapshot would make them
start from the shell's unchanged position.

`rush` therefore uses direct `Stdio::from(File)` only when both conditions
hold:

- `build_fds()` freshly opened the fd for this simple command's own redirect
  list rather than inheriting it from an enclosing `IoEnv`; and
- `exec_simple()` dispatches to `spawn_external()` or `spawn_background()`,
  each of which starts one immediate child.

An fd inherited from a compound, loop, function, or pipeline stage stays on
the existing pump. Builtins and functions also keep their current path. This
classification remains necessary even with inherited-file relays because a
`rush` `IoEnv` is a shell-level virtual descriptor set, not the process's
canonical fd 0/1/2 from which `STDIO_INHERIT` relays.

Keep the sole-use marker local to `exec_simple()`, beside but outside
`[FdSource; 3]`, and pass it only to the two one-child spawn functions. It must
not enter `IoEnv`. Add a debug assertion tying a direct file to the same
`exec_simple()` invocation that opened it.

The classification is per fd. A command may have a direct stderr and pumped
stdout. A duplication redirect copies both `FdSource` and current provenance;
`2>&1` therefore shares fd 1's current route. A later redirect can deliberately
replace one side, as in `2>&1 1>f`.

Unlike v4, the proof stops at the immediate transfer. If that one child spawns
grandchildren with `STDIO_INHERIT`, its VDSO relays them through the direct
`File` it owns, so sequential descendant output advances its offset rather
than taking repeated snapshots. This is the reason the hybrid design closes
the v4 hole.

Group redirects retain today's pump and its memory-proportional buffering.
`{ rg alpha .; } > out.txt` still gives ripgrep a pipe, while
`rg alpha . > out.txt` gives it a file. That is an explicit remaining shell
limitation, not a claim that the two forms are equivalent.

## Exact semantic boundary

| Case | Behavior |
| --- | --- |
| Fresh `>`/`>>` used by one external child | Direct child `File`; exact identity and direct I/O |
| stdout and stderr are positive aliases of one `File` | One child `Arc<File>` and serialized child offset |
| Direct child after parent exit | Continues independently |
| Parent and direct child both use the file | Independent offsets; overlapping writes can replace data |
| Direct child spawns and waits for sequential inherited-output children | Pipes relay through its one `File`; runtime wait drains each relay, preserving order without repeated-snapshot overwrite |
| Inherited child metadata, seek, or flush | Pipe behavior, not regular-file behavior |
| Inherited child after relay parent exits | Loses the relay, as inherited stdio does today |
| Multiple output relays to one parent `File` | Filesystem writes serialize; ordering follows relay scheduling and may interleave at relay chunks |
| One file-backed inherited stdin | Immediate-pipe unread data is returned to the guarded parent offset |
| Parent read/write/readv/writev/seek/snapshot on a `File` with any active file relay | Returns `E_ALREADY_IN_USE` after the brief state check; never waits for the child's lifetime |
| Two overlapping inherited-input children on one `File` | Second spawn returns `E_ALREADY_IN_USE`; sequential waited children use the reconciled offset |
| Input relay overlapping any output relay on one `File` | Later conflicting spawn returns `E_ALREADY_IN_USE`; output-only relays may overlap |
| File-backed stdin inherited through a relay | Child sees a pipe; first source EOF is final, so later file growth is not followed |
| Fresh simple `rush` file stdin or a child-opened path | Child sees a real file; regular-file EOF and later-growth behavior is retained |
| `rush` `producer \| consumer` pipeline | Existing non-streaming staged behavior; no file position reservation or `E_ALREADY_IN_USE` |
| Stdin relayed through several generations | No offset restart, but an exiting intermediate process can lose its private overflow stash |
| Same `File` selected for both direct and relay routes in one spawn | Rejected before child wake |
| Same inherited read/write `File` used for input and output | Rejected before child wake |
| Inherited source has an advisory lock, or is locked while relays are active | Rejected; no locked `File` is dropped on the relay runtime |
| Any redirect `rush` can hand to several immediate commands | Existing pump retained |
| `cmd > f &` with its own redirect | Direct file; bounded memory and output appears while it runs |
| `{ cmd1 & cmd2; } > f` | Group file stays pumped |
| Child file locks | New child `(connection, open_id)` owner |
| Parent-stream sentinel naming this process's stdout/stderr | Relayed from the named canonical source, including when that source is file-backed; source/destination direction mismatch is rejected |
| Positive fd in `SpawnArgsRt` | Borrowed, never closed by spawn; the caller retains ownership |
| Process wait after kernel child exit | Returns only after file-relay finalization; descendant lifetime cannot extend it, but stalled filesystem work can |

Motor append currently means "position at EOF when opened," not atomic
append-before-each-write. Both direct snapshots and relays preserve that
existing limitation; concurrent appenders are deferred filesystem work.

## Performance constraints

The ripgrep path is the direct route. It removes the child-to-parent pipe,
output-sized `Vec`, copies, and delayed file write, replacing them with the
same filesystem path as an ordinary child `File`. Snapshot construction does
no I/O and starts no runtime.

File-backed inheritance uses the already lazy stdio-relay runtime, a bounded
pipe, one reusable 2 KiB buffer, and a completion record only while its child
has a file relay. It adds no thread per child and no unbounded capture. Its
filesystem request takes one extra runtime dispatch compared with a direct file
operation. Measure concurrent relay throughput against the direct route and
against today's pump; if it falls short, resize the ring and the buffer together
rather than reintroducing a batching policy. A contended file relay must not
stall unrelated relay tasks; a relay that holds the position mutex across its
asynchronous dispatch is a correctness failure, not an acceptable performance
tradeoff.

Shared `rush` group redirects retain the current output-sized buffer. Fixing
that requires a separate shell-streaming design.

The position mutex affects every ordinary `rt_fs::File`, not only stdio.
Measure uncontended sequential reads/writes and duplicated-fd contention; an
unexplained file-I/O regression stops the patch even if the ripgrep path is
faster.

Boot time and spawns using only ordinary pipe/inherit/null streams must remain
within measurement noise. Any regression stops implementation for review.

## Implementation stages

Keep each implementation patch small and separately reviewable.

0. Replace the positive-fd panic with precise errors. Add the three
   `STDIO_PARENT_*` constants and the borrowed-fd comment to `moto-rt`, publish
   the crate, and run `cargo update -p moto-rt` in the rustc fork so the later
   `std` stages can reference them. This patch must not yet make a positive
   descriptor succeed, and it adds no `moto-rt` function.
1. Replace `File::pos: AtomicU64` with `moto_rt::mutex::Mutex<PosState>` and
   serialize scalar read/write/seek and snapshots under it, including the
   input/output relay-state check inside the lock. Implement full vectored
   operations under one guard. Make `File::set_nonblocking()` accept and ignore
   the flag and remove the regular-file nonblocking `todo!()` branches in the
   same patch: removing the branches alone is vacuous, since nothing could set
   the flag.
2. Add tagged `StdioData`, direct snapshot/reconstruction, alias grouping,
   sparse file `SELF_STDIO` handling, and direct-file tests. Keep null as empty
   `SelfStdio`. Because the relays do not exist until stages 5 and 6, this
   patch must reject file-backed `STDIO_INHERIT` with `E_NOT_IMPLEMENTED` —
   never falling through to the pipe relay and never unwrapping the empty slot.
   Stage 2 is separately committable, so without that rejection it would ship
   exactly the descendant corruption the later relay stages exist to prevent.
   The safe intermediate test uses `SpawnArgsRt` with a positive file fd; the
   ordinary Rust `Stdio::from(File)` and `rush` routes do not arrive until
   stages 7 and 8 respectively.
3. Add the runtime-internal async owned-buffer filesystem dispatch and its
   focused tests without exposing a new stdio route.
4. Expose the stdio-pipe writer's peer-read counter and add the multi-waiter
   per-child completion-group registry. Integrate its pending/complete state
   with `wait()` and `status()`, while leaving the registry unused by ordinary
   spawns.
5. Add 2 KiB file-output relays, pre-wake registration and parent-operation
   exclusion, output-alias validation, finalization, cleanup, failure tests,
   and throughput checks. File-backed inherited stdin continues to return
   `E_NOT_IMPLEMENTED` in this stage.
6. Add the exclusive file-input reservation, 2 KiB input relay, peer-consumed
   reconciliation, conflict errors, cleanup, and failure/EOF tests. At this
   point file-backed `STDIO_INHERIT` is complete.
7. Complete `From<File> for Stdio`, switch `Stdio::into_rt()` to borrow, drop
   `Command::spawn()`'s per-stream `try_clone()`, forward
   `FileDesc::{read,write}_vectored` to `moto-rt` with
   `is_{read,write}_vectored()` returning `true`, add Rust process tests, and
   rebuild the development toolchain.
8. Add `rush`'s local sole-use classification and direct route. Keep all shared
   immediate descriptors on the pump, then add descendant-relay tests.
9. Add the ripgrep regression and measure memory, direct and relay throughput,
   spawn performance, and boot time.
10. Fix `SelfStdio::close()`, add the payload-free parent-stream `Stdio`
    variants and their `into_rt()` mapping, resolve the sentinels in the VDSO
    including the `SelfStdio` kind field and direction check, test
    descriptor/poll cleanup and source-stream preservation, and rebuild the
    development toolchain. This final step does not broaden positive-fd support
    to other descriptor kinds.

## Test plan

Tests must cover:

- direct file stdin, stdout, and stderr, plus mixed file/pipe/null streams;
- the same nonzero `entry_id` in the parent file and direct child stdout;
- rename after snapshot continuing to address the same `EntryId`;
- direct-child access-mode failures, seek, flush, metadata, truncate, and
  permission operations using the existing regular-file paths;
- a direct child receiving a fresh advisory-lock owner rather than inheriting
  or releasing the parent's owner;
- stdout/stderr positive aliases sharing one child offset without lost writes;
- scalar read/write/seek, direct snapshots, and full vectored operations
  remaining atomic with respect to the position mutex;
- `set_nonblocking` succeeding on a regular-file stdio fd and polling treating
  it as always ready;
- parent and direct-child offsets advancing independently, including an
  explicit overlap demonstration rather than an implication of POSIX sharing;
- file-backed output `STDIO_INHERIT` advancing the parent's live position;
- a direct child spawning two sequential inherited-output grandchildren and
  retaining both outputs in command order after each wait;
- two concurrent output relays sharing one `File`, including stdout/stderr;
- relayed output throughput at the 2 KiB buffer size, against the direct route
  and against today's pump, including a producer that outruns the relay and one
  that trickles single lines;
- scalar and vectored parent reads/writes, seek, and direct snapshot against a
  `File` with an active input or output relay, all returning
  `E_ALREADY_IN_USE` promptly rather than blocking behind a long-running child;
- input and output registration attempted while an ordinary operation is in
  flight, each waiting on the spawning thread for that result and then excluding
  the next ordinary operation before the child wakes;
- two output relays reserving disjoint ranges on one `File` and both writing
  every reserved byte, including under short writes, with parent operations
  excluded until the last relay unregisters;
- an input relay conflicting in both orders with an output relay on the same
  `File`, while independently opened files for one `EntryId` remain
  unaffected;
- a child that spawns a longer-lived grandchild, confirming `wait()` completes
  when the child dies and does not wait on the grandchild;
- multiple threads waiting on one process handle while file relays finalize,
  all waking and observing the same completed state;
- stage 2's interim rejection of file-backed `STDIO_INHERIT`, so the safe
  intermediate state is pinned rather than assumed;
- `wait()` not returning, and `try_wait()` not reporting completion, until the
  dead child's file relays have drained or reconciled;
- an inherited descendant observing pipe metadata and seek behavior;
- file-backed stdin read-ahead: full consumption, partial consumption, no
  consumption, EOF drain, source error, child close, a pipe write whose wake
  fails after copying bytes, and parent read after reconciliation;
- inherited file stdin treating its first source EOF as final even if the file
  later grows, alongside direct file stdin retaining ordinary regular-file
  behavior;
- sequential inherited stdin children starting at the prior child's
  reconciled offset, and an overlapping second child receiving
  `E_ALREADY_IN_USE` without disturbing the first;
- nested stdin relay behavior, including the documented intermediate-overflow
  limit;
- rejection of one-open-description mixed direct/relay and bidirectional
  relay groups before the child wakes;
- rejection of an already locked relay source and of lock acquisition while a
  relay is active, including parent-close/relay-completion cleanup;
- direct detached-child success and inherited-relay parent-exit failure as two
  separate, intentionally different lifetime tests;
- invalid, closed, and unsupported positive descriptors and every spawn
  failure point, with no fd, mapping, task, or handle leaks;
- inherited and parent-stream-sentinel file relays rejecting a non-readable
  input or non-writable output before child wake, while every positive direct
  file retains its access-mode behavior in the child;
- `SelfStdio::close()` removing only the closed fd's poll registrations,
  canonical close making later inherit/parent-stream resolution fail with
  `E_BAD_HANDLE`, and a pre-existing duplicate remaining usable;
- `Stdio::from(io::Stdout)` and `Stdio::from(io::Stderr)` across repeated
  spawns, including `.stdout(io::stderr())`, `.stderr(io::stdout())`,
  `E_BAD_HANDLE` after canonical close, direction-mismatch rejection, and
  sequential children preserving a canonical file-backed stream's live offset;
- a positive stdio fd remaining open and usable in the parent after spawn
  returns, on both the success and every failure path, and one `Command`
  spawning repeatedly from a single configured `Stdio::Fd` without duplication;
- `FileDesc::{read,write}_vectored` reaching `moto_rt::fs::{read,write}_vectored`
  rather than the scalar fallback, with `is_{read,write}_vectored()` true and a
  buffered writer over file-backed stdout taking the vectored path;
- null inheritance remaining immediate EOF/discard without a relay;
- terminal flags and ordinary pipe relay behavior remaining unchanged;
- `rush` simple external and background redirects taking the direct route;
- compound, loop, function, builtin, and pipeline-stage descriptors retaining
  the pump and producing their current final output;
- per-fd mixed direct/pump routing and redirect-order cases including `2>&1`,
  `2>&1 1>f`, and `1>f 2>&1`; and
- no boot or ordinary-spawn regression.

The end-to-end regression creates matching `input.txt` and `results.txt`, runs:

```sh
rg --files-with-matches alpha . >> results.txt
```

and verifies that only `input.txt` is appended. A probe must also compare
`get_file_attr(FD_STDOUT).entry_id` in the direct child with the destination's
identity so an unrelated ignore rule cannot make the test pass. Include the
tests transitively in `src/tests/full-test.sh`.

Before committing any implementation patch, format with `cargo +nightly fmt`,
introduce no compiler or Clippy warnings, and run the full test three times in
both debug and release as required by `AGENTS.md`.

## Why not put open descriptions in `sys-io`

The filesystem protocol currently has no open or close operation. Requests
carry an `EntryId` and absolute offset; `sys-io` holds no per-open position.
Making it authoritative would change every file open, read, write, seek,
duplicate, close, and advisory-lock path. It would also require lifecycle and
failure rules for shared descriptions. That is the right scale for fully POSIX
inheritance, but excessive for the ripgrep case.

A shared offset page in the VDSO is not a smaller correct substitute. An atomic
offset does not serialize an asynchronous request and its short-I/O update; a
cross-process lock can remain held when a process is killed; promotion must
synchronize with duplicate fds and in-flight operations; and the mapping needs
multi-generation transfer and lifetime accounting. Copying a final offset at
`wait()` is also wrong for concurrent, unwaited, or detached children.

The hybrid route is narrower: direct snapshots provide file identity where it
is required, and existing-style relays keep one process's live `File` as the
offset authority when that stream is inherited further.

## Deferred work

- Fully shared, seekable, metadata-preserving open descriptions across
  processes. This likely belongs in `sys-io` or requires a robust transferable
  kernel object.
- Atomic append-before-write semantics.
- Exact deepest-consumer stdin accounting across an arbitrary relay chain.
- General async-safe destruction of a locked `File` on a `LocalRuntime` thread.
- Positive child-pipe descriptors such as
  `Command::stdin(child.stdout.take().unwrap())`; current stdio-pipe endpoints
  are bound to a process pair and cannot simply be retargeted.
- Streaming `rush` pipelines and bounded group-redirection output. The reason
  `rush` still needs a sole-use classifier is that a group redirect is a
  shell-level virtual descriptor rather than the shell's canonical fd 1. A real
  `dup2` in `rush` would make group redirects canonical-fd redirects, which the
  inherited-file relay already covers, and would let the pump and the
  classifier go away together. That is the eventual exit from the two-path
  arrangement.
- The pre-existing `motor-fs` error-level "Corrupt dir entry" log for a stale
  client-supplied `EntryId` generation.

## Approved ancillary fixes and stop conditions

`File::read_vectored()` and `File::write_vectored()` are pre-existing
`todo!()`s. Ordinary Motor Rust `FileDesc` vector methods currently take scalar
fallbacks, but direct `moto_rt::fs::{read,write}_vectored` and C-style callers
can already abort on a regular file. File-backed fd 0/1/2 makes that defect
reachable on canonical stdio. The fix is approved as a prerequisite: implement
each whole vector under one position guard as described above and do not loop
through public scalar methods.

The stdout/stderr conversions and `SelfStdio::close()` abort are also approved
for the final compatibility stage. If implementation encounters any other
pre-existing defect, stop for guidance rather than concealing it with a retry,
timeout, or fallback.

The `moto-rt` delta is fixed at three `STDIO_PARENT_*` constants and one
comment. `moto-rt` forwards to the VDSO table and carries the shared ABI
vocabulary; it is not where behavior goes. If implementation concludes that a
new `moto-rt` *function* is needed, stop and present it: that is either
behavior that belongs in `rt.vdso`, or a genuine gap in the forwarding layer,
and the two need different answers. The same applies in reverse to `std` — if a
Motor `std` path starts doing more than mapping onto a `moto-rt` call, it is on
the wrong side of the layering rule.

## V9 implementation decisions

1. Use direct snapshots for explicit positive regular-file fds. A caller
   wanting one of this process's own streams says so with a parent-stream
   sentinel, which relays; there is no duplicate-detection case.
2. Relay file-backed `STDIO_INHERIT` through the parent's live `File`, including
   bounded stdin read-ahead reconciliation, and accept the documented pipe and
   lifetime semantics for inherited descendants.
3. Reject mixed direct/relay aliases, a bidirectional inherited relay of one
   open description, every input/output relay overlap, overlapping input
   relays, and relaying a locked file instead of risking silent overlap,
   cross-child wait dependencies, deadlock, or a blocking drop on the relay
   runtime.
4. Keep `rush`'s sole-use classifier for immediate shell-level sharing, but do
   not rely on it to reason about descendants.
5. Serialize every in-process position operation, including the whole vector,
   under one ordinary `moto_rt::mutex::Mutex<PosState>`. Relays use async FS
   dispatch and never hold that mutex across an await: output relays reserve
   their range, input relays set a flag and run lock-free. Track the output
   relay count in the same state.
6. Make VDSO `wait`/`status` include per-child file-relay completion so
   sequential waited children preserve output order.
7. Keep `moto-io` and `sys-io` protocols unchanged.
8. Complete `From<File>`, the borrowed-fd conversion, and vectored forwarding
   in the core stages, then fix the sentinel-based stdout/stderr conversions
   and `SelfStdio::close()` in the final compatibility stage.
9. Include the approved pre-existing vectored-file fix as a prerequisite,
   because canonical file stdio makes its panic newly visible.
10. Preserve the child's exit status when a delayed relay fails, close the
    pipe, and log the first failure; a structured finalization-error channel is
    outside this ABI-compatible patch.
11. Add exactly three constants and one comment to `moto-rt`, and no function.
    Keep Motor `std` a thin wrapper over `moto-rt` calls. Treat any proposed
    new `moto-rt` function, or any logic accumulating in `std`, as a layering
    question rather than an implementation detail.
12. Register every file relay under the position mutex on the spawning thread
    before the child wakes. Return `E_ALREADY_IN_USE` for every ordinary
    position operation while any relay is registered, for every relay that
    conflicts with an input relay, and for an input relay requested while any
    output relay is registered; never block an ordinary operation for another
    child's lifetime. The `input_relay` flag and `output_relays` count inside
    `PosState` are the whole mechanism; no additional lock states or fairness
    rules are needed for a case the plan answers with an error.
13. Use one reusable 2 KiB buffer per file relay, equal to the stdio pipe ring,
    so no output batching policy is needed. Enlarge ring and buffer together if
    measurement ever demands larger filesystem writes.
14. Use a multi-waiter futex completion word. `wait()` includes relay
    finalization without a timeout; descendant lifetime cannot retain the
    immediate pipe, but filesystem progress has no wall-clock guarantee.
15. Borrow positive stdio fds in spawn rather than consuming them, so `std`
    needs no per-spawn duplication and the VDSO needs no ownership guard.
16. Express `From<io::Stdout>`/`From<io::Stderr>` as parent-stream sentinels
    rather than a borrowed-fd `Stdio` variant, keeping both the conversion and
    the VDSO's source resolution free of duplicate detection.
17. Forward `std`'s vectored file I/O to the existing
    `moto_rt::fs::{read,write}_vectored`, accepting that this makes the stage 1
    `rt.vdso` vectored implementation load-bearing for ordinary Rust output.
