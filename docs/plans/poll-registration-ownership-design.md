# Poll registration ownership: one object per registration

2026-08-14. Design for the races deferred by commit `7e8e3efc` ("vdso:
retire queued poll events with their registration"): a tombstone racing
a deregistration, a descriptor closed without `poll_del` and its number
reused, and an `add` racing a close. REVIEWED: NOT READY FOR
IMPLEMENTATION; no code changed.

The four replaced fix attempts (v1..v4) are preserved under the local
tag `archive/poll-fix-v1-v4` (`6140fe1d..f903e816`); their systest
scenarios are resurrected in the test plan below.

## Review outcome (2026-08-14)

The per-registration `Arc` remains the recommended ownership model, and
the behavior changes below are acceptable. The first draft was not
implementation-ready, however: its close/reuse proof confused source
object identity with descriptor-incarnation identity, remote close could
hide a registration from a concurrent local close, the `add` transaction
had no linearization protocol, and the ready-queue state machine was
incomplete.

This revision recommends:

1. Keep a detached descriptor number out of the freelist until
   `PosixFile::close` has finished its source-side registration sweep.
   This is simpler than adding a descriptor-generation ID to every poll
   and close path, and it handles reuse by a `dup` of the same source.
2. Keep remotely-closed registrations in the source map until
   `poll_del` or local close retires them. Remote close queues CLOSED bits
   but must not make the registration undiscoverable by local close.
3. Give a registration an `Adding`/`Active`/`Retired` lifecycle, serialize
   registry `add`/`set`/`del` operations with an operations mutex, and make
   every rollback/removal conditional on `Arc` identity.
4. Specify `set`, collect, and retirement transitions completely,
   including unconditional clearing of `pending` after a queue pop and
   removal of a pending queue node on retirement.
5. Put each regression test in the commit that fixes it and apply the
   repository's full core-OS test gate to every implementation commit.

The revised design below records those recommendations. It needs a second
review before implementation because fd reuse timing and registration
lifecycle are non-obvious changes to core runtime behavior.

## The lesson the v1..v4 series taught

A poll registration's state is co-owned by three parties -- the
registry (`pollees`, `events`, `tombstones`), the source
(`EventSourceBase::registries`), and the descriptor table -- keyed by
two things that do not denote identity: an `RtFd` that is reused the
moment a descriptor closes, and a `Token` the caller may alias and
frees at deregistration. Calls run in both directions (registry into
source for add/set/del, source into registry for delivery and
tombstones), so no lock added on one side can make a cross-object
invariant atomic; each of v2..v4 fixed a race the previous commit's
locking created. The converging move is to stop simulating identity
with keys and locks and give a registration one: an `Arc`'d object
that owns its own queued events, whose retirement is a single flag
under a single lock.

## Current state (verified in code 2026-08-14, at 7e8e3efc)

- `Registry` (runtime.rs) holds `events: BTreeMap<Token, EventBits>`
  (the queued events, drained ascending by token), `pollees:
  BTreeMap<RtFd, Pollee>` (weak source ref + token + interests), and
  `tombstones: BTreeMap<RtFd, Event>`, delivered ahead of and never
  mixed with regular events (`collect_tombstones`, line 1066).
- Sources come in two flavors sharing `EventSourceBase`, whose map
  `(r_id, fd) -> (Token, Interests, MaybeBits)` is the source half of
  the registration. Managed sources (TCP, UDP, the Registry itself as
  a nested-poll source) deliver edges synchronously through
  `on_event`; unmanaged sources (SelfStdio, ChildStdio, ChildFd) run a
  readiness task that converts level state to edges, with `MaybeBits =
  EventBits` recording what was already reported.
- Tombstones are produced by `on_handle_error` -> `on_closed_remotely`
  (line 573): the readiness task notices the wait handle died (child
  exited, pipe peer gone) and queues a CLOSED event per registration
  -- on the io-runtime thread, unsynchronized with user threads.
- `posix_close` (posix.rs line 220) pops the descriptor -- which
  pushes the fd number onto the freelist *before* `close()` and thus
  before `on_closed_locally` runs -- so a number can be reissued while
  the old object's poll teardown has not started.
- Every delivery takes the global `REGISTRIES` spin lock to resolve
  `r_id`, and the `if let Some(r) = Option::flatten(REGISTRIES.lock()
  ...)` pattern holds that guard through the delivery call (a
  scrutinee temporary lives to the end of the `if let`).

## The three races, precisely

1. **Tombstone vs deregistration.** `add_tombstone` (line 1149)
   inserts unconditionally. `Registry::del` removes the pollee and
   tombstone, but a tombstone landing just after leaves an event under
   a token whose owner deregistered -- the exact contract break the
   soak campaign root-caused, on the tombstone path instead of the
   event map. Variant: the tombstone is keyed by fd, so after fd reuse
   it can land while a *new* registration owns the number, delivering
   the old token. Trigger is routine: every child exit and pipe
   teardown races every deregistration in the process (russhd spawns a
   child per ssh session).
2. **Close without `poll_del`, number reused.** `on_closed_locally`
   clears the source half and (since 7e8e3efc) the queued bits, but
   the registry's `pollees` entry stays. The next `add` under the
   reused number hits `assert!(insert(..).is_none())` (line 903) --
   a vdso panic, i.e. silent exit-222. A stale tombstone under the
   number likewise survives to be delivered with the dead token.
3. **`add` vs close.** `Registry::add` resolves the file, calls
   `poll_add`, then inserts the pollee, with nothing ordering it
   against `posix_close` on the same fd. If the source-side sweep in
   `on_closed_locally` runs between resolution and `poll_add`'s
   insert, the fresh registration survives on a closed fd: an orphan
   that raises events under its token indefinitely (source-wide edges
   such as a remote close deliver to every registration), or collides
   with the number's next owner in `pollees` (the race-2 assert).

## Design

One new type, owning everything that today is smeared across four maps:

```rust
struct Registration {
    registry: Weak<Registry>,
    source: Weak<dyn PosixFile>,
    r_id: u64,
    source_fd: RtFd,
    state: SpinLock<RegState>,
}
enum RegLifecycle {
    Adding,  // source-published, not yet visible to waiters
    Active,
    Retired,
}
struct RegState {
    token: Token,
    interests: Interests,
    queued: EventBits,   // delivered, not yet collected
    reported: EventBits, // unmanaged level->edge dedup (was MaybeBits)
    pending: bool,       // sitting in the registry's ready queue
    lifecycle: RegLifecycle,
}
```

- The registry holds `pollees: BTreeMap<RtFd, Arc<Registration>>` --
  the fd is now only a lookup key for add/set/del; identity is the
  `Arc`. `Registry::events`, `Registry::tombstones`,
  `retarget_event_bits` and `clear_event_bits` are deleted. The
  registry gains `ready: SpinLock<VecDeque<Arc<Registration>>>` and a
  blocking `ops` mutex serializing `add`/`set`/`del`. Delivery and local
  close do not take `ops`.
- The source half becomes `BTreeMap<(u64, RtFd), Arc<Registration>>`,
  replacing `(Token, Interests, MaybeBits)`. The `PosixFile`
  poll methods change to pass `&Arc<Registration>` -- an internal
  trait, not the vdso ABI, which stays fd-based; no moto-rt bump. Every
  removal from either map, including error rollback, first verifies
  `Arc::ptr_eq` with the expected registration; an old operation must
  never remove a newer registration under the same map key.
- **Lifecycle**: a new registration starts `Adding`. Source delivery may
  accumulate `queued` bits in that state, but cannot put the registration
  on `ready` or expose its token. Only after descriptor revalidation and
  registry-map publication does `add` change it to `Active`, enqueue any
  accumulated bits, and wake. A failed add changes it to `Retired` before
  identity-checked rollback, so a failed `poll_add` cannot leak an event.
- **Delivery**: lock `state`; mask with `deliverable(interests)` (the
  7e8e3efc invariant, now enforced at the only place bits enter);
  drop if `Retired`; `queued |= bits`. `Adding` stops there. For
  `Active`, if `!pending`, set it, push the `Arc` onto `ready`, then
  wake the poller. No `REGISTRIES` lookup -- the registration carries
  `Weak<Registry>`; an upgrade failure tells the source iteration to
  remove that exact registration after releasing its iteration locks
  (replacing today's `dropped_registries` sweeps).
- **Collect** (`wait`): pop one `Arc` from `ready` and release the queue
  lock before taking `state`. Clear `pending` unconditionally. Skip if
  the lifecycle is not `Active` or `queued == 0`; otherwise emit
  `(token, take(queued))`. A delivery racing collect either lands before
  the take or observes `pending == false` after the state lock is
  released and re-pushes; nothing is lost or duplicated.
- **`set`** validates the new interests, then under `state` replaces the
  token and interests, applies `queued &= deliverable(new_interests)`,
  and resets `reported = 0`. The source-specific `maybe_raise_events`
  runs afterward. If masking makes `queued` zero while `pending` is true,
  the existing queue node stays: collect clears `pending`, and a new edge
  arriving first reuses that node.
- **Retirement** changes the lifecycle to `Retired`, sets `queued = 0`,
  and, if `pending`, clears it and removes that exact `Arc` from `ready`.
  Eager removal bounds the queue when a process repeatedly makes a source
  ready and closes it without polling. Retirement is done by
  `Registry::del`, by `on_closed_locally` (local close must raise
  nothing, per the module header), and by `add` replacing a stale
  entry. Everything downstream -- a delivery in flight, a tombstone,
  a collect -- is a no-op by construction, because it takes the same
  state lock. `Registry::del` returns `E_OK` whenever the registry half
  existed; source-map removal is identity-checked and best-effort (see
  ruling 4).
- **Tombstones become ordinary bits.** `on_closed_remotely` locks each
  registration, queues `READ_CLOSED`/`WRITE_CLOSED` masked by its
  interests, and marks the corresponding directional interests reported.
  It does **not** remove the source-map entries: a concurrent or later
  local close must still be able to find and retire them, including bits
  already queued. `poll_del` or local close removes the source half. Race
  1 is fixed because queueing and retiring serialize on the registration's
  lock; the local-close variant is fixed because remote close no longer
  hides the registration from the local sweep.
- **`add` identity rules.** An existing `pollees` entry blocks a new
  add (`E_INVALID_ARGUMENT`, mio's EEXIST) only if it is live: not
  `Retired`, source upgrades, and the source is the same object the new
  add resolved. Anything else -- retired, dead weak, or a different
  object under a reused number -- is a stale entry: retire it, drop
  it, proceed. This deletes the race-2 assert. The close sweep normally
  removed the stale source half before making the fd reusable; rollback
  still removes only an identity match.
- **`add` transaction**: hold `ops`; resolve the source; reject a live
  matching pollee or retire a stale one; construct an `Adding`
  registration; and ask the source to validate and publish its half.
  Revalidate `posix::get_file(source_fd)` before registry publication.
  A mismatch retires the registration, identity-removes the source half,
  and returns `E_BAD_HANDLE`. Otherwise publish the registry half and,
  while holding `state`, activate it. If a close already retired it,
  identity-remove both halves and return `E_BAD_HANDLE`. A close after
  activation linearizes after the successful add and retires it normally.
  The operations mutex prevents an older add from replacing a newer add
  while its final revalidation is pending, but is never taken by close or
  delivery.
- **Lock order**: code may take registration `state` and then `ready`.
  Collect pops under `ready`, releases it, and only then takes `state`.
  Source iteration may take the source map and then `state`; consequently
  retirement releases `state` before asking the source to remove its map
  entry. PDIAG snapshots `Arc`s under map/queue locks and releases those
  locks before reading `state`. No path calls into a file while holding the
  descriptor-table lock.
- **Descriptor reuse**: `posix_close` detaches the descriptor-table entry
  without returning the number to the freelist, calls `PosixFile::close`
  (which completes the source-side sweep), then releases the number even
  if close returned an error. Thus an add through an alias cannot reuse the
  same number and same source object while the old close still has a sweep
  named by that number. No global registry walk is added to close.
- **Nested polls**: `Registry::close` calls
  `self.event_source.on_closed_locally(rt_fd)` -- the one v3 line
  worth keeping, since a Registry is itself a managed source.

## The races under the design

1. Tombstone vs deregistration: both queueing and retirement take
   `state`; whichever wins, a retired registration queues nothing and a
   queued bit on a live one is legitimate readiness. Remote close keeps
   the source entry, so a later local close can still retire already
   queued CLOSED bits. The fd-keyed tombstone map no longer exists.
2. Close without `poll_del` + reuse: local close retires the registration
   before the fd number becomes reusable. The next add replaces the
   retired registry entry; the new descriptor inherits neither bits nor a
   pending queue node. Reuse through a duplicate of the same source is no
   exception because the old close has completed its fd-keyed sweep first.
3. `add` vs close: events accumulated while `Adding` are invisible. A
   detach before revalidation causes identity-checked unwind and
   `E_BAD_HANDLE`; a close after revalidation either retires before
   activation (also unwind) or linearizes after a successful activation.
4. Concurrent adds: `ops` serializes their stale-entry decisions and all
   rollback is identity-checked, so an older add cannot retire or remove a
   newer registration.

## Behavior changes needing a ruling

1. **Tombstones lose delivered-first ordering** and become ordinary
   queued bits. Nothing found in-tree depends on the ordering; mio
   does not promise it. Recommend: accept.
2. **Aliased tokens stop merging.** Two sources registered with the
   same token in one registry today merge into one `Event`; per-
   registration queues emit two. epoll behaves like the latter; tokio
   tokens are unique by construction. Recommend: accept.
3. **Collect order** changes from ascending-token (`BTreeMap`
   `pop_first`) to ready-queue FIFO. mio promises no order; FIFO is
   fairer under load. Recommend: accept.
4. **`Registry::del` on a remotely-closed source** returns `E_OK`
   instead of the source's `E_INVALID_ARGUMENT` (epoll's DEL also
   succeeds there). Recommend: accept.
5. **Descriptor-number reuse is delayed through local close teardown.**
   `posix_close` detaches the entry immediately but returns its number to
   the freelist only after `PosixFile::close` finishes. This slightly
   extends number unavailability, adds no global registry scan, and closes
   the same-object-dup hole. Recommend: accept.

## Commit plan

Keep each implementation commit in the 100-300 line range including its
tests. Split a step further if needed; do not defer a regression test to a
later commit.

1. Introduce `Registration`/`RegState`/`RegLifecycle`, the `ops` mutex,
   and identity-carrying `PosixFile` poll-method plumbing. Use the new
   object as both map values while still delivering into the old
   `Registry::events` map; behavior stays identical.
2. Add the per-registration ready queue, `Adding` activation gate,
   collect/set/retirement transitions, and identity-checked removal;
   delete `Registry::events`, `retarget_event_bits`, and
   `clear_event_bits`. Update PDIAG without introducing a lock inversion.
   Include the deregistration, same-token-set, failed-add-no-event, and
   ready-queue-retirement tests in this commit.
3. Turn tombstones into ordinary queued bits, retain remote-closed source
   entries, and delete the tombstone map and `collect_tombstones`. Include
   tombstone-vs-del, stale-tombstone, unmanaged deregistration, and
   remote-close-vs-local-close tests in this commit.
4. Change descriptor close to detach/close/release, implement the
   serialized add/revalidation transaction, delete the stale-fd assert,
   and make `Registry::close` call `on_closed_locally`. Include the close
   without deregistration, add-vs-close, concurrent add/del, concurrent
   old/new add, and same-source-dup reuse tests in this commit.
5. Run the storm soak on the result; this also supplies the still-pending
   soak verdict for 7e8e3efc.

For every implementation commit: confirm each deterministic regression
fails on its parent, run the focused poll tests while developing, run
`cargo +nightly fmt`, build without new compiler or clippy warnings, then
pass `src/tests/full-test.sh` three times and
`src/tests/full-test.sh --release` three times before committing.

## Test plan

- `poll::test_deregister_retires_closed_events` must stay green through
  every commit.
- Resurrect from `archive/poll-fix-v1-v4` (adapted, not copied -- their
  assertions predate the identity model):
  `test_close_without_deregister_retires_registration`,
  `test_stale_tombstone_is_dropped_after_reregistration`,
  `test_registration_races_source_close`,
  `test_add_races_source_close`, `test_concurrent_add_del_consistent`,
  `test_reregister_same_token_replaces_interests`, and
  `test_deregister_retires_unmanaged_tombstone`.
- New: a tombstone-vs-del hammer (spawn/reap children while registering
  and deregistering their `ChildFd`s), which no v-series test covered and
  which is race 1's production shape.
- New: remote close racing local close without `poll_del`; no CLOSED bit
  may survive the local close.
- New: reuse the just-closed fd through a duplicate of the same source;
  the old close sweep must never retire the new registration.
- New: concurrent old/new adds straddling descriptor reuse, plus a failed
  add that proves its `Adding`-state readiness is never observable.
- New: `set` masks the only queued bit to zero, then a later edge must
  still enqueue; repeated ready/add/close churn must not grow `ready`.
- Every test added to `poll.rs` must be called by `run_all_tests`, keeping
  it transitively covered by `src/tests/full-test.sh`.
- Run focused `systest test-poll`, `mio-test`, and `tokio-tests` during
  development, the per-commit full gates above, then the storm soak.

## Costs

Delivery drops the global `REGISTRIES` lock and one map lookup per event
and gains one `Arc` clone per ready-queue push. The allocation cost is one
per registration lifetime, not one per socket lifetime; one source may be
registered through several fds or registries.

The `ops` mutex affects registration changes only, never delivery or local
close. Eager retirement scans `ready` to remove one exact `Arc`, an O(n)
close/deregister cost that keeps the queue bounded by live pending
registrations; the second review should accept this tradeoff explicitly,
and the storm soak should watch registration-heavy performance. Delayed fd
reuse holds a number only for the source's existing close call and sweep;
it adds no global registry scan and no boot-time work.

`REGISTRIES` survives only for watchdog and PDIAG enumeration. Net: the
hot path sheds a global spin lock that today is taken once per event per
registration across all sockets and the io thread.
