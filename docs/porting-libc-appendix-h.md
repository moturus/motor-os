# Appendix H — M7, step by step

> **Status: complete** (2026-07-03) — `m7` prints "all tests passed" on Motor
> OS (setjmp, float format/parse incl. 20k `%.17g` round-trips, poll over
> UDP/files/TCP incl. the blocking-listener arming path, select on real fds,
> signals) and `lua bin/m7.lua` prints "LUA: all tests passed"; m2–m6 pass
> against the same libc. Lua 5.4.8 cross-compiled with **zero source
> patches**. Three mlibc-upstream defects found and fixed on the way (frigg
> `%.17g` digits, `strtofp` per-digit rounding, `system(NULL)`) plus one
> sysdep-side fd-reuse bug — see Pitfalls in H.9.
> `m7 abort` verified: exit status 134 — the M3-era abort gap is closed.
> Not yet exercised (run when convenient): the interactive `lua` REPL poke,
> and `m7 dns <name>` (note: the mode needs a hostname argument — plain
> `m7 dns` runs the normal suite — plus /etc/resolv.conf on the image).

> Part of the Motor OS libc porting guide — main: [porting-libc-by-fable.md](porting-libc-by-fable.md); appendices: [A: M0 toolchain](porting-libc-appendix-a.md) · [B: M1 shim](porting-libc-appendix-b.md) · [C: M2 mlibc](porting-libc-appendix-c.md) · [D: M3 stdio+malloc](porting-libc-appendix-d.md) · [E: M4 filesystem](porting-libc-appendix-e.md) · [F: M5 threads+TLS](porting-libc-appendix-f.md) · [G: M6 sockets](porting-libc-appendix-g.md) · [H: M7 poll + real program](porting-libc-appendix-h.md)

M7 is "a real program": a fork-free Unix program built against our mlibc runs
end-to-end in a VM. Getting there needs the two libc subsystems every real
program touches that we have so far deferred:

1. **`poll()` / `select()`** — deferred from M6 (G.6). Not optional anymore:
   mlibc's *own DNS resolver* waits on its UDP socket with `poll()`
   (`options/posix/generic/lookup.cpp:161,338`), so `getaddrinfo` by name is
   ENOSYS-broken until `Poll` exists. Motor has an epoll/mio-shaped registry
   API in the VDSO; we bridge POSIX level-triggered `poll()` onto it.
2. **Signals-lite** — `signal`/`sigaction`/`sigprocmask`/`raise`/`kill(self)`.
   Motor has no signal delivery at all, but real programs *install* handlers
   (Lua's REPL does `signal(SIGINT, …)`) and `abort()` needs
   `Sigprocmask`+`Sigaction`+`raise` (the known-failing `m3 abort` mode from
   M3). We implement **synchronous-only** signals: dispositions are recorded,
   `raise()` really invokes the handler in-thread, asynchronous delivery does
   not exist.

The real program itself: **Lua 5.4** (interpreter + REPL) — rationale and
alternatives in H.6. Gate it with `m7.c` (poll/select/signals/setjmp regression
test) so program-level failures are attributable.

All facts below verified against the in-tree VDSO/moto-rt and mlibc `368a00fa`.

---

## H.1 Deliverables

| # | Piece | Where |
|---|---|---|
| 1 | VDSO hardening: non-pollable fds must error, not panic | `rt.vdso/src/posix.rs` |
| 2 | Shim: poll registry exports + `moto_rt_getpid` | `moto-rt-cabi` (v6) |
| 3 | Sysdeps: `Poll`, `Pselect` | `sysdeps/motor/generic/poll.cpp` (new) |
| 4 | Sysdeps: `Sigaction`, `Sigprocmask`, `Kill`, `GetPid` | `sysdeps/motor/generic/signals.cpp` (new) |
| 5 | Listener arming for poll + blocking-`accept` emulation | `socket.cpp` |
| 6 | `m7.c` — poll/select/signal/format regression test | `src/tests/libc/` |
| 7 | Lua 5.4 built, staged, passing an acceptance script | `img_files/motor-os/bin/{lua,m7.lua}` |

## H.2 Ground truth: Motor's poll API

The VDSO exposes a **mio-shaped readiness registry**, already battle-tested by
Rust std / mio on Motor. Client wrappers: `moto-rt/src/poll.rs`; VDSO entry:
`rt.vdso/src/rt_poll.rs`; engine: `rt.vdso/src/runtime.rs` (`Registry`,
`EventSourceManaged`, `EventSourceUnmanaged`).

The API (all via vtable, thin wrappers in `moto-rt/src/poll.rs`):

```text
poll_new()                                   -> RtFd (a real posix fd)
poll_add(poll_fd, source_fd, token, interests) -> ErrorCode
poll_set(poll_fd, source_fd, token, interests) -> ErrorCode
poll_del(poll_fd, source_fd)                   -> ErrorCode
poll_wait(poll_fd, deadline, events*, cap)     -> #events | -ErrorCode
poll_wake(poll_fd)                             -> ErrorCode
```

Event bits (`moto-rt/src/poll.rs:11`): `POLL_READABLE=1`, `POLL_WRITABLE=2`,
`POLL_READ_CLOSED=4`, `POLL_WRITE_CLOSED=8`, `POLL_ERROR=16`.
`Event = { token: u64, events: u64 }` — 16 bytes.

Verified semantics that shape the design:

- **The registry is itself a posix fd** (`rt_poll.rs:12` → `posix::push_file`),
  closed with plain `moto_rt_close`. One fd of table space per live registry.
- **Delivery is edge-ish**: sources push bits into the registry's
  `events: BTreeMap<Token, EventBits>` via `on_event()`; `wait()` **drains**
  the map (`runtime.rs:709-721`). One event per token per wait, bits OR-ed.
- **Initial readiness is synthesized at registration** — this is what makes a
  create-registry-per-`poll()`-call design correct:
  - `TcpStream::poll_add` → `maybe_raise_events` checks current state: rx queue
    non-empty → READABLE, write buffer space → WRITABLE, `!can_read()` →
    READ_CLOSED, `Closed` state → all-closed bits (`rt_tcp.rs:594,648-690`).
  - `UdpSocket::poll_add` → same pattern (`rt_udp.rs:474`).
  - `TcpListener::poll_add` → READABLE iff `async_accepts` non-empty
    (`rt_tcp.rs:101-113`). **See the trap in H.4.4.**
  - Stdio is an *unmanaged* source (kernel wait-handle); the registry's wait
    loop calls `check_interests_for_registry()` before sleeping, converting
    level state to edge events (`runtime.rs:325-341`) — so stdin readiness is
    (re)checked at every `wait()`.
- **Duplicate registration of the same fd in one registry fails**: sources key
  interests by `(registry_id, source_fd)`; `add_interests` on an occupied key
  → `E_INVALID_ARGUMENT` (`runtime.rs:72-77`). POSIX allows duplicate fds in a
  `pollfd[]` — the sysdep must merge (H.4.2).
- **`wait` timeout is an absolute deadline** (`Instant` nanos, `u64::MAX` =
  infinite), and **timeout returns 0**, not an error (`runtime.rs:685-692`,
  the mio convention). Perfect for `poll()`'s `return 0`.
- **Tombstones**: if a polled fd is closed by another thread mid-poll, the
  source leaves a READ_CLOSED/WRITE_CLOSED tombstone event (`runtime.rs:395+`)
  — wakes the waiter instead of hanging. Nice.
- **Data-arrival events fire unconditionally** for streams and UDP (rx path
  calls `on_event(POLL_READABLE)` regardless of the nonblocking flag —
  `rt_tcp.rs:758,803`, `rt_udp.rs:325`), so polling a *blocking* TCP stream or
  UDP socket works. The listener is the sole exception (H.4.4).

### Who is pollable (decides fd classification in H.4.1)

`PosixFile::poll_add` implementors: `TcpStream`, `TcpListener`, `UdpSocket`,
`SelfStdio` (fds 0/1/2), `ChildStdio` (`proc_fd.rs`), and `Registry` itself
(READABLE only, `runtime.rs:477-489` — registries can nest).

**Not pollable — and today it panics**: `File`'s `poll_add` is commented out
(`rt_fs.rs:653-678`), so a regular file falls through to the trait default,
which is `todo!()` (`posix.rs:62-86`). `poll_del`'s default is even
`panic!(...)`. Polling a disk file = VDSO panic = process death. POSIX says
regular files always poll readable+writable, so real programs *do* put file
fds in `poll()` sets. Hence deliverable #1.

## H.3 Motor-side changes

### H.3.1 VDSO hardening (required)

In `rt.vdso/src/posix.rs`, replace the `PosixFile` trait defaults:
`poll_add`/`poll_set`: `todo!()` → `Err(E_INVALID_ARGUMENT)`;
`poll_del`: `panic!(…)` → `Err(E_INVALID_ARGUMENT)`. The commented-out code
already says `// Err(E_INVALID_ARGUMENT)` — finish the thought.

Nothing regresses: Rust std/mio never registers files, and an error return is
strictly better than a process-killing `todo!()` for any future caller. With
this, the sysdep gets a safe probe: `poll_add` failing with `E_INVALID_ARGUMENT`
⇒ "not a pollable kind" ⇒ treat as always-ready (exactly POSIX's rule for
regular files). No Motor-side *feature* work is needed — the registry itself
does everything `poll()` requires.

### H.3.2 Shim exports (moto-rt-cabi v6)

```c
// moto_rt.h additions
#define MOTO_POLL_READABLE     1ull
#define MOTO_POLL_WRITABLE     2ull
#define MOTO_POLL_READ_CLOSED  4ull
#define MOTO_POLL_WRITE_CLOSED 8ull
#define MOTO_POLL_ERROR        16ull

typedef struct {            // mirrors moto_rt::poll::Event, 16 bytes
    uint64_t token;
    uint64_t events;
} moto_poll_event_t;

int32_t  moto_rt_poll_new(void);
int64_t  moto_rt_poll_add(int32_t poll_fd, int32_t source_fd, uint64_t token, uint64_t interests);
int64_t  moto_rt_poll_set(int32_t poll_fd, int32_t source_fd, uint64_t token, uint64_t interests);
int64_t  moto_rt_poll_del(int32_t poll_fd, int32_t source_fd);
int64_t  moto_rt_poll_wake(int32_t poll_fd);
// timeout: RELATIVE nanos; UINT64_MAX = no timeout; 0 = harvest-only.
// Returns #events (0 = timeout) or negative moto error.
int32_t  moto_rt_poll_wait(int32_t poll_fd, uint64_t timeout_nanos,
                           moto_poll_event_t *events, uintptr_t events_cap);
int64_t  moto_rt_getpid(void);   // moto_sys::current_pid()
```

Rust side: straight wrappers over `moto_rt::poll::{new,add,set,del,wake,wait}`,
plus `moto_sys::current_pid()` — the cabi crate already depends on `moto-sys`
with the `userspace` feature. Add a size assert: `moto_poll_event_t` ==
`moto_rt::poll::Event` == 16.

**Unit trap (why `poll_wait` takes a relative timeout):** the registry API's
deadline is a `moto_rt::time::Instant`, whose `u64` payload is **TSC ticks,
not nanos** (`moto-rt/src/time.rs:8` — "Currently tsc. Subject to change").
`moto_rt_mono_nanos()` returns converted *nanos*, so C code cannot add a
timeout to it and get a valid `Instant`. Keep ticks out of the C ABI entirely:
the wrapper computes `Instant::now() + Duration::from_nanos(timeout)` on the
Rust side — the same convention `moto_rt_futex_wait` already uses.

## H.4 Sysdep: `Poll` and `Pselect`

New file `sysdeps/motor/generic/poll.cpp` (add to `meson.build`), tags `Poll` +
`Pselect` in `sysdeps.hpp`. mlibc entries: `poll()`/`ppoll()` call
`Sysdeps<Poll>` (`options/posix/generic/poll.cpp:11` — ppoll falls back to
sigprocmask+poll when `Ppoll` is unimplemented; with our no-async-signals world
that fallback is exact, so **don't** implement `Ppoll`). `select()`/`pselect()`
both call `Sysdeps<Pselect>` (`sys-select.cpp:38,49`).

### H.4.1 The core algorithm (`Poll`)

```text
poll(fds[], nfds, timeout_ms):
  results = 0
  registry = -1                    // created lazily, only if something registers
  for i in 0..nfds:
    fds[i].revents = 0
    fd = fds[i].fd
    if fd < 0:            continue                     // POSIX: ignore entry
    real = fd
    if fd >= MOTOR_PSEUDO_FD_BASE:
        real = motor_sock_realfd(fd)                   // may auto-bind UDP
        if real < 0 (EBADF):  revents = POLLNVAL; results++; continue
        if real < 0 (other, e.g. Fresh TCP — no real fd yet):
            continue                                   // never ready; see gaps
        if listening && !armed:  arm the listener      // H.4.4
    interests = (events&(POLLIN|POLLRDNORM) ? READABLE : 0)
              | (events&(POLLOUT|POLLWRNORM) ? WRITABLE : 0)
    if interests == 0: interests = READABLE            // closed/err bits still wanted
    lazily create registry; e = moto_rt_poll_add(registry, real, token=i, interests)
    if e == E_INVALID_ARGUMENT and not merged-duplicate case:
        // not a pollable kind => regular file/dir: always ready (POSIX)
        revents = events & (POLLIN|POLLOUT|POLLRDNORM|POLLWRNORM); results++
    if e == E_BAD_HANDLE:  revents = POLLNVAL; results++
  if nothing registered:  // only files/invalid/negative entries
      if results == 0 and timeout != 0: sleep timeout (moto_rt_sleep_nanos)
      return results
  timeout_ns = timeout<0 ? UINT64_MAX
             : results>0 ? 0               // already have answers: just harvest
             : timeout_ms * 1'000'000
  n = moto_rt_poll_wait(registry, timeout_ns, evbuf, nregistered)
  for each event: i = token; map bits into fds[i].revents (table below);
                  if fds[i].revents became nonzero, results++
  for each registered fd: moto_rt_poll_del(registry, real)   // politeness; then
  moto_rt_close(registry)
  return results  (never EINTR — no signals on Motor)
```

Notes:

- **Token = index into the caller's array** — no allocation-free mapping table
  needed; the events buffer is `alloca`/small-vector sized `nregistered`
  (cap it: `nfds` beyond a few hundred → heap).
- **timeout=0 fast path** falls out naturally: deadline "now", `poll_wait`
  harvests already-synthesized initial readiness and returns.
- If some entries answered immediately (files, POLLNVAL) but sockets are also
  present, we still call `poll_wait` with deadline=now to merge *current*
  socket readiness — POSIX `poll` reports the state of all fds, but must not
  block when any fd is already ready.
- **Cleanup**: explicit `poll_del` per registered fd before closing the
  registry. Dropping the registry alone is *safe* (sources GC dead-registry
  entries lazily on the next event, `runtime.rs:186-193`), but explicit del
  keeps source-side maps from accumulating between events.
- **EINTR never happens** — document; `SA_RESTART` semantics are moot.

### H.4.2 Duplicate fds in one `pollfd[]`

Same `(registry, fd)` can't be added twice (H.2). Merge sysdep-side: before
registering, check whether this real fd was already registered; if so, OR the
interests via `poll_set` under the *first* entry's token, and record the alias
`i → first_index`. When mapping results, fan each event out to every aliased
entry, masking by that entry's own requested `events`. Rare path (identical fd
twice in one poll set), a dozen lines; don't skip it — mlibc's DNS retry loop
and real programs (redirected stdin/stdout being the same tty fd!) can hit it.

### H.4.3 Bit mapping

povents → interests: `POLLIN|POLLRDNORM → POLL_READABLE`,
`POLLOUT|POLLWRNORM → POLL_WRITABLE`. (`POLLPRI`: no urgent data on Motor —
ignored on input, never reported.)

Motor events → revents (closed/error bits arrive regardless of interests —
sources always report them, `runtime.rs:176-180`):

| Motor bit | revents |
|---|---|
| `POLL_READABLE` | `POLLIN` (if requested) |
| `POLL_WRITABLE` | `POLLOUT` (if requested) |
| `POLL_READ_CLOSED` | `POLLIN \| POLLRDHUP` |
| `POLL_READ_CLOSED` + `POLL_WRITE_CLOSED` | additionally `POLLHUP` |
| `POLL_ERROR` | `POLLERR` |

`POLLIN` for READ_CLOSED matches Linux: EOF is a readable condition (read()
returns 0). `POLLHUP` only when both directions are gone (Linux reports
`POLLHUP` for fully-closed, `POLLRDHUP` for peer half-close). `POLLHUP`,
`POLLERR`, `POLLNVAL` are reported even when `events == 0`.

### H.4.4 The listener trap (and arming)

Listener READABLE events are generated **only in `on_response`**
(`rt_tcp.rs:174`) — i.e. only when accept *requests* have been posted to
sys-io. The nonblocking path posts them from `listen()` (`rt_tcp.rs:250+`,
which — M6 pitfall — requires the VDSO nonblocking flag); the blocking path
posts one *inside* each `accept()` call. A blocking-mode listener that is
merely being polled has posted nothing ⇒ **`poll()` on it would never fire**,
even with connections pending in sys-io. This is the classic
poll-then-accept server loop, so it must work.

Fix, in the pseudo-socket table (`socket.cpp`): add an `armed` flag. When
`Poll` encounters a Listening pseudo-fd that isn't armed:

```c
moto_rt_net_set_nonblocking(real, 1);      // satisfy rt_tcp.rs:250's precondition
moto_rt_net_listen(real, backlog_or_32);   // posts async accept requests
ps->armed = true;                          // one-way; VDSO-level mode is now nonblocking
```

From then on the *VDSO-level* socket is nonblocking; the app-visible mode
(`ps->nonblocking`) is unchanged. Consequently `Accept` on an armed listener
whose app-mode is blocking must emulate blocking:

```c
loop {
    r = moto_rt_net_accept(real, &peer);           // pops async_accepts or EAGAIN
    if (r != -MOTO_E_AGAIN(3)) break;
    tiny registry: new → add(real, READABLE) → wait(no deadline) → close;
}
```

The tiny-registry wait is the rare path (poll said readable, so the first
`accept` almost always succeeds); don't optimize it. `Listen` itself keeps its
M6 shape (bookkeeping-only for blocking sockets) — arming happens on first
poll, so programs that never poll keep the proven M6 blocking path, and
sysdep-side `Listen` on an app-nonblocking socket already arms via the real
`moto_rt_net_listen` (M6 behavior, unchanged).

### H.4.5 `Pselect` over the same core

`select()` is fd_set-shaped sugar. Convert: for each fd < num_fds set in
read/write/except sets, build a `pollfd` (`readfds → POLLIN`,
`writefds → POLLOUT`, `exceptfds → POLLERR`-only interest — Motor has no
OOB/exceptional conditions; except-set members can only report errors).
**Hard limitation, discovered on the VM:** `fd_set` is a fixed 1024-bit ABI
type and mlibc's `FD_SET` traps on `fd >= FD_SETSIZE` — so **pseudo-socket
fds (base `0x40000000`) can never be select()ed**. This is the same failure
mode as fd > 1023 on Linux, just hit by every `socket()` fd. `select()` on
Motor therefore works only on *real* fds: files, stdio, and `accept()`ed
streams. Anything touching `socket()` fds must use `poll()` (which handles
all fd kinds). Not fixable without redesigning the pseudo-fd scheme (e.g. a
VDSO "reserve fd now, bind object later" facility — M8+ wishlist).

Run the H.4.1 core with `timeout = ts ? ms(ts) : -1`. Convert back:
`POLLIN|POLLHUP|POLLERR → readfds`, `POLLOUT|POLLERR → writefds`,
`POLLERR → exceptfds`; `POLLNVAL → return EBADF` (select semantics differ from
poll here!). Result = number of *bits* set across the three sets (not fds) —
match Linux. `sigmask` ignored (no async signals). Zero-fd `select(0,…,ts)` =
portable sleep — make sure the "nothing registered" path sleeps accurately.

## H.5 Sysdep: signals-lite

New file `sysdeps/motor/generic/signals.cpp`; tags `Sigaction`, `Sigprocmask`,
`Kill`, `GetPid`. What mlibc routes where (verified):

- `signal()` → `sigaction()` → `Sysdeps<Sigaction>` (`ansi/generic/signal.cpp:15`).
- `raise(sig)` → `GetPid` + `Kill(pid, sig)` (`signal.cpp:23-26`).
- `abort()` → `Sigprocmask(UNBLOCK)` + `raise(SIGABRT)` + `Sigaction(DFL)` +
  `raise` again + `__builtin_trap` (`ansi/generic/stdlib.cpp:164-189`). With
  the design below, the *first* `raise` terminates with status 134 — closing
  the M3-era `m3 abort` gap.
- `sigprocmask()` → `Sysdeps<Sigprocmask>` (`signal.cpp:36`).

Design — **synchronous-only signals**, per-process:

```c
static FutexLock g_lock;                      // reuse socket.cpp's FutexLock
static struct sigaction g_disp[NSIG];         // dispositions; flags/mask stored, unused
static sigset_t g_procmask;                   // pure bookkeeping
```

| Sysdep | Semantics |
|---|---|
| `GetPid` | `(pid_t)moto_rt_getpid()` — real Motor pid (truncated to int; Motor pids are small). |
| `Sigaction(sn, act, old)` | `EINVAL` if `sn` ∉ [1, NSIG) or `sn` ∈ {SIGKILL, SIGSTOP} with non-null `act`. Record/return dispositions. No delivery machinery. |
| `Sigprocmask(how, set, old)` | Validate `how` (EINVAL else), maintain `g_procmask`, return old. Blocking is meaningless (nothing is ever delivered asynchronously) — bookkeeping only. |
| `Kill(pid, sig)` | `sig==0` → 0 if `pid==getpid()` else `ESRCH`. `pid!=getpid()` → `ESRCH` (we can't signal other processes — Motor kill takes a *handle*, not a pid). `pid==getpid()`: see below. |

`Kill(self, sig)` — the raise path:

1. Handler installed (`sa_handler` ∉ {SIG_DFL, SIG_IGN})? Call it **in the
   calling thread, synchronously**: `h(sig)`, return 0. This is conformant for
   `raise()` — POSIX requires the handler to run before `raise` returns.
   (One-shot `SA_RESETHAND` honored if trivial; otherwise ignore flags.)
2. `SIG_IGN` — return 0. Also `SIG_DFL` for the default-ignore set
   (`SIGCHLD`, `SIGURG`, `SIGWINCH`, `SIGCONT`) — return 0.
3. `SIG_DFL`, default-fatal (everything else, incl. `SIGABRT`, `SIGTERM`,
   `SIGINT`, `SIGSEGV`…) — `moto_rt_exit(128 + sig)`. No core dumps on Motor.
   `g_procmask` does **not** defer this (nothing is pending-able); document.

Deliberately absent (H.8): async delivery of any kind, `EINTR`, `SIGPIPE` (a
write to a closed socket already returns an error without killing the process
— i.e. Motor behaves as if `SIGPIPE` were always ignored, which is what every
real network program wants anyway), inter-process `kill`, `sigwait*`,
`sigaltstack`, `pthread_kill` (`Tgkill` — leave ENOSYS; add only if the M7
program trips on it).

## H.6 The real program: Lua 5.4

### Why Lua

| Candidate | Verdict |
|---|---|
| **Lua 5.4** | **Chosen.** Pure ISO C99, ~33 files, zero configure, fork-free by construction. Exercises the *depth* nothing has yet: `setjmp`/`longjmp` in anger (every `pcall`/error), `%.14g` float formatting, `strtod`, realloc-heavy GC churn on the M3 allocator, `time`/`clock`/`strftime`, `isatty` REPL, `signal()`. Interactive REPL on the Motor console is a satisfying "real program" demo, and a scriptable acceptance test. |
| sbase (suckless coreutils) | Good breadth, shallow depth — each tool exercises little. Worthwhile *stretch* after Lua (cat/wc/head/tail/sort build from the same recipe). Not the milestone gate. |
| Tiny HTTP server (darkhttpd et al.) | Best poll() consumer, but each candidate drags in platform-specific bits (sendfile, daemonize/fork, getpwnam) needing patches — porting friction without new libc coverage beyond what `m7.c` + mlibc's DNS-over-poll already prove. Revisit as a demo after M7. |
| Shell (dash/oksh) | fork()-shaped to the core. Not until Motor has posix_spawn-style process emulation in the libc story (M10+, if ever). |

Known-degraded stdlib corners, all graceful: `os.execute`/`io.popen` (mlibc
`system`/`popen` need fork → fail with error return; Lua surfaces `nil, errmsg`),
`os.tmpname` (no `/tmp`; don't use it in the acceptance script). Everything
else in `lua.c` + stdlib maps to sysdeps we have (or add at this milestone).

### Build recipe (host, like everything else)

```bash
cd /home/posk/motorh
curl -LO https://www.lua.org/ftp/lua-5.4.8.tar.gz     # or latest 5.4.x
tar xf lua-5.4.8.tar.gz && cd lua-5.4.8/src

B=/home/posk/motorh/llvm-project/build/bin
SYSROOT=/home/posk/motorh/motor-sysroot
CFLAGS="--target=x86_64-unknown-motor -O2 -isystem $SYSROOT/usr/include -DLUA_USE_POSIX"

# core+libs (everything except the two standalone drivers)
for f in $(ls *.c | grep -v -e '^lua\.c$' -e '^luac\.c$'); do
  $B/clang $CFLAGS -c $f || break
done
$B/llvm-ar rcs liblua.a *.o
$B/clang $CFLAGS lua.c liblua.a \
  $SYSROOT/usr/lib/crt1.o $SYSROOT/usr/lib/libc.a \
  $SYSROOT/usr/lib/libmoto_rt_cabi.a \
  $SYSROOT/usr/lib/libclang_rt.builtins-x86_64.a -o lua
```

`-DLUA_USE_POSIX`: gives real `isatty(0)` REPL detection (our `Isatty` is real,
via `moto_rt_is_terminal`) and `sigaction`-based SIGINT setup (our new sysdep).
If it drags in something unexpected, fall back to the plain ANSI build
(`lua_stdin_is_tty()` hardcodes 1 — fine on the console). Run the usual audit:
no `PT_TLS`, 0 non-RELATIVE relocs. Stage as `img_files/motor-os/bin/lua`
plus the acceptance script `m7.lua`.

### Acceptance script `m7.lua` (staged next to the binary)

Cover the libc surface Lua leans on; print `LUA: all tests passed` at the end:

1. arithmetic + `string.format("%.14g", …)` round-trips; `tonumber("0x1p-3")`,
   `"3.5e-2"` (strtod);
2. `pcall`/`error` nesting ×1000, plus `coroutine` ping-pong (setjmp/longjmp +
   Lua's own stack juggling);
3. table/GC stress: build and release a few hundred k table nodes,
   `collectgarbage("collect")`, check `collectgarbage("count")` shrinks
   (M3 allocator under realloc churn);
4. `io.open`/`write`/`lines`/`seek` under `/sys/tmp` (M4);
5. `os.time`, `os.clock`, `os.date("%Y-%m-%d", t)`;
6. `os.getenv`, `arg[]` handling;
7. degraded-but-graceful: `os.execute()` returns falsy, doesn't crash.

Run: `lua m7.lua`, then a by-hand REPL sanity poke (`print(1+1)`, Ctrl-ish
behaviors are out of scope — no async SIGINT).

## H.7 The gate test: `m7.c`

`src/tests/libc/m7.c`, same harness style as m3–m6 (CHECK macro, `stderr`
notes, `all tests passed`). Order matters: fail fast on the primitive Lua
depends on before blaming Lua.

1. **setjmp/longjmp smoke** (first real user!): `setjmp`, `longjmp(env, 7)`,
   check returned value + volatile side effects survive.
2. **Float formatting/parsing**: `snprintf %g/%.14g/%e` spot values;
   `strtod("2.5e-1")`, `strtod("0x1p+4")`, round-trip `1/3` through `%.17g`.
3. **poll basics (UDP)**: bound pair; `poll(POLLIN)` on empty → 0 after
   ~100ms (elapsed ≥ 90ms); self-send → `poll` → `revents == POLLIN`;
   `fd=-1` entry ignored; closed-fd entry → `POLLNVAL`.
4. **poll on a regular file**: `open()` under `/sys/tmp` → immediate
   `POLLIN|POLLOUT` (exercises the H.3.1 fallback — this used to be a VDSO
   panic).
5. **poll TCP server loop** (threaded, loopback, ports 347xx): listener
   `poll(POLLIN)` fires on pending connect **with the listener in blocking
   mode** (the H.4.4 arming path), `accept` completes; stream `POLLOUT` when
   connected; peer write → `POLLIN`; peer `close` → `POLLIN|POLLRDHUP`
   (+`POLLHUP` once both directions are down); drain read returns 0.
6. **select()**: same UDP pair through `select` (`FD_ISSET` in/out, timeout
   path, `select(0, …, 150ms)` as a sleep with elapsed check).
7. **signals**: `getpid() > 0`; `signal(SIGUSR1, handler)`; `raise(SIGUSR1)`
   sets the flag synchronously; `signal(SIGUSR1, SIG_IGN)` + `raise` → no-op;
   `sigprocmask` round-trips a mask; `kill(getpid()+12345, 0)` → `ESRCH`.
8. **`m7 abort` mode**: calls `abort()`; expected: process exits with status
   134, *no* mlibc panic banner (regression for the M3 gap).
9. **`m7 dns <name>` mode** (optional, config-dependent): `getaddrinfo(name)`
   over real DNS — exercises mlibc's resolver poll loop (lookup.cpp) in anger.
   Needs `/etc/resolv.conf` on the image pointing at a reachable resolver;
   skip silently if absent.

## H.8 Deliberate gaps (document, defer)

- **No async signals, no EINTR, ever.** `SA_RESTART` moot; `ppoll`/`pselect`
  sigmasks ignored; console Ctrl-C (if Motor ever delivers one) is not a
  SIGINT — it's whatever Motor does today (kills the process at most).
- **`POLLPRI`/OOB data** — no TCP urgent data on Motor; bit never set.
- **Fresh (unbound, unconnected) TCP pseudo-fd in `poll`** — reports nothing,
  forever (no real fd to register). POSIX behavior for an unconnected socket
  is murky anyway; documented, not solved.
- **Registry-per-call cost** — one fd alloc + registration round per `poll()`.
  Fine for poll-loop-per-connection programs; a per-thread cached registry
  with interest diffing is the M8+ optimization if a profile ever demands it.
- **`fstat` on sockets** still isn't `S_IFSOCK` (G.6 carry-over).
- **`Tgkill`/`pthread_kill`, `sigwait*`, `sigaltstack`, `Sigsuspend`** — ENOSYS.
- **`select` is real-fds-only**: pseudo-socket fds (≥ `0x40000000`) exceed
  `FD_SETSIZE` (1024), and mlibc's `FD_SET` traps on them — `socket()` fds
  cannot be select()ed at all (accept()ed streams, files, stdio can). Use
  `poll()`. Fixing this needs a VDSO fd-reservation facility so `socket()`
  can hand out low real fd numbers before the Motor object exists (M8+
  wishlist; would eliminate the whole pseudo-fd table).
- **Lua stdlib corners**: `os.execute`/`io.popen`/`os.tmpname` degraded as
  described in H.6.
- **mlibc hardcodes classic Unix `/etc` paths** — Motor OS has no native
  `/etc`, so the image now stages one (`img_files/motor-os/etc/`). Staged so
  far: `resolv.conf` (DNS for `getaddrinfo`; `m7 dns <name>` needs it). If
  these paths should ever move somewhere more Motor-shaped, every one is a
  string literal in mlibc — the inventory:
  - `/etc/resolv.conf` — `options/posix/generic/resolv_conf.cpp:9`; **only
    the first `nameserver` line is honored** (multi-nameserver is a TODO
    there).
  - `/etc/hosts` — `options/posix/generic/lookup.cpp` (two call sites).
  - `/etc/passwd`, `/etc/group` — `pwd.cpp` / `grp.cpp` (will matter for
    M9-era tools that call `getpwuid`).
  - `/etc/protocols` — `netdb.cpp:34`; `/etc/shells` — `unistd.cpp`;
    `/etc/localtime` — `options/ansi/generic/time.cpp:446,549,794` (TZ data;
    absent ⇒ UTC).
- **Float↔text is faithful, not correctly-rounded** (post-fix, see Pitfalls):
  `%.17g` round-trips are bit-exact (fuzz: 2M/2M) and printed strings match
  glibc except a last-digit ±1 in ~0.4% of values; `strtod` of arbitrary
  ≥20-significant-digit strings can be 1 ULP off (0.08% of torture inputs).
  Guaranteed correct rounding requires a bignum fallback (Dragon4/Ryu) in
  frigg/mlibc — upstream-scale work, deferred.

## H.9 Build, stage, run + exit criteria

Order: (1) VDSO hardening + shim v6 → rebuild vdso + cabi, reinstall
`moto_rt.h`/`libmoto_rt_cabi.a` into the sysroot; (2) mlibc: new
`poll.cpp`/`signals.cpp`, `socket.cpp` arming, `sysdeps.hpp` tags,
`meson.build` → `ninja && DESTDIR=$SYSROOT ninja install`; (3) `m7.c` build +
relink m2–m6 against the fresh `libc.a`; (4) Lua build; (5) stage `m7`,
`lua`, `m7.lua` in `img_files/motor-os/bin/`; user runs `make img` + VM.

Exit criteria — all on Motor OS in a VM, user-run:

- [x] `m7` prints `all tests passed` (2026-07-03; incl. reruns after fixes).
- [x] `m7 abort` exits with status 134, no mlibc panic banner (2026-07-03 —
      closes the M3-era `sigaction failed in abort` gap).
- [x] m2–m6 still pass (no regression from shim v6 / mlibc rebuild).
- [x] Rust programs still healthy (shell/boot fine across many image
      rebuilds with the hardened VDSO).
- [x] `lua m7.lua` prints `LUA: all tests passed` (incl.
      `shell available: false` after the system(NULL) fix).
- [ ] Interactive: `lua` REPL on the console evaluates `print(2^10)`, `os.time()`,
      a multi-line function; `os.exit()` leaves cleanly.
- [~] (Optional) `m7 dns <name>` — **deferred, environmental**: the host has
      no external connectivity right now (`ping 8.8.8.8` fails on the host),
      so the VM can't reach any resolver. The pieces are in place for later:
      `img_files/motor-os/etc/resolv.conf` staged (nameserver 8.8.8.8; only
      the first line is honored — see the H.8 inventory of mlibc's hardcoded
      `/etc` paths, added after `m7 dns google.com` hit "could not resolve
      DNS service" on an image with no `/etc` at all). Re-run when the host
      is online.
- [x] Record here: poll-on-file works **yes** (`M7: poll file ok`);
      listener-arming path taken **yes** (`M7: note: blocking-listener poll
      fired (arming path)`).

### Build log (2026-07-03) — implementation complete, host-side

All deliverables built and staged; awaiting VM verification.

| Piece | Status |
|---|---|
| VDSO hardening (posix.rs trait defaults → `E_INVALID_ARGUMENT`) | done, `cargo check` clean; ships with the next `make img` |
| Shim v6: 6 poll exports + `moto_rt_getpid`, Event size assert | built + installed into the sysroot |
| `poll.cpp` (`Poll` + `Pselect` over shared `do_poll`) | in `libc.a` |
| `signals.cpp` (`Sigaction`/`Sigprocmask`/`Kill`/`GetPid`) | in `libc.a` |
| `socket.cpp`: `armed`+`backlog` fields, poll-time arming (`motor_sock_pollfd`), blocking-`accept` emulation, `F_SETFL` pins armed listeners nonblocking | in `libc.a` |
| `m7` + relinked `m2`–`m6` | staged, reloc audit clean (0 non-RELATIVE, no PT_TLS) |
| Lua 5.4.8 (`-DLUA_USE_POSIX`) | **compiled with zero patches**; `lua` staged, audit clean |
| `m7.lua` | staged; validated end-to-end against a host-built Lua 5.4.8 |

As-implemented notes (differences from / additions to the plan above):

- `Sysdeps<Accept>` on an unmaterialized pseudo-fd now returns `EINVAL`
  (was `ENOTCONN` via `resolve_for_io`) — `EINVAL` is POSIX's "not listening".
- `fcntl(F_SETFL)` clearing `O_NONBLOCK` on an **armed** listener keeps the
  VDSO-level socket nonblocking (disarming would silence its readiness
  events); only the app-visible mode flips, and accept() emulates blocking.
- `m7.lua` gotcha found during host validation: nested `pcall`s are C calls,
  capped by `LUAI_MAXCCALLS` (200) — the script does 1000 *sequential*
  error round-trips + nesting to depth 50, not depth-1000 nesting.
- Host validation of `m7.lua`: numbers/pcall/coroutines/GC/strings/io/time/env
  all pass on a host-built Lua 5.4.8, so any Motor-side failure is a libc/OS
  issue, not a script bug.

### Pitfalls found during M7 (fill as they happen)

- **mlibc `system(NULL)` answers "shell available" with a panic banner**
  (2026-07-03, VM, via Lua's `os.execute()`). POSIX: `system(NULL)` is the
  "is a shell available?" probe — no shell must mean a quiet `return 0`. mlibc
  ran its `MLIBC_CHECK_OR_ENOSYS(Fork && Execve && …)` *before* the NULL
  special case, printing the missing-sysdep banner and returning -1 — which
  Lua faithfully reported as `shell available: true`. Fix (upstreamable):
  handle `command == NULL` first, answering 0 when the fork/exec sysdeps are
  unimplemented (`options/ansi/generic/stdlib.cpp`). `system("cmd")` still
  returns -1/ENOSYS as before.

- **fd-number reuse can alias the per-call poll registry** (2026-07-03, VM).
  `poll()` on a just-closed fd returned 0 instead of `POLLNVAL`: posix fd
  numbers are reused lowest-first, so the lazily-created registry was
  assigned the *closed fd's number* — registering that number then targeted
  the registry itself (whose `poll_add` rejects non-READABLE interests with
  `E_INVALID_ARGUMENT`, which the sysdep maps to "unpollable ⇒ always ready
  for requested ops" ⇒ zero revents for a zero-events entry). Fix in
  `do_poll`: create the registry *before* classifying caller fds, and treat
  any caller fd that resolves to `regfd` as stale ⇒ `POLLNVAL` (the caller
  cannot legitimately hold a registry created inside this very call). The
  general fd-reuse ambiguity (stale fd == some *other* live fd) is inherent
  to POSIX fd semantics and exists on Linux too.

- **mlibc/frigg floating-point text conversion loses ULPs — both directions**
  (2026-07-03, first VM run; the first *mlibc-upstream* bug class the ladder
  has caught, as opposed to Motor OS bugs). `m7` failed its `%.17g` →
  `strtod` round-trip check. Host-side reproduction quantified it:
  - *printing*: frigg's `print_float` extracted digits via
    `fracpart * pow(10, precision)` **in double** (`frg/formatting.hpp`,
    the old `modf`/`rint` block) — at precision 17 the product needs ~57 bits,
    so the last digits were garbage: vs glibc, **77% of random doubles
    printed a different `%.17g` string, 29% failed round-trip even through
    glibc's perfect strtod**. `%.14g` (Lua's format) was unaffected — which is
    why everything looked fine until the 17-digit check.
  - *parsing*: mlibc's `strtofp` accumulated `result += digit / d` **per
    fractional digit in the target type** — one rounding per digit, several
    ULPs off on ordinary inputs. (Bonus: `1e999999999` looped ~10⁹ iterations
    in its exponent scaler.)

  **Fix, both sides in extended precision (x86-64 80-bit, 64-bit mantissa):**
  - `strtofp.hpp`: digits parse exactly into a u64 mantissa (≤19 significant)
    + decimal exponent, then one scale via an exact 10⁰…10²⁷ long-double
    table (10²⁷ = 2²⁷·5²⁷, 5²⁷ < 2⁶³ ⇒ exactly representable); larger
    exponents compose at 2⁻⁶⁴ relative error per 27 decades. Hex floats are
    now fully exact (`ldexpl`). Exponent parse clamped (no more 10⁹-iteration
    loops).
  - frigg `formatting.hpp`: `print_float` mantissa/digit extraction moved to
    long double with the same exact pow10 table (no `powl`/`rintl` libm
    deps; half-up tie rounding). Also fixed a latent `floor(log10())`
    under-estimate case. **frigg is meson-wrap-managed (gitignored!)** — the
    patch lives as `subprojects/packagefiles/frigg-print-float-long-double.patch`
    wired via `diff_files` in `frigg.wrap`, or it would vanish on a fresh
    checkout.

  **Verification (host fuzz vs glibc):** round-trip `v → %.17g → strtod ≡ v`
  bit-exact for **2M/2M random doubles** (was 71%); golden strings
  (1/3, 0.1, π, DBL_MIN, DBL_MAX) glibc-identical; ~0.36% of random doubles
  still print a last-digit-±1 string difference vs glibc (a ±10⁻¹⁷ relative
  perturbation ≪ half-ULP, so round-trips are unaffected) and arbitrary
  ≥20-digit torture strings parse within 1 ULP in 0.08% of cases — full
  correct rounding for those needs a bignum fallback (Dragon4/Ryu class),
  a deliberate non-goal recorded in H.8. `m7` now gates on the golden
  strings, exact strtod cases, and a 20k in-test round-trip fuzz.
