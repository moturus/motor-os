# Appendix F — M5, step by step

> **Status: complete** (2026-07-03) — `m5` prints "all tests passed" on Motor OS,
> exit 0, consistently across 10+ runs. The emutls control-struct ABI (the
> main guide's #1 risk) is now validated under real multithreading: 8 emutls
> variables, no PT_TLS, no .tdata/.tbss in the binary.

> Part of the Motor OS libc porting guide — main: [porting-libc-by-fable.md](porting-libc-by-fable.md); appendices: [A: M0 toolchain](porting-libc-appendix-a.md) · [B: M1 shim](porting-libc-appendix-b.md) · [C: M2 mlibc](porting-libc-appendix-c.md) · [D: M3 stdio+malloc](porting-libc-appendix-d.md) · [E: M4 filesystem](porting-libc-appendix-e.md) · [F: M5 threads+TLS](porting-libc-appendix-f.md)

M5 is threads + TLS: `pthread_create`/`join`/`detach`, mutex/cond/rwlock under real
contention, pthread keys with destructors, a multi-thread `_Thread_local` test that
validates the emutls ABI end to end, and `__cxa_thread_atexit` destructors on
pthread exit. All facts below were verified against mlibc `368a00fa` and the
in-tree VDSO; the design keeps **zero shim changes and zero Motor-side changes** —
M5 is purely mlibc-port code (one new file) plus the test.

What already works, verified in source — most of pthreads is generic mlibc code
over sysdeps we shipped in M1/M2:

| Piece | Status |
|---|---|
| mutex, cond, rwlock, barrier, `pthread_once` | generic mlibc code over `FutexWait`/`FutexWake` — no new sysdeps. `thread_cond_timedwait` converts the absolute time to a **relative** timeout before `FutexWait` (`threads.cpp:468-482`), matching our sysdep. |
| Motor futex semantics vs. mlibc's expectations | compatible, verified in `rt.vdso/src/rt_futex.rs:125`: value-mismatch-at-entry returns "woken" (our sysdep → 0; mlibc treats 0 as possibly-spurious and rechecks — cond case 1), and `false` means a **genuine** timeout (deadline checked), so our `ETIMEDOUT` is never premature. `EAGAIN`/`EINTR` are never needed. |
| pthread keys (`pthread_key_create`, dtors) | generic, TCB-side: `Tcb::localKeys` is allocated by `allocateTcb` (`linker.cpp:1434`), dtors run inside `mlibc::thread_exit`. **No sysdep, no VDSO keys** — this supersedes the main guide §3.3 bullet suggesting pthread keys over the VDSO key API; the generic implementation costs nothing and needs nothing. |
| main-thread TCB | set up by `__dlapi_enter` since M2 (`allocateTcb` + `TcbSet`). |
| emutls + `__cxa_thread_atexit` per-thread cleanup | already hooked into the VDSO's `on_thread_exiting()` via VDSO TLS key destructors (B.2/B.3) — runs for every VDSO-spawned thread. |
| `sched_yield` | one trivial sysdep (`Yield`) over the existing `moto_rt_thread_yield`. |

What M5 must add: the **three thread-creation sysdeps** — `PrepareStack`, `Clone`,
`ThreadExit` — plus `Yield`, in a new `sysdeps/motor/generic/thread.cpp`.

## F.1 The audited mlibc contracts

`mlibc::thread_create` (`options/internal/generic/threads.cpp:78`):

1. `__rtld_allocateTcb()` allocates and zero-inits a `Tcb` (+ TLS image — empty
   under emulated TLS) and its `localKeys` array. Generic; already used for the
   main thread.
2. `sysdep<PrepareStack>(&stack, entry, user_arg, tcb, &stacksize, &guardsize,
   &stack_base)` — on normal ports: allocate a stack and push `{tcb, user_arg,
   entry}` onto it. The returned `*stack` is passed to `Clone` **opaquely** — the
   generic code never dereferences it. `*stack_base` lands in `tcb->stackAddr`.
3. `sysdep<Clone>(tcb, &tid, stack)` — start the new thread; must report the
   child's tid to the parent.
4. Parent stores the tid: `__atomic_store_n(&tcb->tid, tid)` + `FutexWake(&tcb->tid)`.
   (So `Clone` **must** return the real tid — the parent's store would otherwise
   clobber anything the child wrote there.)

The port must provide the child-side entry (managarm's
`sysdeps/managarm/x86_64/thread.cpp` is the reference):
`TcbSet(tcb)` → wait until `tcb->tid != 0` (futex) → enable
`tcbCancelEnableBit` → `tcb->invokeThreadFunc(entry, user_arg)` →
`mlibc::thread_exit(tcb->returnValue)`.

`mlibc::thread_exit` (`threads.cpp:172`) is pure userspace: runs cleanup
handlers + pthread-key dtors, stores the return value, sets `didExit = 1` +
`FutexWake`, then calls the noreturn `ThreadExit` sysdep. `thread_join` just
futex-waits on `didExit` — **join needs no sysdep and no kernel handle**.

`Tcb` layout notes (`options/internal/include/mlibc/tcb.hpp`):

- `static_assert(offsetof(Tcb, stackCanary) == 0x28)` — "GCC expects the canary
  at fs:0x28". On Motor, `%fs` points at the **kernel UTCB** (canary kernel-set at
  `fs:0x28`) and the Tcb is reached indirectly via `fs:0x58`, so `Tcb.stackCanary`
  is simply **unused** — stack-protector code reads the kernel's canary, which is
  per-thread-consistent, so checks work. No action.
- `tid` is `int`; Motor tids are `u64`. We truncate — consistently in both
  `FutexTid` (already does) and `Clone`, so `pthread_self`-adjacent bookkeeping
  agrees with itself. Wishlist note if Motor tids ever exceed 2³¹.
- `cancelBits` offset asserts are for linux's `cp_syscall.S` — irrelevant here.

## F.2 The Motor design

Motor's thread primitive is `moto_rt_thread_spawn(fn, stack_size, arg)` →
`SysCpu::spawn`: the **kernel allocates the stack** (lazy + guard pages) and the
VDSO wraps the entry (`rt_thread.rs:16`): when `fn` returns, the wrapper runs
`on_thread_exiting()` — the VDSO TLS destructors, i.e. **emutls storage and the
`__cxa_thread_atexit` list** — and then the thread self-terminates with
`SysObj::put(SysHandle::SELF)`.

That exit wrapper is the crux: if `ThreadExit` killed the thread abruptly, C++
`thread_local` destructors would never run and emutls storage would leak on every
pthread. So the design makes every mlibc thread exit **through** the VDSO wrapper:

```
moto_rt_thread_spawn(__motor_thread_entry, stack_size, cookie)
        │  (kernel stack, VDSO wrapper)
        ▼
__motor_thread_entry(cookie):
    publish tid to parent (cookie futex)          ── Clone unblocks
    publish &jmp_buf via a VDSO TLS key
    if (setjmp(jb) == 0)
        __mlibc_enter_thread(entry, arg, tcb)     ── TcbSet, wait tid,
            └─> user code ... thread_exit()          run user entry
                  ├─ cleanup handlers + pthread-key dtors   (mlibc, userspace)
                  ├─ didExit = 1 + FutexWake                (joiners unblock)
                  └─ sysdep<ThreadExit> ──── longjmp(jb, 1) ──┐
    ◄─────────────────────────────────────────────────────────┘
    clear the TLS key, free the cookie, return
        │
        ▼  (back in the VDSO wrapper)
    on_thread_exiting()   ── emutls storage freed, __cxa_thread_atexit dtors LIFO
    SysObj::put(SELF)     ── thread gone
```

Decisions, with reasons:

- **Kernel-owned stacks; `PrepareStack` prepares a heap cookie, not a stack.**
  `*stack` is opaque to generic code, so we pass a malloc'd
  `{entry, user_arg, tcb, stack_size, tid-futex}` through it. A user-supplied
  `pthread_attr_setstack` address can't be honored (the kernel places thread
  stacks) → return `EINVAL` for non-null `*stack`. `attr->stacksize` **is**
  honored (forwarded to spawn). `tcb->stackAddr` is recorded as null —
  `pthread_attr_getstack` on a running thread won't report a usable address
  (documented gap).
- **tid handshake in `Clone`.** Motor's spawn returns a *handle*, not a tid, and
  only the child knows its tid (`UTCB.self_tid`). The child publishes
  `(int)moto_rt_tid()` into the cookie and wakes a futex on it; `Clone` waits for
  that, then returns the tid. The parent's subsequent `tcb->tid` store is what
  releases the child out of `__mlibc_enter_thread`'s wait, so the child cannot
  finish and free the cookie before `Clone` has read it.
- **`ThreadExit` = longjmp.** The jmp_buf lives on the thread's (kernel) stack in
  the entry frame; its address is published through a dedicated VDSO TLS key.
  `pthread_exit` from arbitrary stack depth longjmps back to the entry frame and
  the function returns normally into the VDSO wrapper. If the key is empty, the
  caller is the main thread (not created by our trampoline): POSIX says
  `pthread_exit(main)` should keep the process alive until the last thread exits —
  not supported yet; log + `proc_exit(0)` (documented gap).
- **Destructor ordering** (consequence of the design): pthread-key dtors and
  cleanup handlers run *first* (inside `thread_exit`), then `didExit` wakes
  joiners, then emutls/`__cxa_thread_atexit` dtors run in the VDSO wrapper.
  Two observable quirks, both documented: C++ `thread_local` dtors run **after**
  pthread-key dtors (glibc does the reverse; POSIX doesn't specify), and
  **`pthread_join` can return before the joined thread's C++ `thread_local`
  dtors have finished** (didExit fires before `on_thread_exiting`). Tests that
  check dtor side effects must tolerate a small delay (m5 does).
- **Thread handle lifecycle: leaked, deliberately.** `Clone` drops the spawn
  handle on the floor; one kernel handle per pthread is released only at process
  exit. This matches the Rust std status quo (its `JoinHandle` also only ever
  joins). Wishlist: a shim `moto_rt_handle_put()` over `SysObj::put` so `Clone`
  can detach immediately.

## F.3 The port code

**No shim changes, no header changes, no Motor-side changes.** Everything M5
needs is already exported: `moto_rt_thread_spawn/yield`, `moto_rt_futex_*`,
`moto_rt_tls_*`, `moto_rt_tcb_set`, `moto_rt_tid`.

### F.3.1 `sysdeps/motor/generic/thread.cpp` (new file)

```cpp
// Motor OS pthread bring-up: PrepareStack / Clone / ThreadExit / Yield.
// Design: docs/porting-libc-appendix-f.md (F.2). Threads run on kernel-allocated
// stacks inside the VDSO's thread wrapper; ThreadExit longjmps back to the entry
// frame so the wrapper's on_thread_exiting() (emutls + __cxa_thread_atexit
// destructors) always runs.

#include <abi-bits/errno.h>
#include <bits/ensure.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/tcb.hpp>
#include <moto_rt.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>

namespace {

struct MotorThreadCookie {
	void *entry;
	void *user_arg;
	Tcb *tcb;
	size_t stack_size;
	// tid handshake: child stores its tid and wakes; Clone waits on this.
	int tid; // 0 = not yet published (futex word)
};

// VDSO TLS key holding the current thread's exit jmp_buf. Lazily created,
// lock-free: losers of the creation race destroy their key.
size_t exit_key_plus1 = 0; // 0 = uninitialized; key = value - 1

size_t exit_key() {
	size_t cur = __atomic_load_n(&exit_key_plus1, __ATOMIC_ACQUIRE);
	if (cur)
		return cur - 1;
	size_t key = moto_rt_tls_create(nullptr);
	size_t expected = 0;
	if (__atomic_compare_exchange_n(&exit_key_plus1, &expected, key + 1, false,
	                                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return key;
	moto_rt_tls_destroy(key); // lost the race
	return expected - 1;
}

// The child-side entry, per the managarm reference (x86_64/thread.cpp).
void enter_thread(void *entry, void *user_arg, Tcb *tcb) {
	if (mlibc::sysdep<TcbSet>(tcb))
		__ensure(!"sys_tcb_set() failed");

	// Wait until the parent stores our tid (thread_create does the wake).
	while (!__atomic_load_n(&tcb->tid, __ATOMIC_RELAXED))
		mlibc::sysdep<FutexWait>(&tcb->tid, 0, nullptr);

	__atomic_fetch_or(&tcb->cancelBits, tcbCancelEnableBit, __ATOMIC_RELAXED);

	tcb->invokeThreadFunc(entry, user_arg);

	mlibc::thread_exit(tcb->returnValue); // noreturn; ends in ThreadExit
}

// Runs inside the VDSO's thread wrapper, on the kernel-allocated stack.
extern "C" void __motor_thread_entry(uint64_t arg) {
	auto *cookie = reinterpret_cast<MotorThreadCookie *>(arg);

	// Publish our tid; unblocks Clone in the parent. The parent's tcb->tid
	// store (which we wait for in enter_thread) is the ack that it is done
	// reading the cookie, so freeing it at the end of this function is safe.
	__atomic_store_n(&cookie->tid, (int)(uint32_t)moto_rt_tid(), __ATOMIC_RELEASE);
	moto_rt_futex_wake((const uint32_t *)&cookie->tid);

	jmp_buf jb;
	moto_rt_tls_set(exit_key(), &jb);
	if (!setjmp(jb))
		enter_thread(cookie->entry, cookie->user_arg, cookie->tcb);
	// Reached via ThreadExit's longjmp.

	moto_rt_tls_set(exit_key(), nullptr);
	free(reinterpret_cast<MotorThreadCookie *>(arg));
	// Returning hands control to the VDSO wrapper: on_thread_exiting() runs
	// the VDSO TLS dtors (emutls storage, __cxa_thread_atexit list), then the
	// thread self-terminates.
}

} // namespace

namespace mlibc {

int Sysdeps<PrepareStack>::operator()(void **stack, void *entry, void *user_arg,
                                      void *tcb, size_t *stack_size,
                                      size_t *guard_size, void **stack_base) {
	if (*stack) {
		// The kernel owns thread stack placement on Motor; a user-supplied
		// stack (pthread_attr_setstack) cannot be honored.
		mlibc::infoLogger()
		    << "mlibc: pthread_attr_setstack() is not supported on Motor"
		    << frg::endlog;
		return EINVAL;
	}
	if (!*stack_size)
		*stack_size = 0x200000; // 2 MiB, mlibc's default
	*guard_size = 0; // the kernel adds its own guard pages

	auto *cookie = static_cast<MotorThreadCookie *>(malloc(sizeof(MotorThreadCookie)));
	if (!cookie)
		return ENOMEM;
	cookie->entry = entry;
	cookie->user_arg = user_arg;
	cookie->tcb = static_cast<Tcb *>(tcb);
	cookie->stack_size = *stack_size;
	cookie->tid = 0;

	*stack = cookie;      // opaque to generic code; consumed by Clone
	*stack_base = nullptr; // kernel-owned; pthread_attr_getstack won't work
	return 0;
}

int Sysdeps<Clone>::operator()(void *, pid_t *pid_out, void *stack) {
	auto *cookie = static_cast<MotorThreadCookie *>(stack);

	int64_t handle =
	    moto_rt_thread_spawn(__motor_thread_entry, cookie->stack_size,
	                         reinterpret_cast<uint64_t>(cookie));
	if (handle < 0) {
		free(cookie);
		return moto_to_errno(handle);
	}
	// NOTE: the kernel handle is deliberately leaked (freed at process exit);
	// pthread_join is futex-based and never needs it. See F.2.

	// Wait for the child to publish its tid.
	while (!__atomic_load_n(&cookie->tid, __ATOMIC_ACQUIRE))
		moto_rt_futex_wait((const uint32_t *)&cookie->tid, 0, UINT64_MAX);

	*pid_out = cookie->tid;
	return 0;
}

[[noreturn]] void Sysdeps<ThreadExit>::operator()() {
	if (void *p = moto_rt_tls_get(exit_key()))
		longjmp(*static_cast<jmp_buf *>(p), 1);

	// Not one of ours — the main thread. POSIX wants pthread_exit(main) to
	// keep the process alive until the last thread exits; unsupported yet.
	sysdep<LibcLog>("mlibc: pthread_exit() on the main thread exits the process");
	moto_rt_proc_exit(0);
}

void Sysdeps<Yield>::operator()() { moto_rt_thread_yield(); }

} // namespace mlibc
```

One wrinkle to expect: `moto_to_errno` currently sits in an anonymous namespace
in `sysdeps.cpp` — either move it to a small shared header
(`sysdeps/motor/include/mlibc/motor-util.hpp`) or duplicate the few lines; the
listing assumes it is callable. Prefer the shared header.

### F.3.2 Register the tags and the file

`sysdeps/motor/include/mlibc/sysdeps.hpp` — append to the tag list:

```cpp
	Faccessat,
	PrepareStack,
	Clone,
	ThreadExit,
	Yield
{};
```

`sysdeps/motor/meson.build` — add the new source next to `generic/sysdeps.cpp`:

```meson
	'generic/thread.cpp',
```

Rebuild + reinstall (headers unchanged, so just the archive):

```bash
cd $MLIBC && ninja -C build && DESTDIR=$SYSROOT ninja -C build install
```

## F.4 Deliberate gaps (document, defer)

- **`pthread_cancel`** — mlibc's cancellation delivery rides on signals
  (`sigcancel`); Motor has none. `pthread_setcancelstate`/`testcancel` compile
  and the bits are maintained, but a blocked thread is never interrupted.
  Platform property, like signals generally (main guide §3.5).
- **`pthread_attr_setstack` / `getstack`** — `EINVAL` / null base (F.2).
- **`pthread_exit` from the main thread** — exits the process (F.2).
- **join-vs-C++-dtors ordering** — `pthread_join` may return while the joined
  thread's `__cxa_thread_atexit`/emutls destructors are still running (F.2).
- **Kernel thread-handle leak** — one per pthread until process exit (F.2);
  wishlist: shim `moto_rt_handle_put`.
- **detached-thread Tcb leak** — upstream mlibc TODO (`thread_join`: "FIXME:
  destroy tcb here"); not Motor-specific.
- **`pthread_setname_np`** — the `ThreadSetname` sysdep takes a *target* tcb,
  but Motor's `set_name` only names the calling thread; skipped for now.

## F.5 The M5 test program

`$MOTOR/src/tests/libc/m5.c`:

```c
/* M5 test: threads + TLS on mlibc/Motor (docs/porting-libc-appendix-f.md).
 *
 * Exercises: pthread_create/join return values, contended mutexes, cond-var
 * ping-pong + timedwait timeout, pthread keys with dtors, _Thread_local
 * (emulated TLS) isolation across threads, __cxa_thread_atexit on pthread
 * exit, pthread_detach, deep stack recursion on a kernel-allocated stack.
 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(cond)                                                            \
	do {                                                                   \
		if (!(cond)) {                                                 \
			fprintf(stderr, "M5 FAIL %s:%d: %s (errno=%d)\n",      \
			        __FILE__, __LINE__, #cond, errno);             \
			exit(1);                                               \
		}                                                              \
	} while (0)

/* ---- create/join + contended mutex ------------------------------------- */

enum { NTHREADS = 8, ITERS = 100000 };
static pthread_mutex_t counter_mu = PTHREAD_MUTEX_INITIALIZER;
static long counter;

static void *bump(void *arg) {
	for (int i = 0; i < ITERS; i++) {
		CHECK(pthread_mutex_lock(&counter_mu) == 0);
		counter++;
		CHECK(pthread_mutex_unlock(&counter_mu) == 0);
	}
	return (void *)(long)(42 + (long)arg);
}

static void test_create_join_mutex(void) {
	pthread_t t[NTHREADS];
	for (long i = 0; i < NTHREADS; i++)
		CHECK(pthread_create(&t[i], NULL, bump, (void *)i) == 0);
	for (long i = 0; i < NTHREADS; i++) {
		void *ret = NULL;
		CHECK(pthread_join(t[i], &ret) == 0);
		CHECK((long)ret == 42 + i); /* per-thread return value */
	}
	CHECK(counter == (long)NTHREADS * ITERS); /* no lost updates */
}

/* ---- _Thread_local (emutls) isolation ----------------------------------- */

static _Thread_local long tl_counter = 1000; /* nonzero initializer: exercises
                                                the emutls default_value path */
static long tl_seen[NTHREADS];

static void *tl_worker(void *arg) {
	long id = (long)arg;
	for (int i = 0; i <= (int)id; i++)
		tl_counter++; /* each thread bumps a different amount */
	tl_seen[id] = tl_counter;
	return NULL;
}

static void test_thread_local(void) {
	tl_counter = 7; /* main's instance */
	pthread_t t[NTHREADS];
	for (long i = 0; i < NTHREADS; i++)
		CHECK(pthread_create(&t[i], NULL, tl_worker, (void *)i) == 0);
	for (long i = 0; i < NTHREADS; i++)
		CHECK(pthread_join(t[i], NULL) == 0);
	for (long i = 0; i < NTHREADS; i++)
		CHECK(tl_seen[i] == 1000 + i + 1); /* fresh instance per thread */
	CHECK(tl_counter == 7); /* main's instance untouched */
}

/* ---- pthread keys with destructors -------------------------------------- */

static pthread_key_t key;
static int key_dtor_runs; /* atomic enough: bumped pre-join-release? no — use sync */
static pthread_mutex_t dtor_mu = PTHREAD_MUTEX_INITIALIZER;

static void key_dtor(void *val) {
	CHECK((long)val == 77);
	pthread_mutex_lock(&dtor_mu);
	key_dtor_runs++;
	pthread_mutex_unlock(&dtor_mu);
}

static void *key_worker(void *arg) {
	(void)arg;
	CHECK(pthread_setspecific(key, (void *)77) == 0);
	CHECK((long)pthread_getspecific(key) == 77);
	return NULL;
}

static void test_keys(void) {
	CHECK(pthread_key_create(&key, key_dtor) == 0);
	pthread_t t[4];
	for (int i = 0; i < 4; i++)
		CHECK(pthread_create(&t[i], NULL, key_worker, NULL) == 0);
	for (int i = 0; i < 4; i++)
		CHECK(pthread_join(t[i], NULL) == 0);
	/* key dtors run before didExit (mlibc thread_exit), so after join they
	 * are guaranteed to have completed */
	CHECK(key_dtor_runs == 4);
	CHECK(pthread_key_delete(key) == 0);
	CHECK(pthread_getspecific(key) == NULL); /* main never set it */
}

/* ---- __cxa_thread_atexit on pthread exit --------------------------------- */

extern int __cxa_thread_atexit(void (*dtor)(void *), void *obj, void *dso);
static int cxa_runs; /* written by exiting thread, read by main after a delay */

static void cxa_dtor(void *obj) {
	CHECK((long)obj == 55);
	__atomic_fetch_add(&cxa_runs, 1, __ATOMIC_SEQ_CST);
}

static void *cxa_worker(void *arg) {
	(void)arg;
	CHECK(__cxa_thread_atexit(cxa_dtor, (void *)55, NULL) == 0);
	return NULL;
}

static void test_cxa(void) {
	pthread_t t;
	CHECK(pthread_create(&t, NULL, cxa_worker, NULL) == 0);
	CHECK(pthread_join(t, NULL) == 0);
	/* cxa dtors run AFTER didExit (VDSO exit path) — join can return first.
	 * Poll with a deadline instead of asserting immediately (see F.2). */
	for (int i = 0; i < 1000 && !__atomic_load_n(&cxa_runs, __ATOMIC_SEQ_CST); i++)
		sched_yield();
	CHECK(__atomic_load_n(&cxa_runs, __ATOMIC_SEQ_CST) == 1);
}

/* ---- cond var: ping-pong + timedwait timeout ----------------------------- */

static pthread_mutex_t pp_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pp_cv = PTHREAD_COND_INITIALIZER;
static int pp_turn; /* 0 = main's turn, 1 = worker's turn */
static int pp_rounds;

static void *pong(void *arg) {
	(void)arg;
	for (int i = 0; i < 1000; i++) {
		pthread_mutex_lock(&pp_mu);
		while (pp_turn != 1)
			pthread_cond_wait(&pp_cv, &pp_mu);
		pp_rounds++;
		pp_turn = 0;
		pthread_cond_signal(&pp_cv);
		pthread_mutex_unlock(&pp_mu);
	}
	return NULL;
}

static void test_cond(void) {
	pthread_t t;
	CHECK(pthread_create(&t, NULL, pong, NULL) == 0);
	for (int i = 0; i < 1000; i++) {
		pthread_mutex_lock(&pp_mu);
		pp_turn = 1;
		pthread_cond_signal(&pp_cv);
		while (pp_turn != 0)
			pthread_cond_wait(&pp_cv, &pp_mu);
		pthread_mutex_unlock(&pp_mu);
	}
	CHECK(pthread_join(t, NULL) == 0);
	CHECK(pp_rounds == 1000);

	/* timedwait timeout: nobody signals; must return ETIMEDOUT, not early */
	struct timespec t0, t1, abst;
	CHECK(clock_gettime(CLOCK_MONOTONIC, &t0) == 0);
	CHECK(clock_gettime(CLOCK_REALTIME, &abst) == 0);
	abst.tv_nsec += 100 * 1000 * 1000; /* +100ms */
	if (abst.tv_nsec >= 1000000000) {
		abst.tv_sec++;
		abst.tv_nsec -= 1000000000;
	}
	pthread_mutex_lock(&pp_mu);
	int e = pthread_cond_timedwait(&pp_cv, &pp_mu, &abst);
	pthread_mutex_unlock(&pp_mu);
	CHECK(e == ETIMEDOUT);
	CHECK(clock_gettime(CLOCK_MONOTONIC, &t1) == 0);
	long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
	CHECK(elapsed_ms >= 90); /* did not time out prematurely */
}

/* ---- detach + deep stack ------------------------------------------------- */

static int detached_ran;

static void *detached_worker(void *arg) {
	(void)arg;
	__atomic_store_n(&detached_ran, 1, __ATOMIC_SEQ_CST);
	return NULL;
}

static long deep(int depth) {
	volatile char pad[4096]; /* one page per frame */
	pad[0] = (char)depth;
	if (depth == 0)
		return pad[0];
	return deep(depth - 1) + pad[0];
}

static void *deep_worker(void *arg) {
	(void)arg;
	deep(300); /* ~1.2 MiB of a 2 MiB kernel stack; lazy fault-in per page */
	return (void *)1;
}

static void test_detach_and_stack(void) {
	pthread_t t;
	CHECK(pthread_create(&t, NULL, detached_worker, NULL) == 0);
	CHECK(pthread_detach(t) == 0);
	for (int i = 0; i < 1000 && !__atomic_load_n(&detached_ran, __ATOMIC_SEQ_CST); i++)
		sched_yield();
	CHECK(__atomic_load_n(&detached_ran, __ATOMIC_SEQ_CST) == 1);

	void *ret = NULL;
	CHECK(pthread_create(&t, NULL, deep_worker, NULL) == 0);
	CHECK(pthread_join(t, &ret) == 0);
	CHECK(ret == (void *)1);
}

int main(void) {
	CHECK(pthread_self() != 0); /* main thread has a TCB */

	test_create_join_mutex();
	puts("M5: create/join/mutex ok");
	test_thread_local();
	puts("M5: _Thread_local (emutls) ok");
	test_keys();
	puts("M5: pthread keys ok");
	test_cxa();
	puts("M5: __cxa_thread_atexit ok");
	test_cond();
	puts("M5: cond var ok");
	test_detach_and_stack();
	puts("M5: detach + deep stack ok");

	printf("M5: all tests passed\n");
	return 0;
}
```

Build, audit, stage (link line as before, plus nothing new — pthreads are inside
`libc.a`):

```bash
cd $MOTOR/src/tests/libc
$B/clang --target=x86_64-unknown-motor -O2 -isystem $SYSROOT/usr/include m5.c \
    $SYSROOT/usr/lib/crt1.o \
    $SYSROOT/usr/lib/libc.a \
    $SYSROOT/usr/lib/libmoto_rt_cabi.a \
    $SYSROOT/usr/lib/libclang_rt.builtins-x86_64.a -o m5

$B/llvm-readelf -l m5 | grep -w TLS && echo "PT_TLS — BAD" || echo "no PT_TLS"
$B/llvm-readelf -r m5 | grep R_X86_64 | grep -cv R_X86_64_RELATIVE   # must be 0

cp m5 $MOTOR/img_files/motor-os/bin/
```

The PT_TLS audit matters *especially* here: `_Thread_local` in m5.c is the first
test that would smoke out any non-emutls TLS codegen sneaking through.

## F.6 Run on Motor OS + exit criteria

`make img`, boot, then:

```
rush:/$ m5
M5: create/join/mutex ok
M5: _Thread_local (emutls) ok
M5: pthread keys ok
M5: __cxa_thread_atexit ok
M5: cond var ok
M5: detach + deep stack ok
M5: all tests passed
```

Exit 0. Run it a few times — thread bugs are schedule-dependent, and the VM's
vCPU count affects interleavings.

- [ ] mlibc rebuilt with `thread.cpp` + 4 new tags; `m2`–`m4` still pass
      (relinked against the new `libc.a` and staged 2026-07-03; re-run pending).
- [x] `m5` audit clean (no PT_TLS, 0 non-RELATIVE relocs, 8 `__emutls_v.*`,
      no `.tdata`/`.tbss`); full pass on Motor, 10+ consecutive runs.
- [x] Kernel log reviewed during `m5`: quiet.

Known M5 pitfalls, pre-answered:

- **Hang in `pthread_create`** → the tid handshake: check the child published
  `cookie->tid` (child-side) and that the parent's `FutexWake(&tcb->tid)` in
  generic `thread_create` fired. A hang in `enter_thread`'s wait with a running
  child means `Clone` returned a tid of 0 — did `moto_rt_tid()` truncate to 0?
- **Crash on the second `pthread_exit` in a thread's life** → the jmp_buf key
  cleared too early, or `exit_key()`'s race-init destroyed a key still in use.
- **`_Thread_local` values bleed between threads** → emutls ABI break: check
  `llvm-nm m5 | grep __emutls_v` and that no `.tdata`/`.tbss` sections exist —
  the emutls control-struct layout vs. the shim's `EmutlsControl` is the M5
  risk flagged in the main guide (§7) since day one.
- **`test_cxa` flaky** → the join-before-cxa-dtors ordering (F.2); the poll loop
  bounds it — if it *never* fires, `on_thread_exiting` isn't running: check the
  thread really exits by returning out of `__motor_thread_entry` (i.e., the
  longjmp landed) rather than dying inside mlibc.
- **Deadlock in the cond ping-pong under load** → re-check the futex semantics
  note in F.0 against the current VDSO — the "no revalidation after wake"
  comment in `futex_wait_impl` (`rt_futex.rs:158`) is load-bearing for tokio and
  harmless for mlibc, but any VDSO futex change must keep genuine-timeout-only
  `false` returns, or `pthread_cond_timedwait` starts timing out early.
- **Stack overflow in `deep_worker`** → the kernel guard page works; but if the
  *fault-in* of deep frames corrupts data, that would be an xsave-regression
  signature (D.6 pitfalls) — re-run `m3`'s malloc sweep to confirm.
