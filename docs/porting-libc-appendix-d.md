# Appendix D — M3, step by step

> Part of the Motor OS libc porting guide — main: [porting-libc-by-fable.md](porting-libc-by-fable.md); appendices: [A: M0 toolchain](porting-libc-appendix-a.md) · [B: M1 shim](porting-libc-appendix-b.md) · [C: M2 mlibc](porting-libc-appendix-c.md) · [D: M3 stdio+malloc](porting-libc-appendix-d.md) · [E: M4 filesystem](porting-libc-appendix-e.md) · [F: M5 threads+TLS](porting-libc-appendix-f.md)

> **Status: complete** (2026-07-02) — `m3` prints "all tests passed" on Motor OS;
> `m3 abort` terminates with status -1. Found and fixed a kernel bug along the way
> (SSE/AVX state lost on user page faults — see the D.6 pitfalls). Residual: re-run
> `m2` once as a sysdeps regression check (m3 exercises a superset, so low risk).

M2 proved the plumbing with one `printf` and one `malloc`. M3 proves the **ANSI-C
library surface** an application actually leans on: formatted I/O both directions
(`snprintf`/`sscanf`, `%f`), buffered **file** stdio round-trips (`fopen`/`fwrite`/
`fseek`/`ftell`/`fread`/`fgets`/`ungetc`/`setvbuf`), `remove`/`rename`, the allocator
under stress (size-class sweep, `realloc` content preservation, alloc/free churn that
recycles `AnonAllocate`/`AnonFree` mappings), string→number conversions with `errno`,
and the exit path (`atexit`, stdio flush-at-exit, `abort`). All of mlibc's internal
locks (allocator, per-`FILE`, `atexit` queue) run over our `FutexWait`/`FutexWake`
sysdeps — single-threaded they stay uncontended, so M3 exercises the lock code paths
while real contention waits for M5.

Facts below verified against the pinned mlibc `368a00fa` and the in-tree VDSO.
Environment: as C (A.0/B.0 + `MLIBC`, `SYSROOT`, `B`).

### D.1 The ENOSYS worklist (what's missing, and what M3 adds)

Unimplemented *optional* sysdeps surface at runtime: `sysdep_or_enosys<Tag>` returns
`ENOSYS`, and code that can't tolerate that logs via `LibcLog` → kernel log. Audit of
every optional tag reachable from the enabled ANSI option group (grep for
`sysdep_or_enosys<` under `options/ansi` + `options/internal`), with disposition:

| Tag | Called from | M3 disposition |
|---|---|---|
| `Rmdir` | `remove()` | **implement** (D.2/D.3) |
| `Unlinkat` | `remove()` fallback, `tmpfile()`, POSIX `unlink()` | **implement** |
| `Rename` | `rename()` | **implement** |
| `Stat` | locale-archive probe in `locale.cpp` (tolerates failure) | defer to M4 |
| `FdToPath` | `freopen(NULL, ...)` only; explicit-path `freopen` uses `Open` | defer |
| `Sigaction`, `Sigprocmask` | `signal()`, `raise()`, `abort()` | never (no signals; see D.6 on `abort`) |
| `ClockGetres`, `ClockSet` | `clock_getres`/`clock_settime` | defer (harmless ENOSYS) |

Two facts found in this audit that shape D.3:

1. **`remove()` needs `Rmdir` to return `ENOTDIR` on a file** to fall through to
   `Unlinkat` (`options/ansi/generic/stdio.cpp:757`). On Motor this fallback is
   moot: the VDSO's `rmdir` **is an alias of `unlink`** (`rt.vdso/src/rt_fs.rs:1132`),
   and `unlink` does `delete_entry` on *any* entry kind. So `remove()` succeeds on
   files and (empty) directories through the `Rmdir` path alone. The flip side is a
   POSIX fidelity gap — `rmdir()` on a file won't fail `ENOTDIR`, `unlink()` on a
   directory won't fail `EISDIR` — acceptable at M3, tighten at M4 when `Stat` gives
   the sysdep layer a way to check the entry kind first (or fix the VDSO).
2. **`tmpfile()` hardcodes `/tmp/tmpfile_XXXXXX`** (`stdio.cpp`, after the
   `Unlinkat` gate). Motor's writable tree is `/sys/tmp`, so `tmpfile()` fails with
   `ENOENT` even after M3. Not tested at M3; either create `/tmp` on the image or
   patch the pattern when something needs it.

Also run `m2`/`m3` while watching the kernel log for `mlibc:` lines — anything
beyond the table above goes on the M4 worklist.

### D.2 Shim v3 (motor-os repo): unlink / rename / rmdir

The VDSO already exposes all three (`moto_rt::fs::{unlink, rename, rmdir}`); the shim
just hasn't wrapped them. In `src/sys/lib/moto-rt-cabi/src/lib.rs`, next to
`moto_rt_mkdir`:

```rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_unlink(path: *const u8, path_len: usize) -> i32 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    match moto_rt::fs::unlink(path) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

/// NOTE: in today's VDSO rmdir aliases unlink (rt_fs.rs); we still wrap both
/// so the shim ABI tracks moto-rt's API, not the current implementation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_rmdir(path: *const u8, path_len: usize) -> i32 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    match moto_rt::fs::rmdir(path) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_rename(
    old_path: *const u8,
    old_len: usize,
    new_path: *const u8,
    new_len: usize,
) -> i32 {
    let old = match str_arg(old_path, old_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    let new = match str_arg(new_path, new_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    match moto_rt::fs::rename(old, new) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}
```

`moto_rt.h`, in the fs block after `moto_rt_mkdir`:

```c
int32_t moto_rt_unlink(const uint8_t *path, size_t path_len);
int32_t moto_rt_rmdir(const uint8_t *path, size_t path_len);
int32_t moto_rt_rename(const uint8_t *old_path, size_t old_len,
                       const uint8_t *new_path, size_t new_len);
```

Rebuild + restage per B.5 (archive + header into `$SYSROOT/usr`), and confirm the
new symbols landed before rebuilding mlibc:

```bash
nm $SYSROOT/usr/lib/libmoto_rt_cabi.a | grep -E "moto_rt_(unlink|rmdir|rename)$"
# expect three T lines
```

### D.3 sysdeps: `Rmdir`, `Unlinkat`, `Rename`

`$MLIBC/sysdeps/motor/include/mlibc/sysdeps.hpp` — add three tags to the list:

```cpp
	Isatty,
	GetEntropy,
	Rmdir,
	Unlinkat,
	Rename
{};
```

`$MLIBC/sysdeps/motor/generic/sysdeps.cpp` — after `Sysdeps<Close>`
(`abi-bits/fcntl.h`, already included, provides `AT_FDCWD`/`AT_REMOVEDIR`):

```cpp
int Sysdeps<Rmdir>::operator()(const char *path) {
	// The VDSO's rmdir currently aliases unlink and deletes any entry kind,
	// so remove() works on files through this path alone (its ENOTDIR->
	// Unlinkat fallback never fires on Motor). Cost: rmdir() on a file does
	// not fail with ENOTDIR as POSIX wants. Tighten when Stat lands (M4).
	return moto_to_errno(
	    moto_rt_rmdir(reinterpret_cast<const uint8_t *>(path), strlen(path)));
}

int Sysdeps<Unlinkat>::operator()(int dirfd, const char *path, int flags) {
	if (dirfd != AT_FDCWD && path[0] != '/')
		return EBADF; // no dirfd-relative resolution on Motor (openat is M4+)
	if (flags & AT_REMOVEDIR)
		return sysdep<Rmdir>(path);
	if (flags)
		return EINVAL;
	return moto_to_errno(
	    moto_rt_unlink(reinterpret_cast<const uint8_t *>(path), strlen(path)));
}

int Sysdeps<Rename>::operator()(const char *path, const char *new_path) {
	return moto_to_errno(moto_rt_rename(
	    reinterpret_cast<const uint8_t *>(path), strlen(path),
	    reinterpret_cast<const uint8_t *>(new_path), strlen(new_path)));
}
```

Rebuild + reinstall (incremental; the C.7 setup is already in place):

```bash
cd $MLIBC
ninja -C build && DESTDIR=$SYSROOT ninja -C build install
```

### D.4 What M3 deliberately does not add

- **`Stat`/`GetCwd`/dirs/`mkdir()`-the-sysdep** — that's M4 wholesale (the meat is
  translating Motor's `FileAttr` into `struct stat`). Where `m3` needs a directory
  it calls the shim's `moto_rt_mkdir` directly — the archive is linked in anyway.
- **Signals** — platform property (main guide §3.5). `signal()`/`raise()` fail cleanly with
  `ENOSYS`; `abort()` still terminates (D.6).
- **`FdToPath`** — only `freopen(NULL, ...)` wants it; revisit if a real program does.

### D.5 The M3 test program

`$MOTOR/src/tests/libc/m3.c` — self-checking; any failure prints the failing
expression + `errno` to stderr (unbuffered, so it always escapes) and exits 1:

```c
/* M3 test: the ANSI-C surface on mlibc/Motor (docs/porting-libc-appendix-d.md).
 *
 * Exercises: snprintf/sscanf (incl. %f), strtol/strtod + errno, malloc under
 * stress (size classes, realloc, churn), buffered file stdio (fwrite/fseek/
 * fread/fgets/fscanf/ungetc/setvbuf), remove/rename, atexit + exit-time flush.
 *
 * `m3`        -> "M3: all tests passed" + "M3: atexit ran", exit 0.
 * `m3 abort`  -> abort(); expect a nonzero exit status from rush.
 */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <moto_rt.h> /* moto_rt_mkdir: the mkdir() sysdep is an M4 item */

#define CHECK(cond)                                                            \
	do {                                                                   \
		if (!(cond)) {                                                 \
			fprintf(stderr, "M3 FAIL %s:%d: %s (errno=%d)\n",      \
			        __FILE__, __LINE__, #cond, errno);             \
			exit(1);                                               \
		}                                                              \
	} while (0)

#define DIR_TMP "/sys/tmp"
#define F1 "/sys/tmp/m3-a.dat"
#define F2 "/sys/tmp/m3-b.txt"
#define F3 "/sys/tmp/m3-c.txt"

static void test_printf_scanf(void) {
	char buf[128];
	snprintf(buf, sizeof buf, "%d|%u|%x|%05d|%-4s|%c|%lld|%zu",
	         -42, 42u, 0xbeef, 7, "ab", 'X', -1234567890123LL, (size_t)99);
	CHECK(strcmp(buf, "-42|42|beef|00007|ab  |X|-1234567890123|99") == 0);
	snprintf(buf, sizeof buf, "%.3f|%g", 3.14159, 0.5);
	CHECK(strcmp(buf, "3.142|0.5") == 0);
	CHECK(snprintf(NULL, 0, "%d", 123456) == 6); /* C99 size probe */

	int a = 0, b = 0;
	char s[16];
	CHECK(sscanf("17 dogs -9", "%d %15s %d", &a, s, &b) == 3);
	CHECK(a == 17 && b == -9 && strcmp(s, "dogs") == 0);
}

static void test_strconv(void) {
	char *end;
	CHECK(strtol("  -123abc", &end, 10) == -123 && strcmp(end, "abc") == 0);
	CHECK(strtoul("ff", NULL, 16) == 255);
	CHECK(strtol("0x20", NULL, 0) == 32);
	CHECK(strtod("2.5e2", &end) == 250.0 && *end == 0);
	errno = 0;
	CHECK(strtol("99999999999999999999", NULL, 10) == LONG_MAX
	      && errno == ERANGE);
}

static int sweep_failures;

/* Forensics for a corrupted sweep block: where the bad bytes are and what
 * values they hold discriminates the failure mechanism (0x00 = lost/zeroed
 * page; 0xa0+j = overlap with block j; pointer-like = allocator metadata).
 * This caught the xsave-on-#PF kernel bug (see the pitfalls in D.6). */
static void dump_block(int i, const unsigned char *p, size_t sz, unsigned want) {
	size_t bad = 0, first = (size_t)-1, last = 0;
	unsigned char vals[4];
	size_t val_counts[4] = {0};
	int nvals = 0;
	for (size_t k = 0; k < sz; k++) {
		if (p[k] == want)
			continue;
		bad++;
		if (first == (size_t)-1)
			first = k;
		last = k;
		int v;
		for (v = 0; v < nvals; v++)
			if (vals[v] == p[k])
				break;
		if (v < nvals)
			val_counts[v]++;
		else if (nvals < 4) {
			vals[nvals] = p[k];
			val_counts[nvals++] = 1;
		}
	}
	fprintf(stderr,
	        "M3 SWEEP BAD i=%d p=%p sz=%zu want=%02x: %zu bad, off [%zu, %zu]\n",
	        i, (const void *)p, sz, want, bad, first, last);
	for (int v = 0; v < nvals; v++)
		fprintf(stderr, "M3   bad value %02x x%zu\n", vals[v], val_counts[v]);
	sweep_failures++;
}

static int check_block(int i, const unsigned char *p, size_t sz, const char *phase) {
	unsigned want = 0xa0 + (unsigned)i;
	for (size_t k = 0; k < sz; k++)
		if (p[k] != want) {
			fprintf(stderr, "M3 SWEEP FAIL phase %s:\n", phase);
			dump_block(i, p, sz, want);
			return 0;
		}
	return 1;
}

static void test_malloc(void) {
	/* size-class sweep, 1 B .. 8 MiB (the top sizes force fresh vm_maps) */
	unsigned char *blocks[24];
	int n = 0;
	for (size_t sz = 1; sz <= (size_t)1 << 23; sz <<= 1) {
		unsigned char *p = malloc(sz);
		CHECK(p);
		memset(p, 0xa0 + n, sz);
		blocks[n++] = p;
	}
	/* pass A: verify all blocks, no frees yet */
	for (int i = 0; i < n; i++)
		check_block(i, blocks[i], (size_t)1 << i, "A (all live)");
	/* pass B: verify again — corruption appearing only now = async source */
	for (int i = 0; i < n; i++)
		check_block(i, blocks[i], (size_t)1 << i, "B (re-check)");
	/* pass C: interleave frees with checks — corruption appearing only now
	 * is triggered by unmap/free of a neighboring block */
	for (int i = 0; i < n; i++) {
		check_block(i, blocks[i], (size_t)1 << i, "C (freeing)");
		free(blocks[i]);
	}
	CHECK(sweep_failures == 0);

	unsigned char *z = calloc(1000, 4);
	CHECK(z);
	for (int i = 0; i < 4000; i++)
		CHECK(z[i] == 0);
	free(z);

	/* realloc must preserve content across a size-class change */
	char *r = malloc(100);
	CHECK(r);
	for (int i = 0; i < 100; i++)
		r[i] = (char)i;
	r = realloc(r, 50000);
	CHECK(r);
	for (int i = 0; i < 100; i++)
		CHECK(r[i] == (char)i);
	r = realloc(r, 10); /* shrink */
	CHECK(r && r[9] == 9);
	free(r);

	/* churn: bounded live set, pseudo-random sizes; recycles slab entries
	 * and, under the hood, AnonAllocate/AnonFree mappings */
	enum { SLOTS = 64 };
	unsigned char *slot[SLOTS] = {0};
	size_t slot_sz[SLOTS] = {0};
	unsigned lcg = 12345;
	for (int i = 0; i < 20000; i++) {
		lcg = lcg * 1103515245u + 12345u;
		unsigned idx = (lcg >> 16) % SLOTS;
		if (slot[idx]) {
			for (size_t k = 0; k < slot_sz[idx]; k++)
				if (slot[idx][k] != 0x5a) {
					fprintf(stderr,
					        "M3 CHURN BAD iter %d slot %u p=%p sz=%zu off=%zu val=%02x\n",
					        i, idx, (void *)slot[idx], slot_sz[idx], k,
					        slot[idx][k]);
					exit(1);
				}
			free(slot[idx]);
			slot[idx] = NULL;
		} else {
			size_t sz = ((lcg >> 8) % 4096) + 1;
			slot[idx] = malloc(sz);
			CHECK(slot[idx]);
			memset(slot[idx], 0x5a, sz);
			slot_sz[idx] = sz;
		}
	}
	for (int i = 0; i < SLOTS; i++)
		free(slot[i]);
}

static void test_file_io(void) {
	/* /sys/tmp may not exist on a fresh image (cf. m1) */
	int r = moto_rt_mkdir((const uint8_t *)DIR_TMP, strlen(DIR_TMP));
	CHECK(r == 0 || r == -MOTO_E_ALREADY_IN_USE);

	/* binary round-trip; 64 KiB spans many stdio buffer flushes */
	enum { N = 65536 };
	unsigned char *out = malloc(N), *in = malloc(N);
	CHECK(out && in);
	for (int i = 0; i < N; i++)
		out[i] = (unsigned char)(i * 7 + 1);

	FILE *f = fopen(F1, "w+");
	CHECK(f);
	CHECK(fwrite(out, 1, N, f) == N);
	CHECK(fflush(f) == 0);
	CHECK(fseek(f, 0, SEEK_END) == 0 && ftell(f) == N);
	CHECK(fseek(f, 1000, SEEK_SET) == 0 && ftell(f) == 1000);
	CHECK(fgetc(f) == out[1000] && ftell(f) == 1001);
	CHECK(fseek(f, -1, SEEK_CUR) == 0 && ftell(f) == 1000);
	rewind(f);
	CHECK(fread(in, 1, N, f) == N);
	CHECK(memcmp(in, out, N) == 0);
	CHECK(!feof(f));
	CHECK(fgetc(f) == EOF && feof(f));
	clearerr(f);
	CHECK(!feof(f) && !ferror(f));
	CHECK(fclose(f) == 0);

	/* ungetc */
	f = fopen(F1, "r");
	CHECK(f);
	CHECK(fgetc(f) == out[0]);
	CHECK(ungetc('Q', f) == 'Q');
	CHECK(fgetc(f) == 'Q');
	CHECK(fgetc(f) == out[1]);
	CHECK(fclose(f) == 0);
	free(out);
	free(in);

	/* text: fprintf out (unbuffered path via setvbuf), fgets/fscanf back */
	f = fopen(F2, "w");
	CHECK(f);
	CHECK(setvbuf(f, NULL, _IONBF, 0) == 0);
	CHECK(fprintf(f, "line one\nvalue %d %s\n", 42, "end") > 0);
	CHECK(fclose(f) == 0);

	f = fopen(F2, "r");
	CHECK(f);
	char line[64];
	CHECK(fgets(line, sizeof line, f) && strcmp(line, "line one\n") == 0);
	int v = 0;
	char w[16];
	CHECK(fscanf(f, "value %d %15s", &v, w) == 2);
	CHECK(v == 42 && strcmp(w, "end") == 0);
	CHECK(fclose(f) == 0);

	errno = 0;
	CHECK(fopen("/sys/tmp/m3-nonexistent", "r") == NULL && errno == ENOENT);
}

static void test_remove_rename(void) {
	CHECK(rename(F2, F3) == 0);
	errno = 0;
	CHECK(fopen(F2, "r") == NULL && errno == ENOENT); /* old name is gone */
	FILE *f = fopen(F3, "r");
	CHECK(f && fgetc(f) == 'l'); /* content moved with the entry */
	CHECK(fclose(f) == 0);

	CHECK(remove(F3) == 0); /* file, via the Rmdir sysdep (see D.1) */
	CHECK(remove(F1) == 0);
	errno = 0;
	CHECK(fopen(F1, "r") == NULL && errno == ENOENT);
	errno = 0;
	CHECK(remove(F1) == -1 && errno == ENOENT); /* already gone */

	/* empty directory via remove() */
	const char *d = "/sys/tmp/m3-dir";
	CHECK(moto_rt_mkdir((const uint8_t *)d, strlen(d)) == 0);
	CHECK(remove(d) == 0);
}

static void on_exit_hook(void) {
	/* proves atexit runs and stdio still works during exit */
	printf("M3: atexit ran\n");
}

int main(int argc, char **argv) {
	if (argc == 2 && strcmp(argv[1], "abort") == 0) {
		printf("M3: calling abort()\n");
		fflush(stdout);
		abort(); /* must not return; expect a nonzero exit status */
	}
	CHECK(atexit(on_exit_hook) == 0);

	test_printf_scanf();
	puts("M3: printf/scanf ok");
	test_strconv();
	puts("M3: strtol/strtod ok");
	test_malloc();
	puts("M3: malloc ok");
	test_file_io();
	puts("M3: file stdio ok");
	test_remove_rename();
	puts("M3: remove/rename ok");
	printf("M3: all tests passed\n");
	return 0;
}
```

(`MOTO_E_ALREADY_IN_USE` = 13 — add it to the error-code block in `moto_rt.h` if it
isn't there yet.)

Build, audit, stage — identical shape to C.8:

```bash
cd $MOTOR/src/tests/libc
$B/clang --target=x86_64-unknown-motor -O2 -isystem $SYSROOT/usr/include m3.c \
    $SYSROOT/usr/lib/crt1.o \
    $SYSROOT/usr/lib/libc.a \
    $SYSROOT/usr/lib/libmoto_rt_cabi.a \
    $SYSROOT/usr/lib/libclang_rt.builtins-x86_64.a -o m3

$B/llvm-readelf -l m3 | grep -w TLS && echo "PT_TLS — BAD" || echo "no PT_TLS"
$B/llvm-readelf -r m3 | grep R_X86_64 | grep -cv R_X86_64_RELATIVE   # must be 0

cp m3 $MOTOR/img_files/motor-os/bin/
```

### D.6 Run on Motor OS + exit criteria

`make img`, boot, then:

```
rush:/$ m3
M3: printf/scanf ok
M3: strtol/strtod ok
M3: malloc ok
M3: file stdio ok
M3: remove/rename ok
M3: all tests passed
M3: atexit ran
```

Exit 0 (silent). One kernel-log line is expected during the run:
`WARN sys-io/src/runtime/fs.rs: fs.create_entry(...) failed: Kind(AlreadyExists)` —
that's m3's unconditional `moto_rt_mkdir("/sys/tmp")`; the test tolerates
`AlreadyInUse` and sys-io logs the failed create on its side. Harmless.

Then `m3 abort`: prints `M3: calling abort()` and terminates with a **nonzero**
status. Observed on Motor (2026-07-02), traced through the code: mlibc's `abort()`
tries `raise(SIGABRT)` — `MLIBC_CHECK_OR_ENOSYS` prints
`__ensure(Library function fails due to missing sysdep) failed` (a soft check; no
`GetPid`/`Kill`) — then `sysdep_or_enosys<Sigaction>` prints the same, then
`mlibc: sigaction failed in abort` (panicLogger) → our `LibcPanic` sysdep logs
`!!! mlibc panic !!!` and calls `moto_rt_proc_exit(-1)`; rush reports
`[m3] exited with status -1`. Noisy (lines interleave/truncate on the console),
but correct: abnormal termination, nonzero status, prompt returns.

- [x] Shim v3 staged; `nm` shows `moto_rt_{unlink,rmdir,rename}`.
- [x] mlibc rebuilt with the 3 new tags; `m2` still runs (sysdeps regression check).
- [x] `m3` audit clean; full pass on Motor, exit 0; `m3 abort` returns to the prompt
      with a nonzero status (-1).
- [x] Kernel log during `m3` reviewed: only the expected sys-io `AlreadyExists`
      warning; the abort run's missing-sysdep ensures match the D.1 deferrals
      (signals). M4 worklist input: nothing new.

Known M3 pitfalls, pre-answered:

- **Malloc'd memory reads back as zeros from the first page-faulting offset onward**
  (hit at first M3 run) → kernel bug, fixed 2026-07-02: `preempt_current_thread_pf`
  (`arch/x64/syscall.rs`) did not `xsave()` the thread's SSE/AVX state (unlike
  `preempt_current_thread_irq`), while `resume_preempted_thread` unconditionally
  `xrstor()`s — so every **user page fault wiped the vector registers**. A
  vectorized `memset` keeps its fill pattern in XMM: the first store to an
  untouched lazy page faults, and the whole rest of the loop writes zeros. It went
  unnoticed for so long because Motor's Rust processes fault rarely and the
  timer-IRQ preempt path saves state correctly. Diagnostic signature: pages
  pre-faulted by scalar writes keep data; everything after the first faulting
  offset is `00`. Regression tests: systest `test_lazy_memory_map_write()` and
  m3's sweep phases A/B/C.
- **`%.3f`/`%g` mismatch or garbage** → mlibc's float formatting lives in frigg's
  printf machinery; if it misbehaves, it's an upstream mlibc/frigg issue, not a
  sysdep bug — check the same test on the demo port before touching our code.
- **`__ensure` panic inside `VirtualAllocator::unmap` during the churn test** →
  frigg handed `AnonFree` an address/length that doesn't exactly match a prior
  `AnonAllocate` (our `moto_rt_vm_unmap` takes only the address and unmaps the whole
  mapping — D's malloc tests exist largely to validate that assumption). Investigate
  which side changed before touching the shim.
- **`remove()` on a file fails** → the Rmdir-aliases-unlink fact (D.1) changed —
  e.g. the VDSO grew a real `rmdir` that rejects files with something other than
  NotADirectory(16). Make the VDSO return NotADirectory (maps to `ENOTDIR`, which
  `remove()` handles via its `Unlinkat` fallback), not a sysdep-side hack.
- **`fscanf` stops at the first `%15s`** → check the file was really written:
  the `setvbuf(_IONBF)` line must precede any output to the stream (C11 requires
  setvbuf before any other operation).
- **`tmpfile()` returns NULL** → expected on Motor (`/tmp` doesn't exist; D.1).
- **`m3 abort` hangs instead of exiting** → `LibcPanic` isn't reached; check the
  kernel log for where the abort sequence actually stopped.
