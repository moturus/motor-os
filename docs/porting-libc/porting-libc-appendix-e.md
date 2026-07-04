# Appendix E — M4, step by step

> **Status: complete** (2026-07-02) — `m4` prints "all tests passed" on Motor OS,
> exit 0; `m3` regression passes relinked against the M4 `libc.a`. Found and fixed
> a VDSO bug along the way (`opendir` returned errors as positive fds — see the
> E.7 pitfalls).

> Part of the Motor OS libc porting guide — main: [porting-libc-by-fable.md](porting-libc-by-fable.md); appendices: [A: M0 toolchain](porting-libc-appendix-a.md) · [B: M1 shim](porting-libc-appendix-b.md) · [C: M2 mlibc](porting-libc-appendix-c.md) · [D: M3 stdio+malloc](porting-libc-appendix-d.md) · [E: M4 filesystem](porting-libc-appendix-e.md) · [F: M5 threads+TLS](porting-libc-appendix-f.md) · [G: M6 sockets](porting-libc-appendix-g.md) · [H: M7 poll + real program](porting-libc-appendix-h.md) · [I: M8 C++ stack](porting-libc-appendix-i.md)

M4 is the POSIX filesystem surface: the `stat` family, directories
(`opendir`/`readdir`/`closedir`), `getcwd`/`chdir` + relative paths, proper
`mkdir()`/`mkdirat()`, `openat`, `ftruncate`/`fsync`, and `access`/`faccessat`.
The meat is two translations: Motor's `FileAttr` → `struct stat`, and Motor's
one-entry-at-a-time `readdir` → Linux-ABI `dirent` records. All facts below
verified against mlibc `368a00fa` and the in-tree VDSO/moto-rt.

### E.1 What mlibc needs (audited call sites)

| Tag | Called from | Notes |
|---|---|---|
| `Stat` | `stat`/`lstat`/`fstat`/`fstatat` (`sys-stat.cpp`) | one tag, dispatched on `mlibc::fsfd_target` {`path`, `fd`, `fd_path`} |
| `OpenDir` | `opendir` (`dirent.cpp:64`) | returns an fd (`DIR.__handle`) |
| `ReadEntries` | `readdir`/`readdir_r`/`posix_getdents` | fills a caller buffer with `struct dirent` records, advanced by `d_reclen`; returning **one record per call** is legal (mlibc refills when the buffer is consumed) |
| — | `closedir` | plain `close()` on the handle — verified the VDSO's `posix_close` pops **any** fd kind incl. `ReadDir`, so our existing `Close` sysdep covers it |
| `GetCwd` | `getcwd` (`unistd.cpp`) | sysdep fills `buffer` (size incl. NUL); sysdep returns `ERANGE` if too small |
| `Chdir` | `chdir` | |
| `Mkdir`, `Mkdirat` | `mkdir`/`mkdirat` (`sys-stat.cpp`) | `mode` ignored on Motor |
| `Openat` | `openat` (`fcntl.cpp:37`) | plain `open()` uses the `Open` tag we already have; `Openat` is a cheap `AT_FDCWD`-only router |
| `Ftruncate` | `ftruncate` (`unistd.cpp:284`) | moto-rt `truncate(fd, size)` |
| `Fsync` | `fsync` (`unistd.cpp:276`) | moto-rt `fsync(fd)` |
| `Access`, `Faccessat` | `access`/`faccessat` | no sysdep primitive on Motor; implement via `stat` + perm bits |

The `dirent` record layout (`options/posix/include/dirent.h`):
`ino_t d_ino; off_t d_off; reclen_t d_reclen; unsigned char d_type;
char d_name[256]` — the classic getdents64 shape; `d_name` offset is 19,
records should be 8-byte aligned.

### E.2 The ABI structs (moto_rt.h)

`moto_rt::fs::FileAttr` and `DirEntry` are `#[repr(C, align(16))]` — C-safe, but
the **16-byte alignment must be declared** in C (the VDSO writes them with
alignment-assuming code). Timestamps are `u128` **nanoseconds since the UNIX
epoch**, `0` = unknown (same convention the Rust std port uses); the high half is
always 0 for realistic dates — the sysdeps read only the low `u64` (enough until
year 2554). Add to `moto_rt.h`:

```c
/* file types / permissions (moto-rt/src/fs.rs) */
#define MOTO_FILETYPE_FILE      1
#define MOTO_FILETYPE_DIRECTORY 2
#define MOTO_PERM_READ  1u
#define MOTO_PERM_WRITE 2u
#define MOTO_MAX_FILENAME_LEN 256

/* Mirrors moto_rt::fs::FileAttr, #[repr(C, align(16))].
 * Timestamps: u128 nanoseconds since the UNIX epoch as (lo, hi); 0 = unknown. */
typedef struct {
	uint64_t version; /* == 1 */
	uint64_t size;
	uint64_t perm;
	uint8_t  file_type;
	uint8_t  _reserved[7];
	uint64_t created_lo,  created_hi;
	uint64_t modified_lo, modified_hi;
	uint64_t accessed_lo, accessed_hi;
} __attribute__((aligned(16))) moto_file_attr_t;

/* Mirrors moto_rt::fs::DirEntry, #[repr(C, align(16))]. */
typedef struct {
	uint64_t version; /* == 1 */
	uint64_t _reserved;
	moto_file_attr_t attr;
	uint16_t fname_size;              /* fname is NOT NUL-terminated */
	uint8_t  fname[MOTO_MAX_FILENAME_LEN];
} __attribute__((aligned(16))) moto_dir_entry_t;

/* fs, part 2 (M4) */
int32_t moto_rt_stat(const uint8_t *path, size_t path_len, moto_file_attr_t *attr);
int32_t moto_rt_fstat(int32_t fd, moto_file_attr_t *attr);
/* returns the full cwd length; copies min(len, capacity) bytes into buf */
int64_t moto_rt_getcwd(uint8_t *buf, size_t capacity);
int32_t moto_rt_chdir(const uint8_t *path, size_t path_len);
int64_t moto_rt_opendir(const uint8_t *path, size_t path_len); /* fd or -err */
/* 1 = entry written, 0 = end of directory, negative = -err */
int32_t moto_rt_readdir(int32_t fd, moto_dir_entry_t *dentry);
int32_t moto_rt_ftruncate(int32_t fd, uint64_t size);
int32_t moto_rt_fsync(int32_t fd);
```

Sanity: `sizeof(moto_file_attr_t) == 80`, `sizeof(moto_dir_entry_t) == 368` —
assert both in the shim (Rust side) and in `sysdeps.cpp` (`static_assert`) so a
struct drift breaks the build, not the runtime.

### E.3 Shim v4 (motor-os repo)

In `src/sys/lib/moto-rt-cabi/src/lib.rs`, next to the other fs wrappers. The
`FileAttr`/`DirEntry` types come from `moto_rt::fs` — the C structs above mirror
them, so the wrappers can cast pointers directly:

```rust
const _: () = assert!(core::mem::size_of::<moto_rt::fs::FileAttr>() == 80);
const _: () = assert!(core::mem::size_of::<moto_rt::fs::DirEntry>() == 368);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_stat(
    path: *const u8,
    path_len: usize,
    attr: *mut moto_rt::fs::FileAttr,
) -> i32 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    match moto_rt::fs::stat(path) {
        Ok(a) => {
            unsafe { *attr = a };
            0
        }
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_fstat(fd: i32, attr: *mut moto_rt::fs::FileAttr) -> i32 {
    match moto_rt::fs::get_file_attr(fd) {
        Ok(a) => {
            unsafe { *attr = a };
            0
        }
        Err(e) => err64(e) as i32,
    }
}

/// Returns the full cwd length; copies min(len, capacity) bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_getcwd(buf: *mut u8, capacity: usize) -> i64 {
    match moto_rt::fs::getcwd() {
        Ok(cwd) => {
            let bytes = cwd.as_bytes();
            let n = bytes.len().min(capacity);
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n) };
            bytes.len() as i64
        }
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_chdir(path: *const u8, path_len: usize) -> i32 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    match moto_rt::fs::chdir(path) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_opendir(path: *const u8, path_len: usize) -> i64 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match moto_rt::fs::opendir(path) {
        Ok(fd) => fd as i64,
        Err(e) => err64(e),
    }
}

/// 1 = entry written, 0 = end of directory, negative = -err.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_readdir(fd: i32, dentry: *mut moto_rt::fs::DirEntry) -> i32 {
    match moto_rt::fs::readdir(fd) {
        Ok(Some(e)) => {
            unsafe { *dentry = e };
            1
        }
        Ok(None) => 0,
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_ftruncate(fd: i32, size: u64) -> i32 {
    match moto_rt::fs::truncate(fd, size) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_fsync(fd: i32) -> i32 {
    match moto_rt::fs::fsync(fd) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}
```

(mlibc's `closedir` closes the handle with plain `close()`, which reaches the
VDSO's kind-agnostic `posix_close` — no `moto_rt_closedir` wrapper is needed.)

Rebuild + restage per B.5; verify:

```bash
nm $SYSROOT/usr/lib/libmoto_rt_cabi.a | grep -cE \
    " T moto_rt_(stat|fstat|getcwd|chdir|opendir|readdir|ftruncate|fsync)$"  # 8
```

### E.4 sysdeps: 12 new tags

`sysdeps/motor/include/mlibc/sysdeps.hpp` — extend the tag list:

```cpp
	Rmdir,
	Unlinkat,
	Rename,
	Stat,
	GetCwd,
	Chdir,
	Mkdir,
	Mkdirat,
	Openat,
	OpenDir,
	ReadEntries,
	Ftruncate,
	Fsync,
	Access,
	Faccessat
{};
```

`sysdeps/motor/generic/sysdeps.cpp` — new includes at the top:

```cpp
#include <dirent.h>        // struct dirent, DT_*
#include <stddef.h>        // offsetof
#include <sys/stat.h>      // S_IF*
#include <unistd.h>        // R_OK/W_OK/X_OK
```

(`mlibc::fsfd_target` needs no extra include — `sysdep-signatures.hpp`, already
pulled in via `<mlibc/all-sysdeps.hpp>`, includes `<mlibc/fsfd_target.hpp>`.)

The translation helper, in the anonymous namespace next to `moto_to_errno`:

```cpp
static_assert(sizeof(moto_file_attr_t) == 80);
static_assert(sizeof(moto_dir_entry_t) == 368);

// Motor FileAttr -> struct stat. Motor has no inode numbers, uids, or links;
// st_ino is a constant 1 (nonzero so tools don't treat entries as deleted) —
// same-file detection via st_dev/st_ino does NOT work on Motor.
void attr_to_stat(const moto_file_attr_t *a, struct stat *st) {
	memset(st, 0, sizeof(*st));
	st->st_dev = 1;
	st->st_ino = 1;
	st->st_nlink = 1;
	mode_t mode = 0;
	if (a->file_type == MOTO_FILETYPE_DIRECTORY)
		mode = S_IFDIR | 0111; // directories are traversable
	else
		mode = S_IFREG;
	if (a->perm & MOTO_PERM_READ)
		mode |= 0444;
	if (a->perm & MOTO_PERM_WRITE)
		mode |= 0222;
	st->st_mode = mode;
	st->st_size = static_cast<off_t>(a->size);
	st->st_blksize = 4096;
	st->st_blocks = static_cast<blkcnt_t>((a->size + 511) / 512);
	// u128 nanos since epoch; high half ignored (see E.2). 0 stays 0.
	auto to_ts = [](uint64_t nanos) {
		struct timespec ts;
		ts.tv_sec = static_cast<time_t>(nanos / 1000000000ul);
		ts.tv_nsec = static_cast<long>(nanos % 1000000000ul);
		return ts;
	};
	st->st_atim = to_ts(a->accessed_lo);
	st->st_mtim = to_ts(a->modified_lo);
	st->st_ctim = to_ts(a->modified_lo); // no status-change time on Motor
}
```

The sysdeps (after the M3 block):

```cpp
int Sysdeps<Stat>::operator()(fsfd_target fsfdt, int fd, const char *path, int flags,
                              struct stat *result) {
	// AT_SYMLINK_NOFOLLOW is accepted and ignored: Motor has no symlinks,
	// so follow/nofollow are the same operation.
	moto_file_attr_t attr;
	int32_t r;
	switch (fsfdt) {
	case fsfd_target::fd:
		r = moto_rt_fstat(fd, &attr);
		break;
	case fsfd_target::path:
		r = moto_rt_stat(reinterpret_cast<const uint8_t *>(path), strlen(path), &attr);
		break;
	case fsfd_target::fd_path:
		if ((flags & AT_EMPTY_PATH) && !*path) {
			r = moto_rt_fstat(fd, &attr);
			break;
		}
		if (fd != AT_FDCWD && path[0] != '/')
			return EBADF; // no dirfd-relative resolution on Motor
		r = moto_rt_stat(reinterpret_cast<const uint8_t *>(path), strlen(path), &attr);
		break;
	default:
		return EINVAL;
	}
	if (r < 0)
		return moto_to_errno(r);
	attr_to_stat(&attr, result);
	return 0;
}

int Sysdeps<GetCwd>::operator()(char *buffer, size_t size) {
	if (!size)
		return ERANGE;
	int64_t len = moto_rt_getcwd(reinterpret_cast<uint8_t *>(buffer), size - 1);
	if (len < 0)
		return moto_to_errno(len);
	if (static_cast<size_t>(len) + 1 > size)
		return ERANGE;
	buffer[len] = 0;
	return 0;
}

int Sysdeps<Chdir>::operator()(const char *path) {
	return moto_to_errno(
	    moto_rt_chdir(reinterpret_cast<const uint8_t *>(path), strlen(path)));
}

int Sysdeps<Mkdir>::operator()(const char *path, mode_t) {
	// mode ignored: Motor's perm model is per-entry r/w, no create-time mode.
	return moto_to_errno(
	    moto_rt_mkdir(reinterpret_cast<const uint8_t *>(path), strlen(path)));
}

int Sysdeps<Mkdirat>::operator()(int dirfd, const char *path, mode_t mode) {
	if (dirfd != AT_FDCWD && path[0] != '/')
		return EBADF;
	return sysdep<Mkdir>(path, mode);
}

int Sysdeps<Openat>::operator()(int dirfd, const char *path, int flags, mode_t mode,
                                int *fd) {
	if (dirfd != AT_FDCWD && path[0] != '/')
		return EBADF;
	return sysdep<Open>(path, flags, mode, fd);
}

int Sysdeps<OpenDir>::operator()(const char *path, int *handle) {
	int64_t r = moto_rt_opendir(reinterpret_cast<const uint8_t *>(path), strlen(path));
	if (r < 0)
		return moto_to_errno(r);
	*handle = static_cast<int>(r);
	return 0;
}

int Sysdeps<ReadEntries>::operator()(int handle, void *buffer, size_t max_size,
                                     size_t *bytes_read) {
	// One dirent per call: Motor's readdir yields one entry at a time, and
	// packing more would require lookahead buffering (an entry pulled from
	// the server-side cursor can't be pushed back if it doesn't fit).
	// mlibc's readdir() copes fine: it re-calls when the buffer is consumed.
	moto_dir_entry_t ent;
	int32_t r = moto_rt_readdir(handle, &ent);
	if (r < 0)
		return moto_to_errno(r);
	if (r == 0) { // end of directory
		*bytes_read = 0;
		return 0;
	}
	size_t nlen = ent.fname_size;
	if (nlen > 255)
		nlen = 255; // NAME_MAX
	size_t reclen = (offsetof(struct dirent, d_name) + nlen + 1 + 7) & ~size_t(7);
	if (reclen > max_size)
		return EINVAL;
	auto *d = static_cast<struct dirent *>(buffer);
	memset(d, 0, reclen);
	d->d_ino = 1; // Motor exposes no inode numbers; nonzero so entries aren't skipped
	d->d_off = 0;
	d->d_reclen = static_cast<reclen_t>(reclen);
	d->d_type = ent.attr.file_type == MOTO_FILETYPE_DIRECTORY ? DT_DIR : DT_REG;
	memcpy(d->d_name, ent.fname, nlen);
	d->d_name[nlen] = 0;
	*bytes_read = reclen;
	return 0;
}

int Sysdeps<Ftruncate>::operator()(int fd, size_t size) {
	return moto_to_errno(moto_rt_ftruncate(fd, size));
}

int Sysdeps<Fsync>::operator()(int fd) { return moto_to_errno(moto_rt_fsync(fd)); }

int Sysdeps<Access>::operator()(const char *path, int mode) {
	moto_file_attr_t attr;
	int32_t r = moto_rt_stat(reinterpret_cast<const uint8_t *>(path), strlen(path), &attr);
	if (r < 0)
		return moto_to_errno(r);
	if ((mode & R_OK) && !(attr.perm & MOTO_PERM_READ))
		return EACCES;
	if ((mode & W_OK) && !(attr.perm & MOTO_PERM_WRITE))
		return EACCES;
	// X_OK: directories are traversable; nothing else is executable via libc yet.
	if ((mode & X_OK) && attr.file_type != MOTO_FILETYPE_DIRECTORY)
		return EACCES;
	return 0;
}

int Sysdeps<Faccessat>::operator()(int dirfd, const char *path, int mode, int flags) {
	if (dirfd != AT_FDCWD && path[0] != '/')
		return EBADF;
	// AT_EACCESS is a no-op on a single-user OS; AT_SYMLINK_NOFOLLOW likewise.
	(void)flags;
	return sysdep<Access>(path, mode);
}
```

Rebuild + reinstall:

```bash
cd $MLIBC && ninja -C build && DESTDIR=$SYSROOT ninja -C build install
```

### E.5 Known gaps (deliberate, documented)

- **`rewinddir`/`seekdir`/`telldir`** — mlibc implements them via `lseek` on the
  dir fd; the VDSO's `seek` rejects non-`File` fds, and the `ReadDir` cursor
  (`prev_entry_id` in `rt_fs.rs`) can't be reset from outside. `rewinddir`
  *silently does nothing* (it ignores the lseek error but the server-side cursor
  stays). Fix belongs in the VDSO (accept `SEEK_SET 0` on `ReadDir` = reset
  cursor) — a good, small Motor-side task; until then don't reuse a `DIR*` for a
  second listing pass, reopen it.
- **`fdopendir`** — needs `fstat` on a dir fd, but the VDSO's `get_file_attr`
  downcasts to `File` and returns BadHandle for `ReadDir` fds → `EBADF`. Also a
  VDSO-side fix (route metadata for `ReadDir` kinds); rarely needed.
- **`st_ino`/`st_dev` are constants** — same-file detection (`find`,
  hardlink-dedup logic) doesn't work. Motor would need to expose entry ids in
  `FileAttr` (there's `_reserved` space) — Motor-side wishlist.
- **No `.`/`..` from `readdir`** — Motor enumerates children only. POSIX-legal
  ("it is unspecified whether entries for dot and dot-dot are returned"), but
  scripts that expect them will notice.
- **`rmdir` on a non-empty directory** — Motor has no `DirectoryNotEmpty` error
  code (error.rs tops out at 21), and `sys-io/src/util.rs:22` maps motor-fs's
  correct `io::ErrorKind::DirectoryNotEmpty` to `FileTooLarge` as a placeholder,
  so libc reports `EFBIG` instead of `ENOTEMPTY` (measured: errno 27 in m4).
  Motor-side wishlist: new moto-rt error code + `util.rs` + `moto_to_errno()`.
- **Timestamps may be 0** (= unknown) depending on what motor-fs records; the
  sysdep passes 0 through, m4 tolerates it.

### E.6 The M4 test program

`$MOTOR/src/tests/libc/m4.c`:

```c
/* M4 test: the POSIX filesystem surface (docs/porting-libc-appendix-e.md).
 *
 * Exercises: mkdir/mkdirat + EEXIST, stat/fstat (types, sizes, timestamps),
 * opendir/readdir/closedir + d_type, getcwd/chdir + relative open + ERANGE,
 * ftruncate/fsync, access, rmdir, and errno correctness throughout.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond)                                                            \
	do {                                                                   \
		if (!(cond)) {                                                 \
			fprintf(stderr, "M4 FAIL %s:%d: %s (errno=%d)\n",      \
			        __FILE__, __LINE__, #cond, errno);             \
			exit(1);                                               \
		}                                                              \
	} while (0)

#define ROOT "/sys/tmp"
#define D "/sys/tmp/m4-dir"

static void write_file(const char *path, size_t n) {
	FILE *f = fopen(path, "w");
	CHECK(f);
	for (size_t i = 0; i < n; i++)
		CHECK(fputc('a' + (int)(i % 26), f) != EOF);
	CHECK(fclose(f) == 0);
}

static void cleanup(void) { /* best-effort, for reruns after a failure */
	remove(D "/a");
	remove(D "/b");
	remove(D "/c");
	remove(D);
}

int main(void) {
	int r = mkdir(ROOT, 0777); /* the real Mkdir sysdep now (M3 used the shim) */
	CHECK(r == 0 || errno == EEXIST);
	cleanup();

	CHECK(mkdir(D, 0777) == 0);
	errno = 0;
	CHECK(mkdir(D, 0777) == -1 && errno == EEXIST);
	puts("M4: mkdir ok");

	write_file(D "/a", 10);
	write_file(D "/b", 4096);
	write_file(D "/c", 100000);

	struct stat st;
	CHECK(stat(D "/c", &st) == 0);
	CHECK(S_ISREG(st.st_mode) && st.st_size == 100000);
	CHECK(st.st_blksize > 0);
	/* motor-fs may not record timestamps (0 = unknown); if set, must be sane */
	CHECK(st.st_mtim.tv_sec == 0 || st.st_mtim.tv_sec > 1600000000);
	CHECK(stat(D, &st) == 0 && S_ISDIR(st.st_mode));
	errno = 0;
	CHECK(stat(D "/missing", &st) == -1 && errno == ENOENT);

	int fd = open(D "/a", O_RDONLY);
	CHECK(fd >= 0);
	struct stat fst;
	CHECK(fstat(fd, &fst) == 0 && S_ISREG(fst.st_mode) && fst.st_size == 10);
	CHECK(close(fd) == 0);
	puts("M4: stat/fstat ok");

	/* listing: exactly a, b, c — Motor emits no "." / ".." (POSIX-legal) */
	DIR *dir = opendir(D);
	CHECK(dir);
	int seen_a = 0, seen_b = 0, seen_c = 0, others = 0;
	struct dirent *ent;
	while ((ent = readdir(dir))) {
		if (!strcmp(ent->d_name, "a")) {
			seen_a++;
			CHECK(ent->d_type == DT_REG);
		} else if (!strcmp(ent->d_name, "b"))
			seen_b++;
		else if (!strcmp(ent->d_name, "c"))
			seen_c++;
		else
			others++;
	}
	CHECK(seen_a == 1 && seen_b == 1 && seen_c == 1 && others == 0);
	CHECK(closedir(dir) == 0);
	errno = 0;
	CHECK(opendir(D "/a") == NULL && errno == ENOTDIR);
	puts("M4: opendir/readdir ok");

	char cwd[256];
	CHECK(getcwd(cwd, sizeof cwd) && cwd[0] == '/');
	CHECK(chdir(D) == 0);
	CHECK(getcwd(cwd, sizeof cwd) && strcmp(cwd, D) == 0);
	FILE *f = fopen("a", "r"); /* relative path resolves against the new cwd */
	CHECK(f && fgetc(f) == 'a');
	CHECK(fclose(f) == 0);
	errno = 0;
	CHECK(getcwd(cwd, 4) == NULL && errno == ERANGE);
	CHECK(chdir("/") == 0);
	puts("M4: getcwd/chdir ok");

	fd = open(D "/c", O_RDWR);
	CHECK(fd >= 0);
	CHECK(ftruncate(fd, 5) == 0);
	CHECK(fstat(fd, &fst) == 0 && fst.st_size == 5);
	CHECK(fsync(fd) == 0);
	CHECK(close(fd) == 0);
	CHECK(stat(D "/c", &st) == 0 && st.st_size == 5);
	puts("M4: ftruncate/fsync ok");

	CHECK(access(D "/a", F_OK) == 0);
	CHECK(access(D "/a", R_OK | W_OK) == 0);
	errno = 0;
	CHECK(access(D "/missing", F_OK) == -1 && errno == ENOENT);
	puts("M4: access ok");

	/* rmdir(non-empty) must fail; Motor has no DirectoryNotEmpty code yet,
	 * so record what errno actually comes back (POSIX wants ENOTEMPTY). */
	errno = 0;
	CHECK(rmdir(D) == -1);
	fprintf(stderr, "M4: note: rmdir(non-empty) errno = %d\n", errno);

	CHECK(remove(D "/a") == 0 && remove(D "/b") == 0 && remove(D "/c") == 0);
	CHECK(rmdir(D) == 0);
	errno = 0;
	CHECK(stat(D, &st) == -1 && errno == ENOENT);
	puts("M4: cleanup ok");

	printf("M4: all tests passed\n");
	return 0;
}
```

Build, audit, stage (same link line as C.8/D.5 with `m4`):

```bash
cd $MOTOR/src/tests/libc
$B/clang --target=x86_64-unknown-motor -O2 -isystem $SYSROOT/usr/include m4.c \
    $SYSROOT/usr/lib/crt1.o \
    $SYSROOT/usr/lib/libc.a \
    $SYSROOT/usr/lib/libmoto_rt_cabi.a \
    $SYSROOT/usr/lib/libclang_rt.builtins-x86_64.a -o m4

$B/llvm-readelf -l m4 | grep -w TLS && echo "PT_TLS — BAD" || echo "no PT_TLS"
$B/llvm-readelf -r m4 | grep R_X86_64 | grep -cv R_X86_64_RELATIVE   # must be 0

cp m4 $MOTOR/img_files/motor-os/bin/
```

### E.7 Run on Motor OS + exit criteria

`make img`, boot, then `m4` → the six `M4: ... ok` lines, the
`rmdir(non-empty) errno` note, `M4: all tests passed`, exit 0.

- [x] Shim v4 staged; the 8 new exports present; struct-size asserts compile.
- [x] mlibc rebuilt with the 12 new tags; `m3` still passes (regression, relinked
      against the new `libc.a`).
- [x] `m4` audit clean; full pass on Motor. Recorded `rmdir(non-empty)` errno:
      **27 = `EFBIG`**. Full chain: motor-fs correctly returns
      `io::ErrorKind::DirectoryNotEmpty` (`motor-fs/src/layout.rs:876`), but
      `sys-io/src/util.rs:22` maps it to `moto_rt::Error::FileTooLarge` as an
      explicit placeholder (moto-rt has no `DirectoryNotEmpty` code), and the
      sysdep table faithfully maps 18 → `EFBIG`. Fix belongs Motor-side: add
      `DirectoryNotEmpty` to moto-rt's error codes, use it in `util.rs`, then map
      it to `ENOTEMPTY` in `moto_to_errno()`.
- [x] Kernel log reviewed: only the expected `AlreadyExists` WARNs (the
      `mkdir(ROOT)` on an existing dir + the deliberate EEXIST check).

Known M4 pitfalls, pre-answered:

- **`opendir()` on a regular file "succeeds"** (m4's ENOTDIR check fails with
  `errno=0`; hit at first M4 run) → VDSO bug, fixed 2026-07-02: `rt_fs.rs::opendir`
  returned its error codes as **positive** i32 — but it returns an fd on success,
  and moto-rt's `to_result!` treats any non-negative value as a valid fd, so
  `NotADirectory` (16) came back as "fd 16". Errors from fd-returning VDSO
  functions must be negative (like `open`'s). This also affected Rust std's
  `read_dir` on a non-directory path. When adding a new fd-returning vtable
  entry, check its error sign convention first.
- **VDSO writes `FileAttr`/`DirEntry` with 16-byte alignment assumptions** →
  if the C structs lose `__attribute__((aligned(16)))`, stack-allocated ones may
  be 8-aligned and Rust-side `*attr = a` can fault or tear. The `static_assert`s
  catch size drift but not alignment — keep the attribute.
- **`stat()` on `/sys/tmp/...` works but relative `fopen` after `chdir` fails**
  → the VDSO resolves relative paths against its own cwd (`CanonicalPath::parse`);
  if this fails, check that `chdir` actually reached sys-io (kernel log) rather
  than patching paths in the sysdep.
- **`readdir` loops forever on one entry** → `d_reclen` must be nonzero and
  8-aligned — mlibc advances `__ent_next` by it; a zero reclen re-reads the same
  record forever.
- **Second listing pass returns nothing** → that's the `rewinddir` gap (E.5),
  not a bug in your test; reopen the directory instead.
- **`locale.cpp` probes `/usr/lib/locale/locale-archive` at startup now that
  `Stat` exists** → returns `ENOENT`, tolerated; just noise in strace-thinking,
  no action needed.
