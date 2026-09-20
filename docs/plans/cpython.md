# Porting CPython to Motor OS

2026-09-10. Assessment and plan only. No code changes accompany this
document. It follows the root `AGENTS.md`: mlibc and toolchain changes are
cross-repository and are called out as such below.

Scope: CPython 3.14 as a fully static, Linux-cross-built interpreter for
`x86_64-unknown-motor`, shipped on the developer image with the pure-Python
standard library and the built-in extension modules Motor can support. Out
of scope: `ctypes`, loadable extension modules, fork-based
`multiprocessing`, and OpenSSL, which is a separate port (§8).

Provenance. Findings were gathered against:

* Motor OS at `03de326a` (branch `frusa`); the mlibc fork at
  `MOTOR_MLIBC_REV` `0cece7e5` (`../toolchain-src/mlibc`); the standalone
  host LLVM 23.1.0-rc1 (moturus/llvm-project `7c2a7b21`) under
  `../build/toolchain/standalone-llvm/`; the assembly sysroot under
  `../assemblies/<key>/sysroot/devtools/llvm`; the Motor Rust std port under
  `../toolchain-src/rust/library/std/src/sys/*/motor*`.
* CPython `3.14` branch files fetched from GitHub on 2026-09-10:
  `configure.ac`, `Lib/site.py`, `Lib/subprocess.py`,
  `Modules/socketmodule.c`, `Modules/{termios,fcntlmodule,posixmodule,selectmodule}.c`,
  `Python/ceval.c`, `Python/thread_pthread.h`, `Misc/platform_triplet.c`,
  `Tools/wasm/wasi/config.site-wasm32-wasi`. The host Python is 3.14.4.
* A C probe cross-built on the host with the recipe in Appendix A and run on
  the release `motor-os.qcow2` under QEMU with 4 vCPUs. The probe is not in
  the tree; Appendix A describes it so it can be rebuilt.

## 1. Summary and headline recommendation

A first interpreter (`python3 -c`, scripts, `import` of the pure-Python
standard library, `.pyc` caching, sockets, threads) is a few days of work
and is closer to CPython's WASI port than to a Linux build. In several ways
it is easier than WASI: Motor has real threads, TCP/UDP sockets, a
filesystem with mtimes and inodes, and `posix_spawn`.

The work splits three ways:

1. **One hard startup blocker.** mlibc aborts the process, rather than
   returning ENOSYS, when `getuid`, `geteuid`, `getgid`, `getegid`,
   `getppid`, or `gettid` is called without a Motor sysdep, and CPython's
   `site.py` calls `os.geteuid()` and `os.getuid()` during startup. Six
   one-line sysdeps in `sysdeps/motor` fix it for every C program; a
   CPython-only `config.site` workaround also exists (§6.2).
2. **A short list of small gaps** that are configuration or a few hundred
   lines: the `configure.ac` cross-build case, the C stack size assumption,
   UTF-8 mode, the static module list, and a minimal `sys/ioctl.h`.
3. **Platform properties** that must be configured out and have precedent
   on WASI: no `fork`, no `dlopen`, no asynchronous signals, no pty, no
   file-backed `mmap`.

After the first run, the useful "process" parts of the standard library
(`subprocess` with pipes, `Popen.poll`, `shutil.copy2`, `KeyboardInterrupt`)
need runtime and shim additions of one to two weeks. Everything they need
already exists in the VDSO and is used by Rust std; only the C-facing shim
and mlibc lack it.

Recommendation: proceed in the three phases of §6, §7, and §8. Phase 1 is
worth doing on its own and can start without a new toolchain assembly.

## 2. Background A: what CPython needs from a platform

CPython's platform surface, in the order it bites during a port:

* **Build.** Autoconf `configure`, cross-compiled with `--host` and
  `--with-build-python`. The cross case in `configure.ac` (line 320 in
  3.14) derives `ac_sys_system` from `$host` and ends in
  `AC_MSG_ERROR([cross build not supported for $host])` for any triple it
  does not list. `Misc/platform_triplet.c` ends in
  `# error unknown platform triplet` for unknown compilers; that failure is
  tolerated by configure but leaves `MULTIARCH` empty. Checks a cross build
  cannot run are answered from a `config.site`; WASI's is 59 lines with 24
  `ac_cv_*` overrides.
* **Static linking.** `--disable-shared` and every extension module listed
  as static in `Modules/Setup.local`. Without `dlopen`, configure selects
  `dynload_stub.o` and `HAVE_DYNAMIC_LOADING` is off, so `importlib` never
  looks for `.so` files. WASI builds exactly this way.
* **libc.** Beyond ANSI C: pthreads with keys and clock-selectable condition
  variables, semaphores, `getentropy` or `getrandom` for hash seeding
  (without one, startup is a fatal error unless `PYTHONHASHSEED` is set),
  anonymous `mmap` for obmalloc arenas (optional; it falls back to
  `malloc`), `clock_gettime`, `setlocale`/`nl_langinfo`, `sigaction` and
  `pthread_sigmask` (bookkeeping is enough), `select` or `poll`, sockets
  and `getaddrinfo`, `fcntl` for nonblocking mode, `stat` with mtime and
  size for `.pyc` invalidation, `rename` for atomic `.pyc` writes.
* **Processes.** `subprocess` on POSIX uses `_posixsubprocess.fork_exec`
  unless `_can_fork_exec` is false for the platform (`Lib/subprocess.py`
  line 78 lists `emscripten`, `wasi`, `ios`, `tvos`, `watchos`), with a
  `posix_spawn` path that needs `pipe`, `dup2`-style file actions, and
  `waitpid(WNOHANG)` for `Popen.poll`. `asyncio` needs `socketpair` or,
  when `HAVE_SOCKETPAIR` is off, a loopback TCP pair.
* **Signals.** `signal.signal` records handlers; `KeyboardInterrupt`
  depends on a real SIGINT delivery calling `PyErr_SetInterrupt`.
* **Stack.** Since 3.12 CPython bounds C recursion by stack address. In 3.14
  `Python/ceval.c` asks `pthread_getattr_np` for the real bounds and
  otherwise assumes `Py_C_STACK_SIZE`, which is 4,000,000 bytes on an
  unlisted platform. If the real stack is smaller, deep recursion hits the
  guard page instead of raising `RecursionError`.
* **Terminals.** The 3.13+ REPL uses `termios` and falls back to the basic
  REPL when it cannot.

## 3. Background B: what Motor provides

The C runtime is documented in `docs/libc.md`. From the application down:
libc++ and libunwind; mlibc `sysdeps/motor`; compiler-rt builtins with
`emutls.c` removed; `moto-rt-cabi` (`src/sys/lib/moto-rt-cabi`) as the
single C-ABI bridge over `rt.vdso`; and the same `moto-rt`/VDSO runtime that
Rust std uses. Binaries are static PIEs, TLS is emulated (`-femulated-tls`
is a target default), and clang predefines `__motor__` but not `__unix__`.

Platform properties, not gaps: no `fork`, no `dlopen`, no kernel signals
(handlers dispatch synchronously on `raise` only), no pty or termios
(terminals are a userspace pipe protocol, `docs/tui.md`), no symlinks, no
users, no resource limits, no file-backed `mmap`.

mlibc coverage: `sysdeps/motor` specializes 69 of the 272 `Sysdeps<...>`
hooks the Linux sysdeps implement. A missing hook behaves in one of two
ways in mlibc's generic code:

* `sysdep_or_enosys` prints a warning to stderr and returns ENOSYS. This is
  the common case: `pipe`, `dup`, `dup2`, `socketpair`, `uname`, `umask`,
  `chmod` by path, `utimensat`, `tcgetattr`, `clock_getres`, `readv`,
  `times`, `ioctl`.
* `__ensure(!"Cannot continue without sys_...")` aborts the process. This
  applies to `getuid`, `geteuid`, `getgid`, `getegid`, `getppid`, and
  `gettid` (`options/posix/generic/unistd.cpp`).

Only the `posix` mlibc option is enabled (`sysdeps/motor/meson.build`), so
the sysroot has no `sys/ioctl.h`, `sys/random.h`, `pty.h`, `utmp.h`,
`sys/epoll.h`, `iconv.h`, or `libintl.h`. `dlopen` links and always fails
with "Cannot locate requested DSO".

The VDSO already has what the process-related gaps need, because Rust std
uses it: `moto_rt::process::spawn` takes `stdin`/`stdout`/`stderr` slots
with `STDIO_MAKE_PIPE`, and `try_wait`, `kill`, `fs::duplicate`, and
`ctrl_c_register_handler`/`ctrl_c_wait` exist. The C shim exposes none of
them: `moto_rt_spawn` takes no stdio, `moto_rt_waitpid` only blocks, and
there is no pipe or duplicate export. Rust std's `sys/pipe/motor.rs` is also
unsupported, and `set_times` is unsupported on purpose
(`sys/fs/motor.rs`, "Let's not do that").

Stacks: the kernel gives the first thread
`Thread::DEFAULT_USER_STACK_SIZE_PAGES` = 254 pages
(`src/sys/kernel/src/uspace/process.rs`), about 1 MiB, with guards; spawned
threads get the size they request, page for page. mlibc's pthread default
is 2 MiB; `pthread_attr_setstack` is not honored; `pthread_getattr_np` is
absent from `libc.a`.

## 4. Evidence: the VM probe

A C program exercising the calls in §2 was cross-built with the host
standalone clang against the assembly sysroot (Appendix A), uploaded over
sftp, and run over ssh on the release image.

Worked:

| Area | Observation |
| --- | --- |
| pthreads, `_Thread_local`, `sem_*`, `pthread_condattr_setclock(MONOTONIC)` | all return 0; TLS is per thread |
| `getentropy` | 0 |
| `mmap(1 MiB, MAP_ANONYMOUS)`, `munmap` | ok |
| `clock_gettime` REALTIME and MONOTONIC | 0 |
| `sigaction`, `pthread_sigmask`, `siginterrupt`, `setjmp`/`longjmp` | 0 |
| `fcntl` F_GETFL, F_GETFD, F_SETFD | work |
| `open(O_CREAT\|O_EXCL)`, `write`, `fchmod`, `fsync`, `rename`, `stat`, `unlink` | work; `st_mtime` and `st_ino` are real |
| `sysconf` `_SC_PAGESIZE` 4096, `_SC_NPROCESSORS_ONLN` 4, `_SC_OPEN_MAX` 256 | work |
| `posix_spawnp("ls")`, blocking `waitpid` | child ran, exit status decoded |
| `printf("%.17g", 0.1)` | `0.10000000000000001` |
| `mbstowcs` on UTF-8 input | decodes |
| `strftime`, `mktime`, `localtime_r` | work, zone UTC |

Failed:

| Call | Result |
| --- | --- |
| `getuid()` | process aborted, "mlibc panic", exit -1 |
| `gettid()` | process aborted |
| `pipe`, `dup`, `socketpair` | ENOSYS with a warning on stderr |
| `uname`, `umask`, `chmod` by path, `utimensat`, `tcgetattr` | ENOSYS |
| `clock_getres` | ENOSYS |
| `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)` | EINVAL |
| `waitpid(pid, WNOHANG)` | EINVAL |
| `setlocale(LC_ALL, "")` | "C"; `C.UTF-8` returns NULL; `nl_langinfo(CODESET)` is `ANSI_X3.4-1968` |
| `dlopen("x.so")` | NULL, "Cannot locate requested DSO" |
| 1 KiB-frame recursion on the main thread | killed silently at about 1000 KiB, exit -1 |
| the same on a pthread with the 2 MiB default | ran past 3.9 MiB before the guard |

The `isatty` calls returned ENOTTY because the probe ran over ssh without a
terminal; that is correct behavior.

## 5. Gap analysis

| CPython need | Motor today | Fix | Where | Size |
| --- | --- | --- | --- | --- |
| `os.getuid`/`geteuid`/`getgid`/`getegid` at startup (`site.py` lines 275, 279) | abort | sysdeps returning 0 | mlibc `sysdeps/motor` | 6 lines |
| `os.getppid`, `gettid` | abort | sysdeps returning pid and VDSO tid | mlibc | 2 lines |
| configure accepts the host | error | `*-*-motor*)` arm setting `ac_sys_system=Motor` | `configure.ac`, regenerated `configure` | 5 lines |
| `PLATFORM_TRIPLET` | `#error` | `#elif defined(__motor__)` arm | `Misc/platform_triplet.c` | 3 lines |
| cross checks that cannot run | n/a | `config.site` modeled on WASI's | new file in the CPython tree | ~40 lines |
| C stack bounds | assumes 4 MB, has 1 MiB | `Py_C_STACK_SIZE` for `__motor__` near 800 KB, or run the interpreter on a 4 MiB pthread | `Python/ceval.c` or `Programs/python.c` | 5 to 30 lines |
| UTF-8 locale | C only | `_Py_FORCE_UTF8_LOCALE` for `__motor__`, as Android does | `Include/pyport.h` | 1 line |
| static modules | no `dlopen` | `--disable-shared`, `Modules/Setup.local` listing the built-ins | build config | 1 file |
| `fcntl` module (`sys/ioctl.h` required by configure line 8097) | header absent | minimal `sys/ioctl.h` with `ioctl` returning ENOSYS, or accept no `fcntl` module | mlibc `sysdeps/motor/include` | 20 lines |
| `time.get_clock_info` | `clock_getres` ENOSYS | `ClockGetres` sysdep returning 1 ns | mlibc | 5 lines |
| `os.pipe`, `os.dup`, `Popen.poll`, `subprocess` pipes | ENOSYS/EINVAL | see §7.1 | VDSO or shim, mlibc, `subprocess.py` | 300 to 500 lines |
| `asyncio` self-pipe | `socketpair` ENOSYS | `ac_cv_func_socketpair=no`; CPython falls back to a loopback TCP pair; moto-netstack has `127.0.0.1/8` (`docs/networking.md`) | `config.site` | 1 line |
| `KeyboardInterrupt` | Ctrl+C kills a Default process with 130 | helper thread on `ctrl_c_wait` calling `PyErr_SetInterrupt` | shim export plus `Modules/signalmodule.c` | ~80 lines |
| `shutil.copy2`, `copytree`, `os.utime` | `utimensat` ENOSYS, no VDSO set-times | VDSO set-times, or Motor-tolerant `copystat` | VDSO plus mlibc, or `Lib/shutil.py` | see §7.3 |
| `os.chmod(path)`, `os.umask`, `os.uname` | ENOSYS | `Chmod` over `fs::set_perm`; `Umask` bookkeeping; `Uname` constant | mlibc | 30 lines |
| `termios`, `tty`, `_pyrepl` | no termios by design | none; basic REPL | n/a | 0 |
| `ssl`, `hashlib` via OpenSSL | no C TLS library ported | separate port | outside this plan | weeks |

## 6. Phase 1: first run

Goal: `python3 -c 'import json, re, socket, threading; print(1)'` on the
developer image, the pure-Python standard library importable, `.pyc` files
written, and the interpreter's own smoke tests passing.

### 6.1 Build layout

Mirror Lua, a userspace add-on in `src/build-motor-os.sh` (`build_addons`):
sources under `$MOTORH` (`../cpython`), a versioned build directory under the
assembly build root, and the result staged into its own overlay in the
assembly image root under `/devtools/python/{bin,lib/python3.14}`. Like every
add-on it is no part of the toolchain's identity and is rebuilt alone when
its version changes. The imager copies the tree through
`assembly_dirs` (`src/imager/motor-os-dev.yaml`); the data partition is
4096 MB and the standard library without `test` is under 20 MB.

The build runs on the Linux host only. The developer image has clang, lld,
and rush but no `make`, `sh`, or autoconf, so a native CPython build is not
an option (§10).

Configure line, subject to the `config.site` below:

```
CONFIG_SITE=config.site-x86_64-motor \
CC="$B/clang --target=x86_64-unknown-motor -isystem $SYSROOT/devtools/llvm/include" \
./configure --host=x86_64-unknown-motor --build=x86_64-linux-gnu \
  --with-build-python=python3.14 --disable-shared --disable-test-modules \
  --with-ensurepip=no --prefix=/devtools/python
```

The link needs the same explicit group Lua uses, because the host `.cfg`
forces `-nostdlib`: `crt1.o`, then `--start-group libmoto_rt_cabi.a
libc++abi.a libunwind.a libc.a libclang_rt.builtins-x86_64.a --end-group`.
The cleanest way is `LDFLAGS`/`LIBS` in the configure environment; the
alternative is a wrapper `cc` script that appends the group.

### 6.2 CPython patches

1. `configure.ac`: add `*-*-motor*) ac_sys_system=Motor ;;` to the cross
   case at line 320; regenerate `configure` with the pinned autoconf (the
   host lacks autoconf; CPython's `Tools/build/regen-configure.sh`
   container, or patch the generated `configure` in step with the source).
2. `Misc/platform_triplet.c`: `#elif defined(__motor__)` defining
   `PLATFORM_TRIPLET "x86_64-motor"`.
3. `Python/ceval.c`: `#elif defined(__motor__)` with `Py_C_STACK_SIZE
   800000` in the ladder at line 369. The alternative in §10 keeps the
   4 MB assumption by running the interpreter on a large pthread.
4. `Include/pyport.h`: add `__motor__` to the `__ANDROID__ || __VXWORKS__`
   condition that defines `_Py_FORCE_UTF8_LOCALE` (line 531), which also
   forces the UTF-8 filesystem encoding and skips the `nl_langinfo` probe
   in `Python/pylifecycle.c`. Configure with `--without-c-locale-coercion`,
   since mlibc has no `C.UTF-8` to coerce to.
5. `Lib/subprocess.py` line 78: add `"motor"` to the `_can_fork_exec`
   exclusion set for Phase 1, so `Popen` raises a clear `OSError` instead
   of failing inside `fork_exec` with ENOSYS. Phase 2 replaces this.
6. `config.site-x86_64-motor`, starting from WASI's list:
   `ac_cv_buggy_getaddrinfo=no`, `ac_cv_file__dev_ptmx=no`,
   `ac_cv_file__dev_ptc=no`, `ac_cv_func_fork=no`, `ac_cv_func_dlopen=no`,
   `ac_cv_func_socketpair=no`, `ac_cv_func_pipe=no` (until §7.1),
   `ac_cv_func_readv=no`, `ac_cv_func_writev=no`, `ac_cv_func_preadv=no`,
   `ac_cv_func_pwritev=no`, `ac_cv_func_utimensat=no`,
   `ac_cv_func_futimens=no`, `ac_cv_func_chmod=no`, `ac_cv_func_symlink=no`,
   `ac_cv_func_readlink=no`, `ac_cv_func_link=no`, `ac_cv_func_mkfifo=no`,
   `ac_cv_func_setitimer=no`, `ac_cv_func_getloadavg=no`. Every one of
   these symbols exists in `libc.a` and returns ENOSYS, so configure would
   otherwise report them present. Setting `ac_cv_func_getuid=no`,
   `ac_cv_func_geteuid=no`, `ac_cv_func_getgid=no`, `ac_cv_func_getegid=no`,
   and `ac_cv_func_getppid=no` removes the `os` attributes
   (`Modules/posixmodule.c` guards them with `HAVE_GETUID` and
   `HAVE_GETPPID`) and lets `site.py` skip its check, which makes Phase 1
   possible before the mlibc sysdeps of §6.3 land. The sysdeps are still
   the right fix; the workaround does not protect any other C program.
7. `Modules/Setup.local`: `*static*` followed by the built-in list:
   `_posixsubprocess` omitted, `_socket`, `select`, `_ssl` and `_hashlib`
   omitted, `mmap` omitted (file-backed only would fail), `_ctypes`
   omitted, `termios` omitted, `fcntl` per §6.3, `_multiprocessing`
   omitted, `_sqlite3`, `zlib`, `_bz2`, `_lzma`, `readline` omitted until
   their libraries exist, everything else that has no external dependency
   included (`math`, `_struct`, `_json`, `_pickle`, `_datetime`, `_random`,
   `_sha*`, `_md5`, `_blake2`, `binascii`, `_decimal` with the bundled
   libmpdec, `pyexpat` with the bundled expat, `unicodedata`, `array`,
   `_csv`, `_bisect`, `_heapq`, `_statistics`, `_asyncio`, `_queue`,
   `_contextvars`, `_zoneinfo`, `_elementtree`, `_lsprof`, `_opcode`,
   `_typing`, `resource`, `grp` and `pwd` if they build against
   `/system/cfg/libc/passwd`).

### 6.3 mlibc changes (cross-repository, `../toolchain-src/mlibc`)

These select a new assembly key (`docs/toolchain.md`) and must be announced
as mlibc changes:

* `GetUid`, `GetEuid`, `GetGid`, `GetEgid` returning 0; `GetPpid` returning
  0 or 1; `GetTid` returning `moto_rt_tid()`. This turns the abort into
  defined behavior for every C program, not only CPython.
* `ClockGetres` returning 1 ns for MONOTONIC and REALTIME.
* A minimal `sys/ioctl.h` in `sysdeps/motor/include` declaring `ioctl`,
  which the generic mlibc implementation already answers with ENOSYS. This
  lets configure enable the `fcntl` module (`configure.ac` line 8097
  requires the header) and lets `Modules/fcntlmodule.c` and
  `Modules/posixmodule.c` include it. Declaring the glibc mlibc option
  instead is rejected in §10.

### 6.4 Image and gates

* Stage `/devtools/python` from the assembly image root through
  `assembly_dirs`, and `/devtools/bin/python3` as the launcher, as Lua is
  staged today.
* A `src/tests/test-cpython.sh` guest test in the developer-image suite,
  release only per `AGENTS.md` for non-Lorry work: interpreter startup,
  `import` of a fixed module list, a `.pyc` round trip, a threaded loop, a
  TCP echo through `socket`, `json` and `re` round trips, and
  `python3 -m test` on a small deterministic subset with the network tests
  excluded. Wire it into `src/tests/full-test-dev.sh`.

## 7. Phase 2: processes, asyncio, Ctrl+C, copying

### 7.1 `subprocess` with pipes

Two designs are possible; the second is recommended.

*A. Pipes as first-class VDSO objects.* Add an anonymous pipe to the VDSO
and expose it to Rust std (`sys/pipe/motor.rs` is unsupported today) and
to the shim as `moto_rt_pipe`. mlibc gains `Pipe`, `Dup`, `Dup2`, and
`PosixSpawn` file actions that map `dup2(fd, 0..2)` onto the spawn stdio
slots. CPython then needs only `_can_fork_exec` tuning and the existing
`posix_spawn` path. This is the larger change and touches `src/sys`, but it
also fixes Rust's `std::io::pipe`.

*B. Spawn-with-stdio in the shim.* Extend `moto_rt_spawn` with three stdio
arguments and return the pipe fds, matching `SpawnArgs`; add
`moto_rt_try_wait` over `process::try_wait`, `moto_rt_kill`, and
`moto_rt_dup` over `fs::duplicate`. mlibc's `PosixSpawn` accepts file
actions consisting of `addopen`/`adddup2` onto fds 0 to 2 and translates
them into the stdio slots; `Waitpid` honors `WNOHANG` via `try_wait`;
`Dup` and `Dup2` map onto `duplicate`. `pipe()` stays unsupported, so
`os.pipe` stays absent. On the CPython side, `subprocess.py` gains a Motor
branch that always uses `os.posix_spawn` with `file_actions` and never
`fork_exec`, and `Popen.communicate` works because the pipe ends are
ordinary fds that `select` and `poll` already handle
(`sysdeps/motor/generic/poll.cpp`). This keeps `src/sys` untouched except
for the shim and matches what Rust's `Command` does today.

Either way `_posixsubprocess` stays out of the build.

### 7.2 `asyncio` and Ctrl+C

`asyncio` works with `socketpair` marked absent once loopback is enabled in
the image's network configuration; verify with an `asyncio` echo server in
the gate. For `KeyboardInterrupt`, export `ctrl_c_register_handler` and
`ctrl_c_wait` from the shim and start a daemon thread in
`Modules/signalmodule.c` under `__motor__` that calls `PyErr_SetInterrupt`
on each sequence advance. Registration is process-lifetime and single, so
register lazily on the first `signal.signal(SIGINT, ...)` that installs a
Python handler, and never in a process without terminal input, where
registration succeeds dormantly (`docs/tui.md`, "Ctrl+C").

### 7.3 `shutil` and file metadata

`shutil.copystat` calls `os.utime` unguarded, so `copy2`, `copytree`, and
package installers break on ENOSYS. Options: a VDSO set-times operation
(also unblocks Rust `File::set_times`, which is unsupported by choice),
or a `Lib/shutil.py` change that treats `NotImplementedError`/ENOSYS from
`utime` as "unsupported" the way it already does for `chflags`. The second
is a 10-line change and needs no runtime work; the first is the correct
long-term answer if Motor FS wants settable times at all. Add `Chmod` over
`fs::set_perm`, `Umask` as pure bookkeeping, and `Uname` returning
`Motor`/`x86_64` to mlibc in the same patch.

## 8. Phase 3: optional libraries

`zlib` (needed for compressed `zipimport`, `gzip`, `zipfile`), `bzip2`,
`xz`, `sqlite3`, and `readline`/`libedit` are plain C and should cross-build
with the Appendix A recipe; each is a static archive staged next to libc.
OpenSSL is the one that matters for `ssl`, `hashlib` acceleration, and `pip`
against PyPI, and it is a port of its own: a Perl-driven configure, a new
OS target, `no-dso no-shared`, and its own libc expectations. No C TLS
library exists on Motor today; `curl`, `httpd`, and `russhd` are Rust on
rustls. Until OpenSSL lands, `hashlib` uses CPython's built-in
implementations and `pip` can install only local wheels.

## 9. Will not work, by platform design

`os.fork` and everything built on it (`multiprocessing` fork and forkserver
start methods; the `spawn` method becomes possible after §7.1), `ctypes`
(needs libffi and `dlsym` on the process, which a static PIE without a
dynamic symbol table cannot provide), loadable extension modules,
file-backed `mmap`, `pty` and `tty`, `signal.alarm`, `setitimer`, and every
asynchronous signal, `resource` limits, `os.getloadavg`, symlinks. All of
these are skipped on WASI already, and the test suite marks them with
platform checks that a `motor` platform name can reuse.

## 10. Options analyzed and rejected

* **Native build on the developer image.** No `make`, `sh`, or autoconf on
  the image, and the whole CPython build assumes them. Cross-build only.
* **Enabling mlibc's glibc option to get `sys/ioctl.h`.** It drags in a
  large surface (`sys/epoll.h`, `sys/timerfd.h`, `resolv`, `execinfo` with
  aborting stubs) that no Motor sysdep backs. A one-file `sys/ioctl.h` is
  the smaller change.
* **Running the interpreter on a large pthread instead of setting
  `Py_C_STACK_SIZE`.** Works, since spawned threads get what they ask for,
  but changes `Programs/python.c` and every embedding entry point, and
  threads created by `threading` still need a correct bound. The
  `Py_C_STACK_SIZE` arm is the smaller and more general fix; the two can be
  combined if 800 KB proves too tight for the regression tests.
* **Raising the kernel's main-stack default.** Stacks are lazy and guarded,
  so it would be cheap, but it is a `src/sys/kernel` change for one
  consumer and every other process would carry the larger reservation.
  Not proposed without a separate discussion.
* **Fixing `site.py` in CPython instead of mlibc.** The `config.site`
  workaround in §6.2 is acceptable for a first build, but the abort is a
  libc defect that any C program can trigger; the sysdeps are the fix.
* **Emulating `fork` in the shim.** Impossible on this kernel by design.

## 11. Risks and open questions

* **Emulated TLS on the hot path.** `_PyThreadState_GET()` reads a
  `_Thread_local` on every call; under `-femulated-tls` that is a call into
  the shim's `__emutls_get_address`. Expect a measurable interpreter
  slowdown against Linux; measure with `pyperformance`-style microbenchmarks
  in the gate before drawing conclusions. If it matters, CPython can be
  built with `Py_HAVE_NATIVE_TLS` off, which falls back to `pthread_getspecific`.
* **`waitpid` semantics.** mlibc's `Waitpid` returns ECHILD for `pid <= 0`
  and EINVAL for any flag. CPython's `os.wait()` and `Popen.poll()` need
  `WNOHANG`; §7.1 covers it, but any stdlib path that waits for "any
  child" stays unsupported.
* **Directory reads yield one entry per call** (`ReadEntries`). Importing
  from a large `site-packages` does many `readdir` round trips through
  sys-io; measure import time of the standard library and cache the
  listing in `importlib` if it shows.
* **`open()` ignores `mode`** and `mkdir` ignores permissions: files are
  created with the role's default permissions. `tempfile` and `os.makedirs`
  are fine; tests asserting `0o600` will fail and should be skipped for
  `motor`.
* **No `AT_FDCWD`-relative resolution with a real dirfd.** `os.scandir`,
  `os.open(dir_fd=...)`, and `shutil.rmtree`'s safe mode use `*at` with a
  directory fd; mlibc returns EBADF for relative paths there. CPython
  should be configured with `ac_cv_func_openat=no`, `fdopendir=no`,
  `unlinkat=no`, `mkdirat=no`, `faccessat=no`, and `fstatat=no` so it uses
  the path forms.
* **`clock_gettime(CLOCK_PROCESS_CPUTIME_ID)` is EINVAL** and `getrusage`
  reports zeros, so `time.process_time()` returns 0. Profilers still work
  on wall time.
* **Locale data.** Only "C" exists; `locale.setlocale(LC_ALL, "")` returns
  "C", which is what UTF-8 mode expects. `str.format` with `n` and
  `locale.format_string` produce C-locale output.
* **`sys.platform == "motor"`** is a new name in the stdlib and test suite.
  Every `sys.platform.startswith("linux")` branch takes the generic POSIX
  path, which is the right default; audit `platform.py`, `sysconfig`, and
  `test.support` for places that need the name added to a skip list.
* **Assembly cost.** Each mlibc change reselects the assembly; batch the
  §6.3 and §7 sysdeps into as few mlibc commits as the gates allow.

## 12. Validation

* Phase 1: the `test-cpython.sh` gate of §6.4 on the release developer
  image; `python3 -m test test_json test_re test_threading test_socket
  test_importlib test_zipimport test_unicode test_decimal -x` with the
  network resource disabled, recorded pass/skip/fail counts, and the
  failure list checked into the test as the expected set so a regression
  is a diff, not a number.
* Phase 2: `subprocess` round trips (`check_output`, `communicate` with
  both pipes, `poll`), an `asyncio` echo server, `shutil.copytree` of the
  standard library into `/user/tmp`, and Ctrl+C in an rmux pane raising
  `KeyboardInterrupt` exercised through the `test-tui.sh` harness.
* Both phases: the mlibc changes are covered by the existing assembly
  validation and the C smoke tests in `docs/libc.md`; add a `getuid` and
  `clock_getres` check there so the abort cannot return.
* Per `AGENTS.md`, `src/sys/lib/moto-rt-cabi` changes are core: run
  `src/tests/full-test.sh` in debug and release three times each before
  committing them.

## 13. Effort estimate

| Phase | Content | Estimate |
| --- | --- | --- |
| 1 | mlibc sysdeps and `sys/ioctl.h`, CPython patch set and `config.site`, `Setup.local`, build stage, image staging, gate | 3 to 5 days, plus one assembly rebuild |
| 2 | shim exports, mlibc spawn file actions and `WNOHANG`, `subprocess.py` branch, Ctrl+C bridge, `shutil` tolerance or VDSO set-times | 1 to 2 weeks including gates |
| 3 | zlib, sqlite, bzip2, xz as static archives | 1 to 2 days each |
| 3 | OpenSSL | a separate plan; 1 to 2 weeks |

## Appendix A: cross-compiling C on the host and running it on the guest

Reproduces the probe without a VM build. `<llvm-key>` and `<assembly-key>`
are the current directories under `../build/toolchain/standalone-llvm/`
and `../assemblies/`.

```
B=$HOME/motor-dev/build/toolchain/standalone-llvm/<llvm-key>/bin
SR=$HOME/motor-dev/assemblies/<assembly-key>/sysroot/devtools/llvm
CF="--target=x86_64-unknown-motor -O2 -isystem $SR/include"
$B/clang $CF -c probe.c -o probe.o
$B/clang $CF probe.o $SR/lib/crt1.o \
  -Wl,--start-group $SR/lib/libmoto_rt_cabi.a $SR/lib/libc++abi.a \
  $SR/lib/libunwind.a $SR/lib/libc.a \
  $SR/lib/libclang_rt.builtins-x86_64.a -Wl,--end-group -o probe
```

Boot `vm_images/release/run-qemu.sh` detached, upload with `sftp -b -`
using `-mkdir /user/tmp/probe` and `-rm` before `put` (the guest sftp does
not overwrite), and run `/user/tmp/probe/probe 2>&1` over ssh with the
test key from `src/tests/test.key`. The guest shell is rush: it has no
`/dev/null` and no `head`, so redirect and filter on the host. mlibc's
missing-sysdep warnings go to stderr without a trailing newline and glue
themselves to the next stdout line; set stdout unbuffered in the probe.

The probe covered: a thread touching a `_Thread_local`; `sem_init`/`post`/
`trywait`; `pthread_condattr_setclock`; `pthread_attr_getstacksize`;
`getentropy`; anonymous `mmap`/`munmap`; `clock_gettime` for REALTIME and
PROCESS_CPUTIME; `clock_getres`; `setlocale`, `nl_langinfo`, `mbstowcs`,
`strcoll`, `%.17g`; `strftime`/`mktime`; `sigaction`, `pthread_sigmask`,
`siginterrupt`; `fcntl` F_GETFL/F_GETFD/F_SETFD; `uname`, `umask`, `chmod`,
`utimensat`, `tcgetattr`, `isatty`; `open(O_CREAT|O_EXCL)`, `write`,
`fchmod`, `fsync`, `rename`, `stat`, `unlink`; `sysconf`; `dlopen`;
`posix_spawnp` with `waitpid(WNOHANG)` and blocking `waitpid`; `pipe`,
`dup`, `socketpair`, `select`; `getpid`, `getuid`, `gettid`; and a
1 KiB-frame recursion on the main thread and on a pthread.
