# Porting CPython to Motor OS

Target CPython 3.14 as a static interpreter with its pure-Python standard
library. Build on Linux for `x86_64-unknown-motor` and package it as an
installable toolchain overlay. CPython source changes belong in its port.
C library and C ABI changes belong in the separate moturus/mlibc fork.

## First interpreter

1. Teach `configure.ac` and `Misc/platform_triplet.c` the Motor target.
   Use a matching host Python 3.14 for build-time generation, the Motor
   clang driver and sysroot for target objects, and a target `config.site`
   for probes that cannot run on the build host. Link as a static PIE with
   mlibc startup and emulated TLS.
2. Give the recursion guard the actual C stack bound. The initial Motor
   thread has 254 usable 4 KiB pages, much less than CPython's generic
   assumption. Check deep recursion on both the initial and spawned threads.
3. Enable UTF-8 filesystem and text defaults with the C locale. Audit
   `site.py` identity checks before enabling `os.getuid` and its relatives.
   Configure unavailable calls out or provide defined UID, GID, parent-PID
   and thread-ID behavior in mlibc. Coordinate this work with the
   [pgrust port](pgrust-port.md).
4. Select built-ins in `Modules/Setup.local`. Start with `_socket`,
   `select`, threading, Unicode, JSON, math, decimal, hashing and the
   other modules whose dependencies can be linked statically. Use the
   basic REPL. Configure out dynamic extensions, `ctypes`, fork-based
   modules and unsupported dirfd operations. Enable `fcntl` only for
   operations the target headers and mlibc support.
5. Stage the interpreter launcher in `/user/bin/dev` and its library under
   `/user/lib`. Check script execution, imports, bytecode caching, Unicode
   paths, bounded recursion, threads and local TCP/UDP in the guest.
   Distinguish unsupported modules from unexpected import failures.

## Subprocesses, terminals and file metadata

- Choose how `Popen` exposes pipe ends. One route adds a native standalone
  pipe and exact-target descriptor duplication through rt.vdso, moto-rt
  and mlibc. The narrower route binds the C shim's `moto_rt_spawn_ex` to
  Python and returns the parent ends created during spawn. Ordinary
  `posix_spawn` file actions alone cannot create those ends. Keep
  `_posixsubprocess.fork_exec` out of the Motor path. Cover independent
  stdin, stdout and stderr, `communicate`, nonblocking child status and
  error cleanup.
- For `asyncio`, use the loopback wakeup path when socket pairs are
  unavailable. Expose the runtime's Ctrl+C handler and wait interface
  to CPython so a terminal interrupt schedules `KeyboardInterrupt` on
  the interpreter thread. Account for terminal ownership and programs
  with captured stdin.
- Decide how `shutil.copy2` and `copytree` handle timestamps. Alternatives
  are a filesystem set-times operation or treating unsupported timestamp
  copying explicitly in `copystat`. Check creation modes, path `chmod`,
  `umask` and directory-relative operations against Motor role permissions.
- Check the remaining libc surface needed by enabled modules, particularly
  `clock_getres` and the missing `sys/ioctl.h` needed by the `fcntl` build.
  Report the real resolution of supported clocks and the limits of CPU
  time accounting. Use [the C runtime reference](../libc.md) for the
  supported spawn, wait and file actions.

## Optional modules and performance

- Select and package static libraries for compressed imports and archives,
  SQLite and line editing as those modules are enabled. CPython's `ssl`
  and accelerated `hashlib` need a separate TLS-library port. The initial
  installation must be usable with the built-in hashes and local files.
- Measure interpreter-state access through emulated TLS and module import
  costs from directory enumeration. Compare the pthread-key fallback only
  if TLS lookup is a material cost.
- Qualify the standard-library subset on the installed toolchain with
  local fixtures. Include subprocess round trips, an asyncio echo server,
  metadata copying and terminal interrupts as those features are added.
