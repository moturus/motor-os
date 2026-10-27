# Porting pgrust to Motor OS

2026-10-25. Assessment only. No code changes accompany this document, and it
does not plan the implementation. It lists what needs patching, on the
pgrust side and on the Motor OS side, to run pgrust on Motor OS.

Most of the work is outside the main Motor OS repository: in a pgrust fork,
in a new fork of the `libc` crate, and in the mlibc fork. Each item below
says which repository it touches.

Scope: the pgrust server (`postgres`), `initdb`, and pgrust's own client
tools, cross-built on Linux for `x86_64-unknown-motor` and serving SQL over
TCP. Out of scope for now: a native Lorry build, replication, and the
pgrust-specific instance control endpoint (`instaux`).

Decisions already taken:

* TLS uses rustls with the `ring` provider (the moturus/ring fork), as
  curl, httpd, httpd-axum, gix and gears-mock-provider already do. OpenSSL
  is not ported.
* Build resources are not a constraint: a larger build VM is acceptable.
* The `libc` crate gets a Motor OS module over mlibc. pgrust keeps calling
  libc rather than being rewritten onto moto-rt at each call site.
* The main-thread stack size is handled in pgrust (§5.5).

Provenance. Findings were gathered against:

* pgrust `38634b408d` (v0.4-beta, Postgres 18.6 compatible) at `../pgrust`;
* Motor OS `a3d739f9` (branch `dev`); the mlibc fork at `52bed56c`
  (`../toolchain-src/mlibc`); the Motor OS Rust std at
  `../toolchain-src/rust` (Rust 1.99.0 beta, toolchain
  `motor-1.99.0-beta-f47d5bb-dev.2`);
* moturus/mio at `e488415` (branch `motor-1.2.0`, the Cargo checkout);
* crates.io `libc` 0.2.190;
* one measurement: `cargo check --locked --keep-going --target
  x86_64-unknown-motor -p main_main --bin postgres` with the Motor OS
  toolchain. Everything else is from reading code; items not yet confirmed
  on a running VM are marked "to verify".

## 1. Summary

pgrust has no property that rules out Motor OS. Three facts make the port
tractable:

* pgrust runs backends as threads, not processes. `fork` survives only in
  an optional crash supervisor.
* pgrust already has a WASI build (`wasm32-wasip1`). It added per-site
  fallbacks for no `mmap`, no signals, no `dlopen`, no uids, and no C
  libraries. About 830 `target_family = "wasm"` gates across about 100
  crates mark these places, and many apply to Motor OS unchanged.
* Gravity, pgrust's query engine, falls back to its interpreter when the
  platform refuses executable memory. Motor OS refuses it to ordinary
  processes.

The work splits into:

1. **Motor OS side** (§4): a new `libc` crate module for Motor OS, two or
   three small mlibc sysdeps, and, for performance only, native
   thread-local storage.
2. **pgrust side** (§5): Motor OS code paths in about 100 crates. Most
   reuse the WASI fallback. Three need new Motor OS-specific code: event waits
   (over `moto_rt::poll`), process control without signals, and server TLS
   with rustls.

The main open risk is performance, not function: thread-local access cost
(§6).

## 2. pgrust in numbers

* 1.08M lines of Rust in 937 workspace crates; the `postgres` binary links
  906 of them.
* pgrust pins Rust 1.96.0. The Motor OS toolchain is 1.99 beta.
* External dependencies of the `postgres` binary: pure-Rust crates, plus
  `libc`, vendored OpenSSL (`openssl-src`), `zstd-sys`, and mimalloc
  (`third_party/libmimalloc-sys`). Cranelift, wasmtime, loom and shuttle
  are development-only.
* 116 crates call `libc` outside tests; they use 182 distinct libc
  functions. The code follows C Postgres: raw file descriptors, `errno`,
  and C-shaped error handling.
* 964 `thread_local!` declarations and 688 `catch_unwind` uses (pgrust
  raises Postgres errors as panics).
* pgrust is AGPL-3.0. Motor OS is MIT/Apache-2.0.

Motor OS's Rust target is neither `unix` nor `wasm`. pgrust's code paths
are split into `not(target_family = "wasm")`, which in practice means
Linux or macOS through libc, and `target_family = "wasm"`. Motor OS
compiles the first group today and fails there.

The measured check confirms this. Compilation stops at the bottom of the
dependency graph:

* nine crates fail (`vfs`, `ip`, `wait_error`, `pg_clock`, `pg_rusage`,
  `pg_strong_random`, `pgstrcasecmp`, `libpq_pqsignal`, `fdnb`);
* every error is a missing `libc` item;
* the mimalloc and OpenSSL build scripts fail;
* nothing above that layer was checked.

## 3. What Motor OS already provides

These need no Motor OS change:

* **Threads.** pthreads in mlibc and threads in Rust std. Rust std honours
  explicit thread stack sizes.
* **Shared descriptors.** A C socket or file is the same runtime object as
  a Rust one (`docs/libc.md`). The fd number itself is to verify, §4.4.
* **Event waits.** `moto_rt::poll` is a registry with tokens, read and
  write interest, deadlines, and `wake()`. moturus/mio's Motor OS backend
  (`src/sys/motor/selector.rs`, `waker.rs`) shows how to use it.
* **Networking.** TCP and UDP, `poll`/`select`, and `getaddrinfo`
  (numeric and hosts file) in mlibc.
* **Files.** `open`, `pread`/`pwrite`, `fsync`, `ftruncate`, `rename`,
  `stat`, `dirent`, `openat`, and `O_CREAT|O_EXCL`.
* **Processes.** `posix_spawn` and `waitpid` in mlibc. Rust's
  `std::process::Command` with piped stdin, which `initdb` uses to drive
  the server.
* **Lazy anonymous memory.** `F_LAZY` reservations cost nothing until
  touched.
* **TLS stack.** rustls with ring runs on Motor OS in five programs in
  `src/bin` (curl, httpd, httpd-axum, gix, gears-mock-provider); russhd
  uses ring directly.
* **Constructors.** ELF constructors run when the program links through
  mlibc's `crt1.o` (`motor-rust-cc`).

## 4. Motor OS side

### 4.1 A Motor OS module in the `libc` crate (new repository, required)

crates.io `libc` has no Motor OS bindings. Its only mention of Motor OS is
a comment. pgrust needs one, as would any other libc-based Rust crate on
Motor OS.

This is a fork of `rust-lang/libc` (for example `moturus/libc`). It is a
new repository outside the main Motor OS tree. Its module:

* declares the functions mlibc provides, with mlibc's ABI;
* takes constants and most structures from Linux: Motor OS's mlibc symlinks
  its `abi-bits` headers to `abis/linux` (`errno`, `O_*` flags, `stat`,
  `sockaddr*`, `pollfd`, signals, `rlimit`, `termios`);
* defines mlibc's own types separately, because they differ from glibc's:
  `pthread_*`, `FILE`, `locale_t`, and the `passwd` and `addrinfo`
  layouts must be checked against mlibc's headers;
* exposes `errno` the way mlibc does (`__errno_location`, emulated TLS).

It also needs layout tests that compare the Rust definitions against the
mlibc sysroot headers.

pgrust would take the fork through `[patch.crates-io]`. Programs that use
it must link through `motor-rust-cc` so that mlibc is present.

### 4.2 mlibc sysdeps (`../toolchain-src/mlibc`, recommended)

These are small and benefit every C or libc-based program. Each one could
instead be avoided in pgrust; §5 says where.

* **Identity calls abort.** `getuid`, `geteuid`, `getgid`, `getegid`,
  `getppid` and `gettid` abort the process when they have no Motor OS sysdep
  (seen on the VM 2026-09-10, `docs/plans/cpython.md`). pgrust calls
  `geteuid` from 18 sites, `getuid` from 2 and `getppid` from 2. Fixed
  sysdeps (for example uid 0 or a fixed value) remove the trap for
  everyone.
* **`fdatasync` returns ENOSYS.** Motor OS has no `Fdatasync` sysdep.
  Postgres's default `wal_sync_method` on Linux is `fdatasync`, and an
  fsync failure on WAL is a PANIC. Mapping it to `Fsync` is one line.
  Otherwise pgrust must default to `fsync` on Motor OS.
* **`getrlimit` returns ENOSYS** for every resource. pgrust reads
  `RLIMIT_NOFILE` (descriptor budget) and `RLIMIT_STACK` (stack sizing).
  Returning a fixed or infinite limit would match what Motor OS actually
  enforces. pgrust can also handle ENOSYS itself.

Each change to mlibc selects a new toolchain assembly
(`MOTOR_MLIBC_REV`, `docs/toolchain.md`).

### 4.3 Native thread-local storage (`src/sys`, performance only)

Motor OS's Rust target sets `has_thread_local: false`. std's `thread_local!`
then takes the OS-key path:

* each access is an indirect call into rt.vdso (`moto_rt::tls::get`);
* the vdso looks the key up in a per-thread `BTreeMap`
  (`rt.vdso/src/rt_tls.rs`).

pgrust has 964 `thread_local!` declarations, and several are read on hot
paths: memory contexts, interrupt checks, executor state. The cost per
access is not measured. The expected order is tens of nanoseconds instead
of about one.

The real fix spans the kernel or loader, the rustc target spec, and the
toolchain: static TLS through `%fs`, with the loader accepting `PT_TLS`. It
helps every Rust program on Motor OS. This is a separate core-OS project;
the port works without it, only slower (§6).

### 4.4 To verify (may turn into patches)

* **mlibc fds as moto-rt fds.** An fd from mlibc `socket()` or `accept()`
  must be the number `moto_rt::poll::add` expects. `docs/libc.md` says the
  objects are shared, which suggests yes.
* **WAL durability.** The Motor OS filesystem (`motor-fs`) is built for VMs: block writes
  are assumed atomic, and only power-off is guarded against. What does
  `fsync` guarantee for file data and metadata, and does it reach the
  virtio-blk flush?
* **Directory fsync.** Postgres opens a directory and fsyncs it after
  renames and creates. What does `open()` on a directory return on Motor
  OS, and does `fsync` on it mean anything? Postgres ignores some errors
  here, so rename durability then rests on the Motor OS filesystem's own metadata
  ordering.
* **Unwinding.** pgrust's errors are panics caught with `catch_unwind`
  (688 sites). Motor OS's std has unwinding support, and a Motor OS test calls
  `catch_unwind`. pgrust's heavy use has not been tried, nor has unwinding
  across threads with large stacks.
* **Large file I/O.** 1 GB relation segments, many open files, and large
  sparse files.

### 4.5 Not needed

* **No new poll or wake API.** `moto_rt::poll` covers event waits
  (§5.4).
* **No executable memory for user processes.** Gravity's interpreter
  covers it (§5.13).
* **No `pipe`, `socketpair` or Unix-domain sockets.** pgrust's uses can be
  replaced (§5.4, §5.10).
* **For a native Lorry build only:** the moturus/ring fork needs crates.io
  ring's `pregenerated/`. That work is staged locally, not yet pushed.

## 5. pgrust side (fork, outside the main repository)

All changes in this section are in a pgrust fork.

### 5.1 Platform selection

Motor OS needs its own code paths beside Linux, macOS and WASI:

* In most places the WASI fallback is right, and the gate widens to cover
  Motor OS as well, for example
  `any(target_family = "wasm", target_os = "motor")`.
* In others the native path works once `libc` has Motor OS bindings (§4.1).
* A few places need Motor OS-specific code: §5.3, §5.4 and §5.7.

The WASI fallbacks assume one thread, no sockets, and no wake sources.
Motor OS has all three, so each WASI fallback has to be checked before it
is reused.

Bug-for-bug behaviour with C Postgres stays the goal, as upstream pgrust
intends. Where Motor OS cannot match it, the change should report a clean
error, as the WASI build does.

### 5.2 Build and link

* **Linking.** Link `postgres` and the client tools through
  `motor-rust-cc`. mlibc is needed for libc, and its `crt1.o` runs
  `.init_array`, which `pagepool::by_arch_default!` relies on.
* **Allocator.** mimalloc's build script fails for Motor OS. Use the
  system allocator under `init_small::oom::Rescue`, as WASI does. The
  mimalloc-specific code (`thread_retained_bytes`, the `allocarena` arenas
  given to mimalloc) takes its WASI stub.
* **zstd.** Either cross-compile `zstd-sys` for Motor OS (plain C, as
  SQLite was) or take the WASI arm, where columnar storage falls back to
  LZ4 and refuses zstd-compressed data when reading it.
* **re2.** `regexp_alt` probes for re2 and uses its stub engine without it
  (`PGRUST_FORCE_NO_RE2=1`).
* **Commit hash.** `main_main`'s `build.rs` runs `git` and tolerates a
  failure.
* **Linux-only link flags** are already gated by target and need nothing.

### 5.3 TLS and crypto with rustls

* **Server TLS.** `be_secure`'s `ssl` feature selects `be_secure_openssl`
  (2,434 lines). It implements Postgres's TLS functions: `be_tls_init`,
  `be_tls_open_server`, `be_tls_read`/`be_tls_write`/`be_tls_close`, and
  getters for cipher, version, peer DN, serial, extensions and the
  certificate hash. A `be_secure_rustls` crate provides the same
  functions.
  * Outside callers: `backend_status` (`pg_stat_ssl`) and
    `contrib/sslinfo`.
  * Direct-SSL ALPN (`postgresql`) and the bytes read before the handshake
    map directly onto rustls.
* **Certificate details** (DNs, serial, extensions; `clientname=CN|DN`
  client-certificate login; `tls-server-end-point` channel binding for
  SCRAM-SHA-256-PLUS) need an X.509 parser such as `x509-parser`. rustls
  hands back only the raw DER certificate.
* **Behaviour differences from OpenSSL:**
  * `ssl_ciphers` uses OpenSSL's cipher-string syntax;
  * no finite-field DHE, so `ssl_dh_params_file` has no effect;
  * TLS 1.2 and 1.3 only;
  * `ssl_passphrase_command` with encrypted keys needs a PKCS#8 crate;
  * CRLs work through rustls-webpki, with different error text;
  * `ssl_library` and cipher names change.
* **pgcrypto.** Its ciphers already use RustCrypto. `digest()` and `hmac()`
  look digests up by OpenSSL name, and RustCrypto covers the common ones.
  The FIPS check reports off.
* **Client tools (`pgclient`).** Client TLS moves to rustls in the same
  way.
* **Fenced off, as on WASI:** LDAP over TLS in `auth`, OAuth validators,
  and `instaux`. Each can move to rustls and ring later.

Still to decide: whether the rustls backend is Motor OS-only, or selectable on
Linux too so it can be tested on the host (§7).

### 5.4 Event waits and latch wake-ups

* **New backend.** `waiteventset` picks `epoll.rs` (174 lines) on Linux,
  `kqueue.rs` (217 lines) elsewhere, and a time-only stub on WASI. Motor
  OS needs a fourth, `motor.rs`, over `moto_rt::poll`, modelled on mio's
  Motor OS selector.
  * It uses `moto_rt::poll` directly rather than mio. pgrust registers raw
    fds, and mio has no `SourceFd` on Motor OS.
  * pgrust takes `moto-rt` from crates.io.
* **Edge versus level triggering.** `moto_rt::poll` is edge-triggered: a
  wait takes the queued events (`collect_events`,
  `rt.vdso/src/runtime.rs`). Postgres expects level-triggered waits:
  unread data is reported again.
  * Adding or re-setting a registration reports the source's current
    state; TCP streams do this in `maybe_raise_events`,
    `rt.vdso/src/net/rt_tcp.rs`.
  * So the backend re-sets each socket's registration before every wait.
    Wait sets are small (usually one socket and the latch).
* **Latch wake-ups.** `waiter` uses a self-pipe per thread
  (`ensure_wake_pipe`, a one-byte write to wake). mlibc has no `pipe`.
  * The Motor OS version uses a per-waiter `moto_rt::poll` fd, registered in
    the wait set as readable and woken with `moto_rt::poll::wake`, as
    mio's `Waker` does. There is nothing to drain.
  * The existing ordering (set the latch flag, then wake; recheck the flag
    after arming) has to hold with the new primitive.
* **Postmaster death** (`WL_POSTMASTER_DEATH`) is already marked not
  ported under the thread model.
* **Plain `poll()`** users need nothing beyond the libc bindings: `fdnb`,
  `fd/desc.rs`, `pgclient`, RADIUS and `postgres_fdw`.

### 5.5 Main-thread stack and the stack-depth guard

pgrust's instructions ask for `ulimit -s 65520` and a 32 MiB
`RUST_MIN_STACK`.

* Backends run on spawned threads with explicit stack sizes, which works
  on Motor OS.
* The main thread has a fixed ~1 MiB stack on Motor OS. The postmaster,
  `--single` and `initdb`'s bootstrap runs all run on it.
* An overflow kills the process silently.

Motor OS needs:

* the main thread's work moved onto a spawned thread with a large stack;
* the stack-depth guard (`stack_depth_core`) given its bounds directly.
  `getrlimit(RLIMIT_STACK)` returns ENOSYS and `pthread_getattr_np` does
  not exist.

### 5.6 Identity

Unless the mlibc sysdeps of §4.2 land, every `geteuid`, `getuid`,
`getppid` and `gettid` call on Motor OS has to take WASI's fixed identity,
or the process aborts.

* The WASI fixed identity is: process id 1, ownership checks skipped (the
  shape of C Postgres's Windows code), user name from the environment.
* Sites to cover include the "do not run as root" check, data-directory
  ownership checks, `getpwuid` user lookup, and peer authentication.

### 5.7 Signals and process control

Motor OS delivers no signals from outside the process. Under the thread
model pgrust already emulates per-backend signals (`statement_timeout`'s
SIGALRM, `pg_cancel_backend`, interrupts) inside the process. What remains:

* **Shutdown and reload.** `pg_ctl stop` sends SIGTERM, SIGINT or SIGQUIT;
  configuration reload sends SIGHUP. Neither can reach the process.
  Shutdown and reload need another trigger. One existing piece is Motor OS's
  terminal Ctrl+C mechanism (`docs/tui.md`), which covers a foreground
  server only. The choice is open (§7).
* **Crash restart.** The supervisor (`postmaster/supervisor.rs`) needs
  `fork` and passes listen sockets over `SCM_RIGHTS`. It stays off; its
  no-supervisor switch exists. A hard crash then ends the server, and the
  next start runs crash recovery.
* **Crash handlers** (`SIGSEGV` with `sigaltstack`, `crash_signals.rs`)
  become inert. mlibc records signal dispositions but never delivers
  them.
* **Subprocess exits.** Code that waits for children through signals,
  such as the syslogger, archiver and `wait_error`, follows its WASI
  fallback or polls `waitpid`.

### 5.8 Memory management

pgrust sizes one memory budget from the machine. Its page pool, allocator
arenas and memory runtime manage memory with calls Motor OS lacks:

* `madvise` (returning pages), `mprotect`, `mincore`, `mremap`;
* `prctl` (naming mappings), `MAP_NORESERVE`;
* `/proc` and `smaps` reads.

The crates involved are `pagepool`, `pagegive`, `allocarena`,
`memruntime`, `bufmgr` and `mempolicy`.

Motor OS has anonymous and lazy mappings, and whole-mapping unmap only:
there is no way to give back part of a mapping.

* **Allocator.** With the page pool off (the WASI shape), the default
  allocator runs, and pgrust's out-of-memory protection degrades to the
  emergency-reserve retry in `init_small::oom::Rescue`.
* **Machine size.** Physical memory should come from Motor OS
  (`SysMem::query_stats`) rather than `sysconf` or cgroups, so the budget
  is sized from the VM.
* **Admission floor.** Motor OS's admission floor applies. Failed allocations
  return null, and stack growth can fail
  (`docs/oom-handling.md`).

### 5.9 File I/O and the filesystem

* **`vfs`/`fd` platform calls.** Calls Motor OS lacks or does not need get
  fallbacks or no-ops: `O_DIRECT`, `posix_fadvise`, `sync_file_range`,
  `fallocate`/`posix_fallocate`, `copy_file_range`, `syncfs`, `statvfs`,
  `utime`, `link`, `chown`, xattrs.
* **WAL sync method.** `fdatasync` maps to `fsync`, unless §4.2 lands.
* **No io_uring.** Only `io_method=sync` is supported.
* **No file-backed `mmap`.** Columnar storage's segment map takes the WASI
  heap-buffer arm, and so does any other file mapping.
* **No symlinks.** Tablespaces are unsupported. Uses of
  `std::os::unix::fs::symlink` (17) need Motor OS arms or an error.
* **`std::os::unix`.** Motor OS's std has no `std::os::unix`. Its
  `std::os::motor::ffi` is unstable and string-based. 41 non-test files
  use `std::os::unix`:
  * `OsStrExt::as_bytes` (22 uses) becomes `as_encoded_bytes`;
  * `PermissionsExt`, `MetadataExt`, `OpenOptionsExt`, `DirBuilderExt` and
    `FileExt` need Motor OS arms, such as libc calls or plain std;
  * `UnixStream` and `CommandExt` are covered in §5.10 and §5.14.
* **Permissions.** Data-directory mode checks (`0700`/`0750`) meet Motor
  OS's own permission model (`docs/fs-permissions.md`). They take the
  WASI arm or a Motor OS-specific check.

### 5.10 Networking

* **TCP only.** Motor OS has no Unix-domain sockets; `AF_UNIX` appears in
  20 files.
  * The server runs with `unix_socket_directories=''` and TCP
    `listen_addresses`.
  * The client tools must not default to a socket directory.
* **Socket handoff.** `SCM_RIGHTS` is only used by the supervisor (§5.7).
* **Peer credentials.** `getpeereid`/`SO_PEERCRED` do not exist, so
  `peer` authentication is unsupported. Use `trust`, `scram-sha-256` or
  certificates.
* **Socket options.** TCP keepalive and other `setsockopt` options mlibc
  rejects must not be fatal.
* **Interface listing.** `getifaddrs`, used for `samehost`/`samenet` in
  `pg_hba.conf`, needs a fallback.

### 5.11 Locale, encodings, ICU and XML

* **Locales.** mlibc supports only the C locale: `setlocale(LC_ALL, "")`
  gives "C", and "C.UTF-8" returns NULL. `nl_langinfo(CODESET)` reports
  ASCII.
  * `initdb` runs with `--no-locale --encoding UTF8`.
  * pgrust's locale code (`pg_locale`, `newlocale`/`uselocale`) takes the
    C-locale path.
  * Encoding detection must not trust the codeset.
  * `CREATE COLLATION` from system locales (`collationcmds`, which runs
    `locale -a`) is unsupported.
* **ICU and libxml.** Both load through `dlopen`, which does not exist.
  They report "not supported", as on WASI.

### 5.12 Extensions and dynamic loading

There is no `dlopen` (30 files use it). Loading C extensions, `LOAD`, and
loadable procedural languages are unsupported. Built-in contrib modules
work.

### 5.13 JIT

* **Gravity.** Gravity maps compiled code executable through its own
  machine-code compiler (`crates/tpde`). Motor OS refuses executable
  memory for ordinary processes: self-mapping needs `CAP_IO_MANAGER`.
  `gravity_backend::compiled_or_interpreted` already falls back to the
  tier-0 interpreter when mapping is refused, today on macOS only. Motor
  OS takes that path, or turns compilation off outright.
* **Tuple decoding JIT.** `jit_deform` uses `PROT_EXEC` the same way and
  needs its non-JIT path.

### 5.14 Subprocesses and pipes

* **`std::process::Command`** works, including piped stdin and stdout.
* **`popen` is unsupported in mlibc.** It is used by
  `OpenPipeStream`/`COPY ... PROGRAM`, `ssl_passphrase_command`, and
  `collationcmds`. `system()` works, which covers `archive_command` and
  `restore_command`.
  * The `popen` users move to `std::process::Command`, or report an error.
* **`CommandExt` and `ExitStatusExt`** (Unix-only std) need Motor OS arms.
  Motor OS has no signals to
  report in an exit status.
* **psql.** It uses `tcgetattr`/`tcsetattr` for password prompts and line
  editing. mlibc returns ENOSYS, and psql must work without them.

### 5.15 Smaller items

* **`getrusage`** reports zeros: `log_*_stats` and `pg_rusage` show zero
  CPU time.
* **`sysconf`** supports page size and processor count. pgrust's other
  queries need defaults.
* **Unsupported and skipped:** `sched_getaffinity`/`sched_setaffinity`,
  `getpriority`, `mlock`, `getauxval`, `dl_iterate_phdr`, `mallinfo2`.
* **No syslog.** `log_destination=syslog` is unsupported; stderr and the
  logging collector remain.
* **Linux-only `asm!`** (for example thread-pointer reads in `pagepool`)
  is already gated to Linux.

## 6. Performance risks

These do not block a working port; they decide whether it is useful.

* **Thread-local access** (§4.3): the largest risk. It is not measured
  yet.
* **File I/O through sys-io.** Every 8 KB page read or write and every WAL
  write is an IPC round trip. fsync latency sets commit latency. Without
  io_uring and read-ahead hints, sequential scans depend on the Motor OS filesystem
  caching.
* **No JIT.** Gravity runs on its interpreter.
* **Memory.** The WASI build peaks at about 118 MiB with
  `shared_buffers=32MB`. Pages, once touched, stay committed until unmap.
* **Wait-set re-registration** (§5.4) costs one or two vdso calls per
  wait. Expected to be small.

## 7. Open decisions

1. **License.** pgrust is AGPL-3.0. Shipping it in a Motor OS image, or
   offering it as a network service, carries AGPL obligations.
2. **Shutdown and reload.** What replaces `pg_ctl stop`, `pg_ctl reload`
   and `kill -HUP`? It must work without signals and without fork (§5.7).
3. **mlibc versus pgrust.** Fix identity calls, `fdatasync` and
   `getrlimit` in mlibc (§4.2), or work around them in pgrust only?
4. **The rustls backend.** Motor OS only, or selectable on Linux as well
   for host testing (§5.3)?
5. **Native thread-local storage.** Is it in scope as a core-OS project
   (§4.3)?
6. **Upstream.** A fork carrying Motor OS-specific code at a few hundred
   sites is costly to rebase on a fast-moving beta. Should we offer a
   Motor OS target upstream, as the WASI build was upstreamed?

## 8. Out of scope here

* Implementation steps, ordering, and tests.
* A native Lorry build on Motor OS. It is plausible, but needs a large
  build VM and is unmeasured.
* Replication, logical decoding, `instaux`, LDAP, OAuth, GSSAPI, ICU, XML,
  tablespaces and loadable extensions.
