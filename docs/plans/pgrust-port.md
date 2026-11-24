# Porting pgrust to Motor OS

Target a Linux cross-build of the pgrust PostgreSQL server, `initdb`
and its client tools serving SQL over TCP. The main work belongs in an
external pgrust fork. C runtime changes belong in the separate
moturus/mlibc fork. Decide whether and how to distribute the
AGPL-licensed software and maintain the port upstream before packaging it.

## C ABI and storage

- Select the existing `moturus/libc` Motor bindings in pgrust's dependency
  graph. Check which PostgreSQL call sites need declarations beyond those
  bindings. Link the binaries through the C runtime so ELF constructors
  initialize their registrations. The toolchain's fork and version are
  listed in [Building Rust](../build-rustc.md).
- Define UID, GID, parent PID and thread ID where callers require them, or
  use explicit Motor paths for identity and ownership. Decide whether
  descriptor and stack limits belong in mlibc's `getrlimit` or in
  pgrust's resource sizing. The identity work also affects the
  [CPython port](cpython.md).
- Select a durable WAL sync method. Either map `fdatasync` in mlibc or
  select `fsync` in pgrust. Establish file and directory guarantees for a
  commit, rename and crash recovery on motor-fs, including device flush
  errors. Check large sparse relation segments, descriptor pressure and
  directory sync after a create or rename.
- Adapt the Unix file and metadata calls to Motor role permissions,
  especially the data-directory ownership check. Use synchronous I/O and
  heap-backed segment reads where pgrust expects file-backed mappings.
  Tablespace paths that require symlinks need an explicit unsupported result.

## Server runtime

- Classify platform-specific call sites individually. Motor has native
  threads, sockets and wake sources. Some WASI fallbacks are suitable for
  optional facilities, but single-threaded wait and networking stubs
  cannot serve a database. Replace or disable mimalloc, choose zstd or
  the LZ4 fallback, and set the optional re2 policy.
- Move main-thread database work to a suitably sized thread or supply
  explicit bounds to the stack-depth guard. The postmaster, single-user
  server and `initdb` bootstrap all need to avoid overflowing the initial
  stack. Verify error unwinding through `catch_unwind` in backend threads.
- Implement `waiteventset` over `moto_rt::poll`. Verify that mlibc socket
  descriptors can be registered directly. PostgreSQL expects unread data
  to remain ready across waits. Rearm edge-triggered registrations and
  recheck before parking. Use a poll waker for each latch, preserving the
  flag-before-wake and arm-before-recheck ordering.
- Define shutdown, reload and cancellation for `pg_ctl` and a background
  server. Terminal Ctrl+C only covers foreground operation. Keep the
  fork-based crash supervisor and its descriptor passing out of this port.
  Define how the next start performs crash recovery and how child exit is
  observed without asynchronous signals.
- Size the memory budget from guest RAM. Choose fallbacks for page return,
  partial unmap, residency queries and `/proc` accounting. Check behavior
  under the guest's OOM policy and the emergency allocation reserve.
  Use Gravity's interpreter and a non-JIT tuple decoder for ordinary roles.

## Clients, authentication and optional features

- Use TCP for server and client defaults. Define `pg_hba.conf` behavior
  for local-interface rules in the absence of `getifaddrs`. Provide SCRAM
  or certificate authentication for network clients. Unix-domain peer
  authentication needs a different transport and identity contract.
- Implement server and client TLS with rustls and ring. Cover PostgreSQL
  ALPN, buffered handshake input, certificate identity, SCRAM channel
  binding, CRLs, and the values exposed via `pg_stat_ssl` and `sslinfo`.
  Decide which cipher configuration, encrypted keys and certificate
  extensions to support, and whether Linux should offer the same backend.
  Replace the OpenSSL digest lookup used by `pgcrypto`.
- Adapt the C locale for UTF-8 databases and `initdb`. Make the limits on
  collations, dynamic extensions, ICU, XML and loadable languages visible
  to callers. Keep replication, LDAP, OAuth, GSSAPI and `instaux` outside
  the initial port.
- Replace `popen` users such as `COPY ... PROGRAM` with a supported child
  API or an explicit error. Adapt psql's line editing and secret prompts
  to the terminal interface. Specify unsupported resource counters,
  scheduling calls and syslog settings.

## Performance decisions

Measure thread-local accesses on query hot paths, WAL flush latency,
sequential scans, poll rearming and resident memory under load. Native TLS
would span the loader, Rust target and external toolchain. Consider that
separate core change only after measuring the cost of emulated TLS in the
server. A native Lorry build is a separate scope decision.
