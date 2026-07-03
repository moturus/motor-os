# Appendix G — M6, step by step

> Part of the Motor OS libc porting guide — main: [porting-libc-by-fable.md](porting-libc-by-fable.md); appendices: [A: M0 toolchain](porting-libc-appendix-a.md) · [B: M1 shim](porting-libc-appendix-b.md) · [C: M2 mlibc](porting-libc-appendix-c.md) · [D: M3 stdio+malloc](porting-libc-appendix-d.md) · [E: M4 filesystem](porting-libc-appendix-e.md) · [F: M5 threads+TLS](porting-libc-appendix-f.md) · [G: M6 sockets](porting-libc-appendix-g.md)

M6 is BSD sockets: TCP client/server, UDP (incl. connected UDP), `getsockname`/
`getpeername`, `shutdown`, the common `setsockopt`s, nonblocking sockets, plus
name resolution (`getaddrinfo`). All facts verified against mlibc `368a00fa` and
the in-tree VDSO/moto-rt.

The impedance mismatch, stated up front: **mlibc speaks BSD** (`socket()` creates
an unbound fd; `bind`/`connect` come later), while **Motor creates sockets bound
or connected** (`net::bind(proto, addr) -> fd`, `net::tcp_connect(addr) -> fd` —
there is no bare-socket state). The port bridges this with a sysdep-side
**pseudo-socket table** (G.3). Everything else maps close to 1:1 — Motor's net
API turns out to be far more BSD-shaped than its Rust-std pedigree suggests.

Two very good facts, verified in source:

- **Socket fds are ordinary posix fds.** `TcpStream`, `TcpListener`, `UdpSocket`
  all implement `PosixFile` (`rt.vdso/src/net/rt_tcp.rs:91,564`, `rt_udp.rs:452`),
  so our existing `Read`/`Write`/`Close` sysdeps work on materialized sockets
  unchanged — `read`/`write`/`close` on a connected TCP fd need nothing new.
- **Loopback works.** systest exercises UDP over `127.0.0.1` (`systest/src/udp.rs`),
  so m6 can run self-contained in one process (threads courtesy of M5) without
  external networking.

## G.1 What mlibc needs (audited call sites)

All socket functions live in the `posix` option group (already enabled). From
`options/posix/generic/sys-socket.cpp`, the tags to implement — 12 + 1:

| Tag | Called from | Notes |
|---|---|---|
| `Socket` | `socket()` | `(family, type, protocol, *fd)`; `type` carries `SOCK_NONBLOCK`/`SOCK_CLOEXEC` flags |
| `Bind`, `Connect` | `bind()`/`connect()` | Linux-ABI `struct sockaddr *` |
| `Listen` | `listen()` | |
| `Accept` | `accept()`/`accept4()` | `(fd, *newfd, addr, *addrlen, flags)`; addr out-params optional |
| `Sendto`, `Recvfrom` | `send`/`sendto`/`recv`/`recvfrom` | **preferred over the msghdr path**: `sendto()` checks `IsImplemented<Sendto>` first and only falls back to `MsgSend` — so `MsgSend`/`MsgRecv` (ancillary data, iovecs) can be skipped entirely at M6 |
| `Shutdown` | `shutdown()` | `SHUT_RD/WR/RDWR` = 0/1/2 |
| `Sockname`, `Peername` | `getsockname()`/`getpeername()` | `(fd, addr, max_len, *actual_len)` |
| `SetSockopt`, `GetSockopt` | `setsockopt()`/`getsockopt()` | `(fd, layer, number, buf, [*]size)` |
| `Fcntl` | `fcntl()` | `(fd, request, va_list, *result)` — minimal support (G.3.5): `F_GETFL`/`F_SETFL` for `O_NONBLOCK`, `F_GETFD`/`F_SETFD` no-ops. High value for M7; also unblocks mlibc-internal users. |

Not implemented (resolve to `ENOSYS` via `sysdep_or_enosys`, which the call
sites use): `Socketpair`, `Sockatmark`, `MsgSend`/`MsgRecv`.

**getaddrinfo** (`netdb.cpp:273`) is generic mlibc code with a three-step
resolver chain, no resolver sysdep exists:

1. `lookup_name_ip` — numeric addresses; pure parsing, works with nothing.
2. `lookup_name_hosts` — reads `/etc/hosts` with `fopen` (works since M4, if the
   file exists on the image).
3. `lookup_name_dns` — mlibc's own DNS client: reads `/etc/resolv.conf`, then
   speaks DNS over **UDP sockets** (`lookup.cpp:77-164`) — i.e. it starts working
   the moment our UDP sysdeps do, provided `resolv.conf` names a reachable
   server. Motor's native `dns_lookup` vtable entry (`moto_rt::net::lookup_host`)
   goes unused by mlibc — there is no sysdep hook to route it through; noted as
   a possible future custom patch, not M6.

m6 tests step 1; steps 2–3 are configuration (files on the image), documented
but not gated on.

## G.2 The Motor side (audited)

`moto-rt/src/net.rs` — per-fd, C-struct-based, nearly BSD:

| Motor API | Maps to |
|---|---|
| `bind(proto: u8, addr) -> RtFd` (`PROTO_TCP`=1, `PROTO_UDP`=2) | socket **creation** for servers and UDP |
| `listen(fd, backlog)`, `accept(fd) -> (fd, sockaddr)` | `listen`/`accept` |
| `tcp_connect(addr, timeout: Duration, nonblocking: bool) -> RtFd` | socket **creation** for TCP clients |
| `udp_connect(fd, addr)` | connected UDP |
| `socket_addr(fd)`, `peer_addr(fd)` | `getsockname`/`getpeername` |
| `shutdown(fd, how)` (`SHUTDOWN_READ`=1, `SHUTDOWN_WRITE`=2, or'able) | `shutdown` (note: Linux `SHUT_RD`=0! translate) |
| `set_nonblocking`, `peek`, `udp_recv_from/peek_from/send_to` | `O_NONBLOCK`, `MSG_PEEK`, UDP I/O |
| `set/get`: nodelay, ttl, broadcast, linger, only_v6, read/write timeouts, `take_error` | the `setsockopt` surface |
| `lookup_host(host, port)` | native DNS (unused by mlibc, G.1) |

**The address ABI is NOT Linux.** `moto-rt/src/netc.rs`: `sa_family_t` is **u8**
(Linux: u16), `AF_INET` = **0** (Linux: 2), `AF_INET6` = **1** (Linux: 10), and
`sockaddr_in6` field order differs (Motor: family, port, addr, flowinfo, scope;
Linux: family, port, flowinfo, addr, scope). Layouts, `repr(C)`:

- `netc::sockaddr_in`: `{u8 family; u16 port(be); u32 addr}` → offsets 0/2/4,
  size 8, align 4.
- `netc::sockaddr_in6`: `{u8; u16; [u8;16]; u32 flowinfo; u32 scope}` → offsets
  0/2/4/20/24, size 28.
- `netc::sockaddr` is a **union** of the two, size 28.

So the sysdeps translate field-wise in both directions (G.5); the shim carries a
C mirror of the union (G.4) with size asserts on both sides.

Also relevant: the VDSO has an epoll-shaped poll API (`moto-rt/src/poll.rs`:
`new/add/set/del/wake/wait`) — POSIX `poll()` over it is deferred to M7 (G.6).

## G.3 The design

### G.3.1 The pseudo-socket table

`socket()` must return an fd before Motor can create anything. The port keeps a
small table (128 slots, futex-locked) of **pseudo-sockets** in the sysdep layer;
pseudo-fds live at `PSEUDO_FD_BASE = 0x40000000` — far above any real `RtFd`
(VDSO fds are small integers), so the two ranges can't collide.

```
slot = { in_use, family (AF_INET/AF_INET6), type (SOCK_STREAM/SOCK_DGRAM),
         nonblocking, real_fd (-1 until materialized) }
```

Lifecycle mapping:

| BSD sequence | Motor realization |
|---|---|
| `socket()` | allocate a slot; nothing Motor-side |
| `bind(addr)` | `moto_rt_net_bind(proto, addr)` → real fd stored in the slot; apply pending `nonblocking` |
| `connect(addr)` on TCP, unmaterialized | `moto_rt_net_tcp_connect(addr, ∞, nonblocking)` → real fd |
| `connect(addr)` on UDP | auto-bind first if needed (below), then `udp_connect` |
| `listen(backlog)` | requires materialized (bound); **bookkeeping-only for blocking sockets** — Motor's `bind(PROTO_TCP)` already yields an accept()able listener, and the VDSO's `listen()` (which arms the async-accept machinery) *requires* nonblocking mode (`rt_tcp.rs:250`); call `net_listen` only for nonblocking listeners |
| first `sendto`/`recvfrom` on unbound UDP | **auto-bind** to `0.0.0.0:0` / `[::]:0` (POSIX auto-bind semantics) |
| `accept()` | on the real fd; returns a **real** fd directly (no slot needed — it is fully materialized) |
| `close()` | close the real fd if materialized; free the slot |

Every sysdep that receives an fd resolves it first: `fd < PSEUDO_FD_BASE` → use
as-is (fast path, one compare); else → table lookup. Three existing sysdeps in
`sysdeps.cpp` get the hook: **`Read`, `Write`, `Close`** (`Seek` on a socket
correctly fails in the VDSO already; `Isatty` on a pseudo-fd returns `ENOTTY`
via `is_terminal` = 0 on a bogus fd — acceptable). `Close` additionally frees
the slot.

Unmaterialized-socket corner cases: `read`/`write`/`getpeername` → `ENOTCONN`
(TCP) or auto-bind + proceed (UDP); `getsockname` → all-zero address of the
right family (POSIX-blessed); `listen` before `bind` → `EDESTADDRREQ`-ish
(`EINVAL`); TCP `bind` **then** `connect` → `EOPNOTSUPP` (Motor's
`tcp_connect` creates the socket; binding a client to a fixed source port is
not expressible — documented gap).

### G.3.2 Address translation

Two helpers in the sysdeps (`lx_to_moto_addr`, `moto_to_lx_addr`) translating
Linux-ABI `sockaddr_in`/`sockaddr_in6` ↔ `moto_sockaddr_t`, field-wise; ports
stay big-endian byte-for-byte. `moto_to_lx_addr` honors the caller's buffer
length (`socklen_t`), truncating per POSIX and reporting the full length.
Reject families other than `AF_INET`/`AF_INET6` with `EAFNOSUPPORT`.

### G.3.3 Socket options

Translate by (layer, name), compiled against the Linux headers (values resolve
from `abi-bits`):

| Linux option | Action |
|---|---|
| `SOL_SOCKET/SO_REUSEADDR` | **no-op success** — Motor has no TIME_WAIT rebinding concept exposed; failing would break every server ever written |
| `SOL_SOCKET/SO_KEEPALIVE` | no-op success + one-time log |
| `SOL_SOCKET/SO_BROADCAST` | `set/get_broadcast` |
| `SOL_SOCKET/SO_RCVTIMEO`, `SO_SNDTIMEO` | `struct timeval` ↔ `set/get read/write timeout` (nanos; `u64::MAX` = none) |
| `SOL_SOCKET/SO_ERROR` (get) | `take_error` → 0 or the moto error mapped via `moto_to_errno` |
| `IPPROTO_TCP/TCP_NODELAY` | `set/get_nodelay` |
| `IPPROTO_IP/IP_TTL` | `set/get_ttl` |
| anything else | one-time log + `ENOPROTOOPT` |

On unmaterialized pseudo-sockets, only the no-op options succeed; the rest
return `ENOTSOCK`-adjacent `EINVAL` (a "set options after socket(), before
bind()" pattern that matters — `SO_REUSEADDR` — is covered by the no-op).

### G.3.4 Flags policy

- `SOCK_NONBLOCK` at `socket()`/`accept4()` → tracked in the slot / applied via
  `set_nonblocking`. `SOCK_CLOEXEC` → no-op (no `exec` on Motor).
- `MSG_PEEK` → `net_peek` (TCP) / `udp_peek_from` (UDP).
- `MSG_NOSIGNAL` → no-op (no signals; `EPIPE` comes back as an error return
  anyway, which is exactly what callers of `MSG_NOSIGNAL` want).
- `MSG_DONTWAIT` and anything else → one-time log + `EINVAL` (revisit at M7 if a
  real program needs it — it would mean flipping nonblocking around one call).

### G.3.5 Minimal `Fcntl`

`fcntl()` is how programs toggle `O_NONBLOCK` after creation; a minimal sysdep
covers the 90% case: `F_GETFD` → 0, `F_SETFD` → success (no exec ⇒ `FD_CLOEXEC`
is meaningless), `F_GETFL` → `O_RDWR | (nonblocking ? O_NONBLOCK : 0)` (state
from the slot for pseudo-fds; plain `O_RDWR` for others), `F_SETFL` → for
sockets, diff against current and call `set_nonblocking`; other flag changes
ignored with a log. Everything else (`F_DUPFD`, locks) → `ENOSYS`. Note
`fcntl(F_GETFD/F_SETFD)` is also called by `fdopendir` — the no-ops make those
calls succeed (fdopendir remains blocked on `fstat`-of-dirfd, E.5).

## G.4 Shim v5 (motor-os repo)

New: the `netc` mirror types and ~21 thin wrappers over `moto_rt::net`. In
`moto_rt.h`:

```c
/* net (moto-rt/src/netc.rs — NOT the Linux sockaddr ABI: family is u8,
 * MOTO_AF_INET = 0, MOTO_AF_INET6 = 1, and the v6 field order differs). */
#define MOTO_AF_INET  0
#define MOTO_AF_INET6 1
#define MOTO_PROTO_TCP 1
#define MOTO_PROTO_UDP 2
#define MOTO_SHUTDOWN_READ  1u
#define MOTO_SHUTDOWN_WRITE 2u

typedef struct {
	uint8_t  family; /* MOTO_AF_INET */
	uint16_t port;   /* big-endian */
	uint32_t addr;   /* big-endian (network order), as in Linux */
} moto_sockaddr_in_t;

typedef struct {
	uint8_t  family; /* MOTO_AF_INET6 */
	uint16_t port;   /* big-endian */
	uint8_t  addr[16];
	uint32_t flowinfo;
	uint32_t scope_id;
} moto_sockaddr_in6_t;

typedef union {
	moto_sockaddr_in_t  v4;
	moto_sockaddr_in6_t v6;
} moto_sockaddr_t;

/* creation / lifecycle (fd or -err unless noted) */
int64_t moto_rt_net_bind(uint8_t proto, const moto_sockaddr_t *addr);
int32_t moto_rt_net_listen(int32_t fd, uint32_t backlog);
int64_t moto_rt_net_accept(int32_t fd, moto_sockaddr_t *peer);
int64_t moto_rt_net_tcp_connect(const moto_sockaddr_t *addr,
                                uint64_t timeout_nanos /* MAX = none */,
                                int32_t nonblocking);
int32_t moto_rt_net_udp_connect(int32_t fd, const moto_sockaddr_t *addr);
int32_t moto_rt_net_socket_addr(int32_t fd, moto_sockaddr_t *out);
int32_t moto_rt_net_peer_addr(int32_t fd, moto_sockaddr_t *out);
int32_t moto_rt_net_shutdown(int32_t fd, uint8_t how); /* MOTO_SHUTDOWN_*, or'able */

/* I/O beyond plain read/write */
int64_t moto_rt_net_peek(int32_t fd, uint8_t *buf, size_t n);
int64_t moto_rt_net_udp_recv_from(int32_t fd, uint8_t *buf, size_t n,
                                  moto_sockaddr_t *from);
int64_t moto_rt_net_udp_peek_from(int32_t fd, uint8_t *buf, size_t n,
                                  moto_sockaddr_t *from);
int64_t moto_rt_net_udp_send_to(int32_t fd, const uint8_t *buf, size_t n,
                                const moto_sockaddr_t *to);

/* options (getters return the value or -err; timeouts: MAX = none) */
int32_t moto_rt_net_set_nonblocking(int32_t fd, int32_t nonblocking);
int32_t moto_rt_net_set_nodelay(int32_t fd, int32_t v);
int32_t moto_rt_net_nodelay(int32_t fd);
int32_t moto_rt_net_set_ttl(int32_t fd, uint32_t ttl);
int64_t moto_rt_net_ttl(int32_t fd);
int32_t moto_rt_net_set_broadcast(int32_t fd, int32_t v);
int32_t moto_rt_net_broadcast(int32_t fd);
int32_t moto_rt_net_set_read_timeout(int32_t fd, uint64_t nanos);
int32_t moto_rt_net_set_write_timeout(int32_t fd, uint64_t nanos);
int64_t moto_rt_net_read_timeout(int32_t fd);  /* nanos; MAX = none */
int64_t moto_rt_net_write_timeout(int32_t fd); /* nanos; MAX = none */
int32_t moto_rt_net_take_error(int32_t fd);    /* 0 = none; -err */
```

Rust side (`lib.rs`), all mechanical; the pattern (with the layout asserts once):

```rust
const _: () = assert!(core::mem::size_of::<moto_rt::netc::sockaddr>() == 28);
const _: () = assert!(core::mem::size_of::<moto_rt::netc::sockaddr_in>() == 8);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_bind(
    proto: u8,
    addr: *const moto_rt::netc::sockaddr,
) -> i64 {
    match moto_rt::net::bind(proto, unsafe { &*addr }) {
        Ok(fd) => fd as i64,
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_accept(fd: i32, peer: *mut moto_rt::netc::sockaddr) -> i64 {
    match moto_rt::net::accept(fd) {
        Ok((fd2, addr)) => {
            unsafe { *peer = addr };
            fd2 as i64
        }
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_tcp_connect(
    addr: *const moto_rt::netc::sockaddr,
    timeout_nanos: u64,
    nonblocking: i32,
) -> i64 {
    let timeout = if timeout_nanos == u64::MAX {
        core::time::Duration::MAX
    } else {
        core::time::Duration::from_nanos(timeout_nanos)
    };
    match moto_rt::net::tcp_connect(unsafe { &*addr }, timeout, nonblocking != 0) {
        Ok(fd) => fd as i64,
        Err(e) => err64(e),
    }
}

// ... udp_connect, listen, socket_addr, peer_addr, shutdown, peek,
// udp_recv_from/peek_from/send_to, and the option wrappers follow the same
// mold: Result<()> -> 0/-err (i32), Result<T> -> T/-err (i64),
// Option<Duration> <-> u64 with MAX = none, bool <-> 0/1.
```

Rebuild + restage per B.5; `nm` must show the 21 `moto_rt_net_*` exports.

## G.5 sysdeps: `sysdeps/motor/generic/socket.cpp` (new file)

Structure (full code at implementation time; the load-bearing parts):

```cpp
// Pseudo-socket table: BSD socket() lifecycle over Motor's create-bound API.
// Design: docs/porting-libc-appendix-g.md (G.3).

constexpr int PSEUDO_FD_BASE = 0x40000000;
constexpr int MAX_PSEUDO_SOCKETS = 128;

struct PseudoSocket {
	bool in_use;
	int family;      // AF_INET / AF_INET6 (Linux values)
	int type;        // SOCK_STREAM / SOCK_DGRAM
	bool nonblocking;
	int real_fd;     // -1 until materialized
};
PseudoSocket table[MAX_PSEUDO_SOCKETS]; // + FutexLock table_lock
```

Exposed to `sysdeps.cpp` via `sysdeps/motor/include/mlibc/motor-socket.hpp`:

```cpp
// Resolve an application fd: pseudo-socket fds map to their materialized
// real fd; everything else passes through. Returns -errno on dead pseudo-fds.
int motor_sock_realfd(int fd);
// close() hook: frees the slot (and closes the real fd); returns -1 if fd is
// not a pseudo-socket (caller closes normally), else 0/errno.
int motor_sock_close(int fd);
```

…and `sysdeps.cpp`'s `Read`/`Write`/`Close` gain three-line hooks
(`if (fd >= PSEUDO_FD_BASE) { … }`).

The sysdeps themselves, following G.3:

- `Socket(family, type, protocol, *fd)` — validate `AF_INET`/`AF_INET6` (else
  `EAFNOSUPPORT`) and `SOCK_STREAM`/`SOCK_DGRAM` (else `EPROTONOSUPPORT`),
  extract `SOCK_NONBLOCK`/`SOCK_CLOEXEC` from `type`, allocate a slot.
- `Bind(fd, addr, len)` — translate address; `moto_rt_net_bind(proto, …)`;
  store `real_fd`; apply `nonblocking`.
- `Connect(fd, addr, len)` — TCP unmaterialized → `moto_rt_net_tcp_connect`
  (timeout ∞, slot's nonblocking); TCP already bound → `EOPNOTSUPP`; UDP →
  auto-bind if needed, then `moto_rt_net_udp_connect`.
- `Listen(fd, backlog)` — must be materialized (else `EINVAL`); backlog < 0 → 0.
- `Accept(fd, *newfd, addr, *len, flags)` — `moto_rt_net_accept`; translate
  the peer address out if requested; `SOCK_NONBLOCK` → `set_nonblocking` on the
  new fd; the returned fd is real (no slot).
- `Sendto`/`Recvfrom` — resolve fd (auto-bind unbound UDP); with a destination
  address → `udp_send_to`; without → plain `moto_rt_write`/`moto_rt_read` (works
  for TCP and connected UDP alike, both are `PosixFile`s); `MSG_PEEK` →
  `net_peek`/`udp_peek_from`; flag policy per G.3.4. Fill `src_addr` from
  `udp_recv_from`'s out-param, translated.
- `Shutdown(fd, how)` — `SHUT_RD/WR/RDWR` (0/1/2) → moto bits (1/2/3).
- `Sockname`/`Peername` — `socket_addr`/`peer_addr` + translate-out with the
  caller's length honored; unmaterialized: zero-address / `ENOTCONN`.
- `SetSockopt`/`GetSockopt` — the G.3.3 table.
- `Fcntl` — G.3.5.

Register in `sysdeps/motor/include/mlibc/sysdeps.hpp` (append):
`Socket, Bind, Connect, Listen, Accept, Sendto, Recvfrom, Shutdown, Sockname,
Peername, SetSockopt, GetSockopt, Fcntl` — and add `'generic/socket.cpp'` to
`libc_sources` in `sysdeps/motor/meson.build`.

Rebuild + reinstall: `ninja -C build && DESTDIR=$SYSROOT ninja -C build install`.

## G.6 Deliberate gaps (document, defer)

- **`poll`/`select`** — Motor has an epoll-shaped API (`moto-rt/src/poll.rs`);
  POSIX `poll()` over it (create-instance-per-call, or a cached instance) is an
  M7 item — the first real program will tell us which shape it needs. The
  pseudo-fd translation must be wired into it then.
- **TCP `bind()` + `connect()`** (fixed client source port) — not expressible
  over `tcp_connect`; `EOPNOTSUPP`. Motor-side wishlist if anything needs it.
- **`SO_REUSEADDR`/`SO_KEEPALIVE`** — accepted and ignored.
- **`MsgSend`/`MsgRecv`** (`sendmsg`/`recvmsg`: iovecs, ancillary data/SCM
  rights) — no fd-passing on Motor anyway; `ENOSYS`.
- **`socketpair`, `AF_UNIX`** — no Unix-domain sockets on Motor; `ENOSYS` /
  `EAFNOSUPPORT`. (Affects some build tools at M9 — worth remembering.)
- **DNS** — `getaddrinfo` for names needs `/etc/resolv.conf` (+ reachable
  nameserver) or `/etc/hosts` on the image; both are configuration, not code.
  Motor's native `dns_lookup` is unused by mlibc (no hook) — a future local
  patch could short-circuit `lookup_name_dns` through it.
- **`MSG_DONTWAIT`** — `EINVAL` + log for now.
- **Pseudo-fd visibility** — a pseudo-socket fd handed to sysdeps that don't
  know about the table (e.g. `Isatty`, `Stat`-by-fd) misbehaves gracefully
  (`ENOTTY`/`EBADF`) but not always POSIX-perfectly (`fstat` on a socket should
  return `S_IFSOCK`). Revisit if a program cares.

## G.7 The M6 test program

`$MOTOR/src/tests/libc/m6.c` — self-contained over loopback, using M5's
pthreads for the TCP server. Fixed ports in the 34700s. Outline (full listing at
implementation time):

1. **getaddrinfo/inet round-trip**: `inet_pton`/`inet_ntop` for v4;
   `getaddrinfo("127.0.0.1", "34701", AI_NUMERICHOST)` → one `AF_INET` result
   with the right port; `freeaddrinfo`.
2. **UDP pair**: two sockets bound to `127.0.0.1:34701/34702`; `sendto` both
   ways; `recvfrom` verifies payload **and source address**; `getsockname`
   reports the bound port.
3. **Connected UDP**: `connect()` the first socket to the second; bare
   `send`/`recv`; `getpeername` checks.
4. **UDP `MSG_PEEK`**: peek returns the datagram, then `recvfrom` returns the
   same one.
5. **`SO_RCVTIMEO`**: 100 ms on a silent UDP socket → `recvfrom` fails with
   `EAGAIN`/`EWOULDBLOCK` after ≥ 90 ms (monotonic clock check — guards against
   premature timeouts).
6. **Nonblocking**: `socket(SOCK_DGRAM | SOCK_NONBLOCK)` → immediate
   `EAGAIN` on `recvfrom`; `fcntl(F_SETFL, O_NONBLOCK)` on a blocking socket →
   same; `F_GETFL` reflects it.
7. **TCP end-to-end**: server thread — `socket`/`SO_REUSEADDR`/`bind(:34703)`/
   `listen`/`accept`, then echo until EOF, then `close`; client — `connect`,
   `getpeername` = `127.0.0.1:34703`, `TCP_NODELAY` set + get-back, send 64 KiB
   in chunks / verify the echo, `shutdown(SHUT_WR)`, drain to EOF (`recv` → 0),
   `close`, `pthread_join`. Accept's peer address sanity-checked on the server
   side.
8. **Error paths**: `connect` to a closed port → `ECONNREFUSED` (record what
   Motor actually returns — smoltcp may say something else; the check accepts
   "fails with a sane errno" and prints it); `recv` on an unconnected TCP
   pseudo-socket → `ENOTCONN`; `socket(AF_UNIX, …)` → `EAFNOSUPPORT`.

Expected output: eight `M6: ... ok` lines + `M6: all tests passed`, exit 0.

Build/audit/stage identical to D.5/E.6 (`m6`); the audit gate is unchanged
(no PT_TLS, RELATIVE-only).

## G.8 Run on Motor OS + exit criteria

`make img`, boot, `m6` (several runs — the TCP test is scheduling-sensitive).

- [ ] Shim v5 staged; 21 `moto_rt_net_*` exports present; sockaddr size asserts
      compile on both sides.
- [ ] mlibc rebuilt with `socket.cpp` + 13 tags; `m5` still passes (threads
      regression — relink first).
- [ ] `m6` audit clean; full pass on Motor, repeated. Record the actual errno
      for connect-to-closed-port here: ____.
- [ ] Kernel/sys-io log reviewed during `m6` — smoltcp warnings are the thing
      to watch for.

Known M6 pitfalls, pre-answered:

- **sys-io panics in `TcpListener::drop` (tcp_listener.rs:49) after the client
  exits** (hit at first full M6 run) → sys-io bug, fixed 2026-07-03:
  `drop_from_client` (the fd-close path) drained the listener's socket sets and
  dropped its listening sockets, but left the listener **registered** — and each
  dropped listening socket's replenish task ("respawn when leaving the Listen
  state", `socket/tcp.rs`) then resurrected a replacement into the still-alive
  listener. Result: a zombie listener that kept accepting SYNs after `close()`,
  and non-empty sets when it was finally dropped at process exit → the Drop
  assert. Fix mirrors `on_connection_done`'s documented ordering ("first remove
  listeners, otherwise dropped listening sockets will spawn new ones"):
  unregister from both maps and drop the local `Rc` (killing the weak upgrades)
  *before* dropping the child sockets.
- **`listen()` fails with `EINVAL` on a blocking socket** (hit at first M6 TCP
  run) → the VDSO's `TcpListener::listen()` returns `InvalidArgument` unless the
  listener is nonblocking — it exists to arm the mio/poll-style async-accept
  path; blocking accept posts its requests on demand and never needs it (Rust
  std never calls it on the blocking path either). Fix: the `Listen` sysdep is
  bookkeeping-only for blocking sockets (G.3.1).
- **`recvfrom` with `SO_RCVTIMEO` blocks forever** (hit at first M6 run: m6 hung
  right after "udp ok") → VDSO bug, fixed 2026-07-03: `rt_udp.rs`'s
  `recv_or_peek_from` computed its deadline from **`tx_timeout_ns`** (the send
  timeout) instead of `rx_timeout_ns` — a copy-paste from the send path, so the
  read timeout was never honored (Rust std's `UdpSocket::set_read_timeout` was
  silently broken too; the TCP paths were correct). One-word fix at
  `rt_udp.rs:145`; m6's "no premature timeout" + "must fire" checks are the
  regression test.
- **Address family confusion** — Linux `AF_INET`=2 vs Motor 0: if every
  connect/bind fails with `EINVAL`-ish errors or the VDSO panics on
  `sin_family`, a translation was missed (the moto `netc` union `From` impl
  `panic!()`s on unknown families — `rt.vdso` side).
- **`recvfrom` returns the wrong source port** — ports are big-endian in both
  ABIs; do **not** byte-swap when translating, copy as-is.
- **TCP echo hangs at the end** — `shutdown(SHUT_WR)` mapping: Linux `SHUT_WR`
  is **1**, Motor `SHUTDOWN_WRITE` is **2**; an identity mapping deadlocks both
  sides waiting for EOF.
- **`EAGAIN` storms in blocking mode** — `NotReady` (3) maps to `EAGAIN`; if a
  *blocking* socket op returns it, the slot's `nonblocking` was applied to the
  wrong fd (or inherited across `accept` unexpectedly).
- **`SO_RCVTIMEO` seems ignored** — the timeval→nanos conversion: `tv_usec` is
  micro, not nano; and `{0,0}` means "no timeout" (map to `u64::MAX`), not
  "instant timeout".
- **Everything works except under parallel load** — the pseudo-socket table
  lock ordering vs. mlibc's own locks; keep table critical sections tiny (no
  Motor calls under the lock).
