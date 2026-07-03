/* moto_rt.h — C ABI over the Motor OS RT.VDSO (via the moto-rt-cabi staticlib).
 *
 * Error convention: negative return = -(moto error code); these are MOTOR codes
 * (moto-rt/src/error.rs), not POSIX errno. Non-negative = success value.
 *
 * This header is the C half of the moto-rt-cabi crate's ABI; keep the two in
 * sync. See docs/porting-libc-appendix-b.md for the design.
 */
#ifndef MOTO_RT_H
#define MOTO_RT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MOTO_RT_VERSION 16u

/* Motor error codes (subset; see moto-rt/src/error.rs). */
#define MOTO_E_OK               0
#define MOTO_E_NOT_READY        3
#define MOTO_E_NOT_IMPLEMENTED  4
#define MOTO_E_INVALID_ARGUMENT 7
#define MOTO_E_OUT_OF_MEMORY    8
#define MOTO_E_NOT_ALLOWED      9
#define MOTO_E_NOT_FOUND        10
#define MOTO_E_TIMED_OUT        12
#define MOTO_E_ALREADY_IN_USE   13
#define MOTO_E_BAD_HANDLE       17

/* open() flags (moto-rt/src/fs.rs). */
#define MOTO_O_READ       (1u << 0)
#define MOTO_O_WRITE      (1u << 1)
#define MOTO_O_APPEND     (1u << 2)
#define MOTO_O_TRUNCATE   (1u << 3)
#define MOTO_O_CREATE     (1u << 4)
#define MOTO_O_CREATE_NEW (1u << 5)
#define MOTO_O_NONBLOCK   (1u << 6)

/* seek() whence (moto-rt/src/fs.rs). */
#define MOTO_SEEK_SET 0
#define MOTO_SEEK_CUR 1
#define MOTO_SEEK_END 2

/* stdio fds. */
#define MOTO_FD_STDIN  0
#define MOTO_FD_STDOUT 1
#define MOTO_FD_STDERR 2

/* file types / permissions (moto-rt/src/fs.rs) */
#define MOTO_FILETYPE_FILE      1
#define MOTO_FILETYPE_DIRECTORY 2
#define MOTO_PERM_READ  1u
#define MOTO_PERM_WRITE 2u
#define MOTO_MAX_FILENAME_LEN 256

/* Mirrors moto_rt::fs::FileAttr, #[repr(C, align(16))] — keep the alignment
 * attribute: the VDSO writes these structs with alignment-assuming code.
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

/* init / process / misc */
void     moto_rt_start(void);              /* MUST be the first call */
uint64_t moto_rt_version(void);            /* == MOTO_RT_VERSION      */
_Noreturn void moto_rt_proc_exit(int32_t code);
void     moto_rt_log(const uint8_t *msg, size_t len);
void     moto_rt_fill_random_bytes(uint8_t *buf, size_t len);
size_t   moto_rt_num_cpus(void);
uint64_t moto_rt_tid(void);

/* argv/env, NULL-terminated; single VDSO-heap allocation, never free */
char   **moto_rt_get_args(int32_t *argc);
char   **moto_rt_get_env(void);          /* "KEY=VALUE" strings */

/* VDSO heap (paired: never mix with another allocator's free) */
void *moto_rt_alloc(size_t size, size_t align);
void *moto_rt_alloc_zeroed(size_t size, size_t align);
void *moto_rt_realloc(void *p, size_t size, size_t align, size_t new_size);
void  moto_rt_dealloc(void *p, size_t size, size_t align);

/* raw anonymous pages (for the libc allocator) */
int64_t moto_rt_vm_map(size_t num_bytes);  /* addr or -err */
int32_t moto_rt_vm_unmap(uint64_t addr);

/* fs */
int64_t moto_rt_open(const uint8_t *path, size_t path_len, uint32_t opts);
int64_t moto_rt_read(int32_t fd, uint8_t *buf, size_t n);
int64_t moto_rt_write(int32_t fd, const uint8_t *buf, size_t n);
int64_t moto_rt_seek(int32_t fd, int64_t offset, uint8_t whence);
int32_t moto_rt_close(int32_t fd);
int32_t moto_rt_mkdir(const uint8_t *path, size_t path_len);
int32_t moto_rt_unlink(const uint8_t *path, size_t path_len);
int32_t moto_rt_rmdir(const uint8_t *path, size_t path_len);
int32_t moto_rt_rename(const uint8_t *old_path, size_t old_len,
                       const uint8_t *new_path, size_t new_len);
int32_t moto_rt_is_terminal(int32_t fd); /* 1 = tty, 0 = not (or bad fd) */

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

/* net I/O beyond plain read/write */
int64_t moto_rt_net_peek(int32_t fd, uint8_t *buf, size_t n);
int64_t moto_rt_net_udp_recv_from(int32_t fd, uint8_t *buf, size_t n,
                                  moto_sockaddr_t *from);
int64_t moto_rt_net_udp_peek_from(int32_t fd, uint8_t *buf, size_t n,
                                  moto_sockaddr_t *from);
int64_t moto_rt_net_udp_send_to(int32_t fd, const uint8_t *buf, size_t n,
                                const moto_sockaddr_t *to);

/* net options (getters return the value or -err; timeouts: MAX = none) */
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

/* time */
uint64_t moto_rt_mono_nanos(void);         /* monotonic, since boot   */
uint64_t moto_rt_real_nanos(void);         /* wall clock, UNIX epoch  */
void     moto_rt_sleep_nanos(uint64_t nanos);

/* poll: the VDSO readiness registry (mio/epoll-shaped).
 * A registry is an ordinary fd: close it with moto_rt_close().
 * Delivery is edge-ish: sources synthesize current readiness at add-time and
 * push transitions afterwards; wait() drains accumulated (token, events).
 * Not every fd kind is pollable: poll_add on e.g. a regular file returns
 * MOTO_E_INVALID_ARGUMENT (callers treat that as "always ready"). */
#define MOTO_POLL_READABLE     1ull
#define MOTO_POLL_WRITABLE     2ull
#define MOTO_POLL_READ_CLOSED  4ull
#define MOTO_POLL_WRITE_CLOSED 8ull
#define MOTO_POLL_ERROR        16ull

typedef struct { /* mirrors moto_rt::poll::Event */
    uint64_t token;
    uint64_t events;
} moto_poll_event_t;

int32_t moto_rt_poll_new(void); /* registry fd; -err */
int32_t moto_rt_poll_add(int32_t poll_fd, int32_t source_fd, uint64_t token,
                         uint64_t interests); /* 0 or -err */
int32_t moto_rt_poll_set(int32_t poll_fd, int32_t source_fd, uint64_t token,
                         uint64_t interests);   /* 0 or -err */
int32_t moto_rt_poll_del(int32_t poll_fd, int32_t source_fd); /* 0 or -err */
int32_t moto_rt_poll_wake(int32_t poll_fd);                   /* 0 or -err */
/* timeout is RELATIVE nanos; UINT64_MAX = infinite; 0 = harvest only.
 * Returns the number of events written (0 = timeout), or -err. */
int32_t moto_rt_poll_wait(int32_t poll_fd, uint64_t timeout_nanos,
                          moto_poll_event_t *events, uintptr_t events_cap);

/* process identity */
int64_t moto_rt_getpid(void);

/* futex (u64 max timeout = infinite); 1 = woken, 0 = timed out */
int32_t moto_rt_futex_wait(const uint32_t *addr, uint32_t expected,
                           uint64_t timeout_nanos);
int32_t moto_rt_futex_wake(const uint32_t *addr);
void    moto_rt_futex_wake_all(const uint32_t *addr);

/* key-based TLS (VDSO); dtors run at thread exit */
size_t moto_rt_tls_create(void (*dtor)(void *));
void   moto_rt_tls_set(size_t key, void *value);
void  *moto_rt_tls_get(size_t key);
void   moto_rt_tls_destroy(size_t key);

/* the libc TCB slot (UTCB.libc_tcb, fs:0x58; needs kernel_version >= 2) */
void  moto_rt_tcb_set(void *tcb);
void *moto_rt_tcb_get(void);

/* threads */
int64_t moto_rt_thread_spawn(void (*thread_fn)(uint64_t), size_t stack_size,
                             uint64_t arg);            /* handle or -err */
int32_t moto_rt_thread_join(uint64_t handle);
void    moto_rt_thread_yield(void);

/* provided for the compiler, not for direct use:
 *   void *__emutls_get_address(void *control);
 *   int __cxa_thread_atexit(void (*dtor)(void *), void *obj, void *dso); */

#ifdef __cplusplus
}
#endif
#endif /* MOTO_RT_H */
