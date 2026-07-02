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

/* time */
uint64_t moto_rt_mono_nanos(void);         /* monotonic, since boot   */
uint64_t moto_rt_real_nanos(void);         /* wall clock, UNIX epoch  */
void     moto_rt_sleep_nanos(uint64_t nanos);

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
