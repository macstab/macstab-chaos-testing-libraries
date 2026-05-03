/**
 * @file bench_io.c
 * @brief Stage 3 microbenchmarks for libchaos-io.
 *
 * @details
 * Three benchmarks exercise the libchaos-io hot paths:
 *
 *  1. `pread_passthrough` — `pread(fd, buf, 64, 0)` against an open
 *     tmpfile, with no rule installed.  Without LD_PRELOAD this is
 *     pure libc / kernel cost; with LD_PRELOAD this measures the chaos
 *     library's TLS guard + snapshot pointer load + rule scan + early
 *     return overhead.
 *  2. `pread_match_no_fire` — same call, with a probability=0 rule
 *     loaded so the selector match runs but the dice never trigger.
 *  3. `pread_errno` — same call, probability=1 ERRNO rule, exercising
 *     the full effect-dispatch path.
 *
 * Setup creates an anonymous tmpfile via `mkstemp`, fills the first 4 KiB
 * with deterministic bytes, and unlinks the path so the file disappears
 * on teardown.  Iter does one `pread` of 64 bytes from offset 0; the
 * choice of offset 0 means each call hits the page-cached first block,
 * so we measure the path-resolution + chaos overhead, not the
 * device.
 */

#include "chaos_bench.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/sendfile.h>
#endif

#define BENCH_IO_PAYLOAD_BYTES 64
#define BENCH_IO_FILE_BYTES    4096

/**
 * @brief Per-benchmark state: open tmpfile + result buffer.
 *
 * @details The buffer is 64 bytes — enough to be representative but
 * small enough to fit in one cache line plus a bit, so the iter cost
 * is dominated by the syscall+chaos path, not the memcpy.
 */
typedef struct bench_io_state
{
    int     fd;
    char    buffer[BENCH_IO_PAYLOAD_BYTES];
    ssize_t rc;
} bench_io_state_t;

static void bench_io_setup(void *user_state)
{
    bench_io_state_t *s = (bench_io_state_t *)user_state;
    char path[] = "/tmp/chaos-bench-io.XXXXXX";
    char fill[BENCH_IO_FILE_BYTES];
    ssize_t written;

    s->fd = mkstemp(path);
    if (s->fd < 0)
    {
        perror("bench_io: mkstemp");
        abort();
    }
    /* Unlink immediately; the fd keeps the file alive. */
    (void)unlink(path);

    memset(fill, 0xA5, sizeof(fill));
    written = write(s->fd, fill, sizeof(fill));
    if (written != (ssize_t)sizeof(fill))
    {
        perror("bench_io: write");
        abort();
    }
}

static void bench_io_iter_pread(void *user_state)
{
    bench_io_state_t *s = (bench_io_state_t *)user_state;
    s->rc = pread(s->fd, s->buffer, sizeof(s->buffer), 0);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->buffer);
}

static void bench_io_teardown(void *user_state)
{
    bench_io_state_t *s = (bench_io_state_t *)user_state;
    if (s->fd >= 0)
    {
        (void)close(s->fd);
    }
}

CHAOS_BENCH("io", pread_passthrough,    bench_io_state_t,
            bench_io_setup, bench_io_iter_pread, bench_io_teardown)
CHAOS_BENCH("io", pread_match_no_fire,  bench_io_state_t,
            bench_io_setup, bench_io_iter_pread, bench_io_teardown)
CHAOS_BENCH("io", pread_errno,          bench_io_state_t,
            bench_io_setup, bench_io_iter_pread, bench_io_teardown)

/* ------------------------------------------------------------------ read ---
 * `read(/dev/zero)` — never blocks, never advances a meaningful position,
 * isolates the chaos hook from any filesystem variability.
 */
typedef struct bench_io_dev_state
{
    int     fd;
    char    buffer[BENCH_IO_PAYLOAD_BYTES];
    ssize_t rc;
} bench_io_dev_state_t;

static void bench_io_devzero_setup(void *user_state)
{
    bench_io_dev_state_t *s = (bench_io_dev_state_t *)user_state;
    s->fd = open("/dev/zero", O_RDONLY);
    if (s->fd < 0) { perror("bench_io: open /dev/zero"); abort(); }
}

static void bench_io_devnull_setup(void *user_state)
{
    bench_io_dev_state_t *s = (bench_io_dev_state_t *)user_state;
    s->fd = open("/dev/null", O_WRONLY);
    if (s->fd < 0) { perror("bench_io: open /dev/null"); abort(); }
    memset(s->buffer, 0xC3, sizeof(s->buffer));
}

static void bench_io_dev_teardown(void *user_state)
{
    bench_io_dev_state_t *s = (bench_io_dev_state_t *)user_state;
    if (s->fd >= 0) (void)close(s->fd);
}

static void bench_io_iter_read(void *user_state)
{
    bench_io_dev_state_t *s = (bench_io_dev_state_t *)user_state;
    s->rc = read(s->fd, s->buffer, sizeof(s->buffer));
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->buffer);
}

static void bench_io_iter_write(void *user_state)
{
    bench_io_dev_state_t *s = (bench_io_dev_state_t *)user_state;
    s->rc = write(s->fd, s->buffer, sizeof(s->buffer));
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
}

CHAOS_BENCH("io", read_passthrough,    bench_io_dev_state_t,
            bench_io_devzero_setup, bench_io_iter_read, bench_io_dev_teardown)
CHAOS_BENCH("io", read_match_no_fire,  bench_io_dev_state_t,
            bench_io_devzero_setup, bench_io_iter_read, bench_io_dev_teardown)
CHAOS_BENCH("io", read_errno,          bench_io_dev_state_t,
            bench_io_devzero_setup, bench_io_iter_read, bench_io_dev_teardown)

CHAOS_BENCH("io", write_passthrough,    bench_io_dev_state_t,
            bench_io_devnull_setup, bench_io_iter_write, bench_io_dev_teardown)
CHAOS_BENCH("io", write_match_no_fire,  bench_io_dev_state_t,
            bench_io_devnull_setup, bench_io_iter_write, bench_io_dev_teardown)
CHAOS_BENCH("io", write_errno,          bench_io_dev_state_t,
            bench_io_devnull_setup, bench_io_iter_write, bench_io_dev_teardown)

/* ----------------------------------------------------------- readv/writev ---
 */
typedef struct bench_io_iov_state
{
    int          fd;
    char         buf_a[32];
    char         buf_b[32];
    struct iovec iov[2];
    ssize_t      rc;
} bench_io_iov_state_t;

static void bench_io_readv_setup(void *user_state)
{
    bench_io_iov_state_t *s = (bench_io_iov_state_t *)user_state;
    s->fd = open("/dev/zero", O_RDONLY);
    if (s->fd < 0) { perror("bench_io: open /dev/zero"); abort(); }
    s->iov[0].iov_base = s->buf_a; s->iov[0].iov_len = sizeof(s->buf_a);
    s->iov[1].iov_base = s->buf_b; s->iov[1].iov_len = sizeof(s->buf_b);
}

static void bench_io_writev_setup(void *user_state)
{
    bench_io_iov_state_t *s = (bench_io_iov_state_t *)user_state;
    s->fd = open("/dev/null", O_WRONLY);
    if (s->fd < 0) { perror("bench_io: open /dev/null"); abort(); }
    memset(s->buf_a, 0xA1, sizeof(s->buf_a));
    memset(s->buf_b, 0xB2, sizeof(s->buf_b));
    s->iov[0].iov_base = s->buf_a; s->iov[0].iov_len = sizeof(s->buf_a);
    s->iov[1].iov_base = s->buf_b; s->iov[1].iov_len = sizeof(s->buf_b);
}

static void bench_io_iov_teardown(void *user_state)
{
    bench_io_iov_state_t *s = (bench_io_iov_state_t *)user_state;
    if (s->fd >= 0) (void)close(s->fd);
}

static void bench_io_iter_readv(void *user_state)
{
    bench_io_iov_state_t *s = (bench_io_iov_state_t *)user_state;
    s->rc = readv(s->fd, s->iov, 2);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->buf_a);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->buf_b);
}

static void bench_io_iter_writev(void *user_state)
{
    bench_io_iov_state_t *s = (bench_io_iov_state_t *)user_state;
    s->rc = writev(s->fd, s->iov, 2);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
}

CHAOS_BENCH("io", readv_passthrough,    bench_io_iov_state_t,
            bench_io_readv_setup, bench_io_iter_readv, bench_io_iov_teardown)
CHAOS_BENCH("io", readv_match_no_fire,  bench_io_iov_state_t,
            bench_io_readv_setup, bench_io_iter_readv, bench_io_iov_teardown)
CHAOS_BENCH("io", readv_errno,          bench_io_iov_state_t,
            bench_io_readv_setup, bench_io_iter_readv, bench_io_iov_teardown)

CHAOS_BENCH("io", writev_passthrough,    bench_io_iov_state_t,
            bench_io_writev_setup, bench_io_iter_writev, bench_io_iov_teardown)
CHAOS_BENCH("io", writev_match_no_fire,  bench_io_iov_state_t,
            bench_io_writev_setup, bench_io_iter_writev, bench_io_iov_teardown)
CHAOS_BENCH("io", writev_errno,          bench_io_iov_state_t,
            bench_io_writev_setup, bench_io_iter_writev, bench_io_iov_teardown)

/* -------------------------------------------------------------- open_close ---
 * Per-iter `open(/dev/null)` + immediate `close`.  Pairs the two hooks so
 * the bench measures both, since they're often called as a duo in real
 * code (e.g. probing for file existence via stat→open).
 */
typedef struct bench_io_oc_state
{
    int fd;
} bench_io_oc_state_t;

static void bench_io_iter_open_close(void *user_state)
{
    bench_io_oc_state_t *s = (bench_io_oc_state_t *)user_state;
    s->fd = open("/dev/null", O_RDONLY);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->fd);
    if (s->fd >= 0) (void)close(s->fd);
}

CHAOS_BENCH("io", open_close_passthrough,    bench_io_oc_state_t,
            NULL, bench_io_iter_open_close, NULL)
CHAOS_BENCH("io", open_close_match_no_fire,  bench_io_oc_state_t,
            NULL, bench_io_iter_open_close, NULL)
CHAOS_BENCH("io", open_close_errno,          bench_io_oc_state_t,
            NULL, bench_io_iter_open_close, NULL)

/* ----------------------------------------------------------- openat_close ---
 * Per-iter `openat(AT_FDCWD, "/dev/null", ...)` + close.  Tests the
 * `openat` hook specifically (different libc entry from `open` on glibc).
 */
static void bench_io_iter_openat_close(void *user_state)
{
    bench_io_oc_state_t *s = (bench_io_oc_state_t *)user_state;
    s->fd = openat(AT_FDCWD, "/dev/null", O_RDONLY);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->fd);
    if (s->fd >= 0) (void)close(s->fd);
}

CHAOS_BENCH("io", openat_close_passthrough,    bench_io_oc_state_t,
            NULL, bench_io_iter_openat_close, NULL)
CHAOS_BENCH("io", openat_close_match_no_fire,  bench_io_oc_state_t,
            NULL, bench_io_iter_openat_close, NULL)
CHAOS_BENCH("io", openat_close_errno,          bench_io_oc_state_t,
            NULL, bench_io_iter_openat_close, NULL)

/* ------------------------------------------------------------------ fsync ---
 * `fsync` on a tmpfile that has zero dirty pages → kernel fast path.
 * Measures the chaos-hook overhead, not actual disk sync.
 */
static void bench_io_iter_fsync(void *user_state)
{
    bench_io_state_t *s = (bench_io_state_t *)user_state;
    int rc = fsync(s->fd);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(rc);
}

static void bench_io_iter_fdatasync(void *user_state)
{
    bench_io_state_t *s = (bench_io_state_t *)user_state;
    int rc = fdatasync(s->fd);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(rc);
}

CHAOS_BENCH("io", fsync_passthrough,    bench_io_state_t,
            bench_io_setup, bench_io_iter_fsync, bench_io_teardown)
CHAOS_BENCH("io", fsync_match_no_fire,  bench_io_state_t,
            bench_io_setup, bench_io_iter_fsync, bench_io_teardown)
CHAOS_BENCH("io", fsync_errno,          bench_io_state_t,
            bench_io_setup, bench_io_iter_fsync, bench_io_teardown)

CHAOS_BENCH("io", fdatasync_passthrough,    bench_io_state_t,
            bench_io_setup, bench_io_iter_fdatasync, bench_io_teardown)
CHAOS_BENCH("io", fdatasync_match_no_fire,  bench_io_state_t,
            bench_io_setup, bench_io_iter_fdatasync, bench_io_teardown)
CHAOS_BENCH("io", fdatasync_errno,          bench_io_state_t,
            bench_io_setup, bench_io_iter_fdatasync, bench_io_teardown)

/* -------------------------------------------------------------- ftruncate ---
 * Truncate the same tmpfile to the same size each iter — kernel mostly
 * no-ops, leaving wrapper overhead as the dominant cost.
 */
static void bench_io_iter_ftruncate(void *user_state)
{
    bench_io_state_t *s = (bench_io_state_t *)user_state;
    int rc = ftruncate(s->fd, BENCH_IO_FILE_BYTES);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(rc);
}

CHAOS_BENCH("io", ftruncate_passthrough,    bench_io_state_t,
            bench_io_setup, bench_io_iter_ftruncate, bench_io_teardown)
CHAOS_BENCH("io", ftruncate_match_no_fire,  bench_io_state_t,
            bench_io_setup, bench_io_iter_ftruncate, bench_io_teardown)
CHAOS_BENCH("io", ftruncate_errno,          bench_io_state_t,
            bench_io_setup, bench_io_iter_ftruncate, bench_io_teardown)

/* -------------------------------------------------------------- fallocate ---
 * Linux-only.  Allocate 1 page at offset 0 each iter (idempotent on a
 * file that already covers that range — exercises the hook, not extents).
 */
#ifdef __linux__
static void bench_io_iter_fallocate(void *user_state)
{
    bench_io_state_t *s = (bench_io_state_t *)user_state;
    int rc = fallocate(s->fd, 0, 0, 4096);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(rc);
}

CHAOS_BENCH("io", fallocate_passthrough,    bench_io_state_t,
            bench_io_setup, bench_io_iter_fallocate, bench_io_teardown)
CHAOS_BENCH("io", fallocate_match_no_fire,  bench_io_state_t,
            bench_io_setup, bench_io_iter_fallocate, bench_io_teardown)
CHAOS_BENCH("io", fallocate_errno,          bench_io_state_t,
            bench_io_setup, bench_io_iter_fallocate, bench_io_teardown)
#endif

/* --------------------------------------------------------------- sendfile ---
 * Linux-only.  Two tmpfiles, sendfile from in→out at offset 0 each iter.
 */
#ifdef __linux__
typedef struct bench_io_sendfile_state
{
    int   in_fd;
    int   out_fd;
    off_t offset;
} bench_io_sendfile_state_t;

static void bench_io_sendfile_setup(void *user_state)
{
    bench_io_sendfile_state_t *s = (bench_io_sendfile_state_t *)user_state;
    char in_path[]  = "/tmp/chaos-bench-sf-in.XXXXXX";
    char out_path[] = "/tmp/chaos-bench-sf-out.XXXXXX";
    char fill[BENCH_IO_FILE_BYTES];

    s->in_fd  = mkstemp(in_path);
    s->out_fd = mkstemp(out_path);
    if (s->in_fd < 0 || s->out_fd < 0) { perror("bench_io: mkstemp sendfile"); abort(); }
    (void)unlink(in_path);
    (void)unlink(out_path);
    memset(fill, 0xA5, sizeof(fill));
    if (write(s->in_fd, fill, sizeof(fill)) != (ssize_t)sizeof(fill)) abort();
    s->offset = 0;
}

static void bench_io_iter_sendfile(void *user_state)
{
    bench_io_sendfile_state_t *s = (bench_io_sendfile_state_t *)user_state;
    s->offset = 0;
    ssize_t rc = sendfile(s->out_fd, s->in_fd, &s->offset, 64);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(rc);
}

static void bench_io_sendfile_teardown(void *user_state)
{
    bench_io_sendfile_state_t *s = (bench_io_sendfile_state_t *)user_state;
    if (s->in_fd  >= 0) (void)close(s->in_fd);
    if (s->out_fd >= 0) (void)close(s->out_fd);
}

CHAOS_BENCH("io", sendfile_passthrough,    bench_io_sendfile_state_t,
            bench_io_sendfile_setup, bench_io_iter_sendfile, bench_io_sendfile_teardown)
CHAOS_BENCH("io", sendfile_match_no_fire,  bench_io_sendfile_state_t,
            bench_io_sendfile_setup, bench_io_iter_sendfile, bench_io_sendfile_teardown)
CHAOS_BENCH("io", sendfile_errno,          bench_io_sendfile_state_t,
            bench_io_sendfile_setup, bench_io_iter_sendfile, bench_io_sendfile_teardown)
#endif
