/**
 * @file bench_io.c
 * @brief Per-call overhead of the libchaos-io wrappers for file I/O and sync calls.
 *
 * @details
 * Each hooked call has three registered benchmarks sharing one iteration body:
 * `<fn>_passthrough`, `<fn>_match_no_fire` and `<fn>_errno`. `run-bench.sh` runs each
 * once without LD_PRELOAD (baseline) and once with LD_PRELOAD=libchaos-io.so and the
 * matching `benchmark/scenarios/io-*.conf` copied to the rule file
 * `/tmp/.chaos-io.conf` (treatment); the driver reports the median difference.
 *
 * Targets are chosen so the kernel side is cheap and stable and the wrapper dominates:
 * `/dev/zero` and `/dev/null` (no filesystem, no blocking), or a 4 KiB unlinked temp
 * file in `/tmp` whose single page stays in the page cache.
 *
 * Scenario status at this revision (checked against src/config/chaos_io_config.c):
 *  - Effective: pread, read, write, open_close.
 *  - Never fire, so `_match_no_fire` and `_errno` equal `_passthrough`: openat_close,
 *    readv, writev, ftruncate, fallocate, sendfile (operation token not accepted) and
 *    fsync, fdatasync (path selector `/tmp/chaos-bench-io.*` is a literal prefix, not
 *    a glob). Each scenario file states its defect.
 *
 * The `_errno` arm skips the real call, so its delta is wrapper cost minus the skipped
 * kernel work.
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
 * @brief State of the temp-file kernels (pread, fsync, fdatasync, ftruncate, fallocate).
 *
 * @details `buffer` is 64 bytes, one cache line on amd64 and most arm64 cores, so the
 * copy-out is negligible next to the syscall and wrapper.
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
    /* Unlink at once: the open fd keeps the inode alive and the file vanishes with the
     * process even if teardown never runs. */
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
 * `read(/dev/zero, 64)` and `write(/dev/null, 64)`: character devices with no file
 * position, no page cache and no blocking, so the kernel cost is the bare syscall.
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
 * Two 32-byte iovecs against /dev/zero and /dev/null: same total payload as read and
 * write, so the difference isolates the vectored wrapper path.
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
 * `open("/dev/null")` followed by `close`: both calls are wrapped, so the baseline
 * delta covers two wrappers. The pair keeps the fd table from growing. In the `_errno`
 * arm open fails with ENOENT and close is skipped. `run-bench.sh` caps it at 20000
 * iterations.
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
 * `openat(AT_FDCWD, "/dev/null")` followed by `close`: openat is a separate libc entry
 * point with its own wrapper. Capped at 20000 iterations.
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
 * `fsync` / `fdatasync` on the temp file. Setup dirties one page; the first call (in
 * warmup) writes it back, after which every call finds nothing dirty and returns
 * without device I/O. The cost still depends on the filesystem backing /tmp (the
 * container root, overlayfs under Docker's default storage driver). Capped at 20000
 * iterations.
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
 * `ftruncate` to the current size (4096 bytes): the size does not change, so no
 * blocks are freed or allocated, but the kernel still takes the inode lock and updates
 * timestamps.
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
 * Linux only. `fallocate(mode 0)` over [0, 4096), a range setup already wrote, so no
 * extent changes after the first call. Capped at 20000 iterations.
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
 * Linux only. `sendfile` of 64 bytes from offset 0 of one unlinked temp file to
 * another. The input offset is reset each iteration; the output file position is not,
 * so the output file grows by 64 bytes per successful call (12.8 MB at the default
 * 200000 iterations). Regular-file output needs Linux >= 2.6.33.
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
