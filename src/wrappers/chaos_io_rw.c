/*
 * Read- and write-side wrappers for libchaos-io.
 *
 * These wrappers all operate on existing file descriptors and therefore share
 * the same fd-backed rule lookup path.
 */

#include "chaos_io_actions.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

/*
 * Returns the total byte count covered by an iovec array when it fits in
 * `ssize_t`.
 *
 * Torn vectored writes need a concrete byte budget so the wrapper can present a
 * shortened logical request to libc. If the vector metadata is invalid or the
 * sum would overflow the real system-call contract, the helper returns zero and
 * the wrapper falls back to the original call without trying to reshape it.
 */
static int chaos_io_iovec_total_bytes(const struct iovec *iov, int iovcnt, size_t *total)
{
    int index;
    size_t bytes = 0U;

    if (total == NULL)
    {
        return 0;
    }
    *total = 0U;
    if (iov == NULL || iovcnt <= 0)
    {
        return 0;
    }

    for (index = 0; index < iovcnt; ++index)
    {
        if (iov[index].iov_len > (size_t)SSIZE_MAX - bytes)
        {
            return 0;
        }
        bytes += iov[index].iov_len;
    }

    *total = bytes;
    return 1;
}

/*
 * Builds a truncated iovec view that covers exactly `limit` bytes.
 *
 * The wrapper uses this for `TORN` on vectored writes so the real libc call
 * still receives a structurally valid iovec array whose total byte span matches
 * the shortened logical write size.
 */
static int chaos_io_trim_iovecs(
    const struct iovec *source,
    int source_count,
    size_t limit,
    struct iovec *target,
    int *target_count
)
{
    int index;
    int written = 0;
    size_t remaining = limit;

    if (source == NULL || source_count <= 0 || target == NULL || target_count == NULL)
    {
        return 0;
    }

    for (index = 0; index < source_count && remaining > 0U; ++index)
    {
        size_t segment_len = source[index].iov_len;

        target[written] = source[index];
        if (segment_len > remaining)
        {
            segment_len = remaining;
        }
        target[written].iov_len = segment_len;
        if (segment_len > 0U)
        {
            remaining -= segment_len;
        }
        ++written;
    }

    *target_count = written;
    return written > 0;
}

/*
 * Derives a torn vectored-write view from the caller's original iovec array.
 *
 * The returned target count is non-zero only when the wrapper can safely model
 * a real short write. Otherwise the caller should delegate to libc unchanged.
 */
static int chaos_io_build_torn_iovecs(
    const struct iovec *source, int source_count, struct iovec *target, int *target_count
)
{
    size_t total;
    size_t torn_total;

    if (!chaos_io_iovec_total_bytes(source, source_count, &total) || total == 0U)
    {
        return 0;
    }

    torn_total = chaos_io_torn_count(total);
    if (torn_total == 0U || torn_total >= total)
    {
        return 0;
    }

    return chaos_io_trim_iovecs(source, source_count, torn_total, target, target_count);
}

/*
 * Corrupts one byte across a logical iovec byte stream.
 *
 * `readv()` and `preadv()` expose one contiguous logical read result even
 * though the destination spans multiple buffers, so corruption sampling happens
 * across the logical byte range and then targets the selected segment.
 */
static void chaos_io_corrupt_iovecs(const struct iovec *iov, int iovcnt, size_t size)
{
    uint32_t index_sample;
    uint32_t bit_sample;
    size_t remaining = size;
    size_t index;
    int entry;

    if (iov == NULL || iovcnt <= 0 || size == 0U)
    {
        return;
    }

    index_sample = chaos_io_prng_next_u32();
    bit_sample = chaos_io_prng_next_u32();
    index = (size_t)(index_sample % size);
    for (entry = 0; entry < iovcnt && remaining > 0U; ++entry)
    {
        size_t segment_len = iov[entry].iov_len;

        if (segment_len > remaining)
        {
            segment_len = remaining;
        }
        if (index < segment_len)
        {
            chaos_io_corrupt_buffer_sample(
                iov[entry].iov_base, segment_len, (uint32_t)index, bit_sample
            );
            return;
        }

        if (segment_len > 0U)
        {
            index -= segment_len;
            remaining -= segment_len;
        }
    }
}

/* Calls the real `readv()` while preserving the recursion guard. */
static ssize_t chaos_io_call_real_readv(int fd, const struct iovec *iov, int iovcnt)
{
    int previous;
    ssize_t result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_readv(fd, iov, iovcnt);
    chaos_io_leave_internal(previous);
    return result;
}

/* Calls the real `writev()` while preserving the recursion guard. */
static ssize_t chaos_io_call_real_writev(int fd, const struct iovec *iov, int iovcnt)
{
    int previous;
    ssize_t result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_writev(fd, iov, iovcnt);
    chaos_io_leave_internal(previous);
    return result;
}

/* Calls the real `preadv()` while preserving the recursion guard. */
static ssize_t chaos_io_call_real_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    int previous;
    ssize_t result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_preadv(fd, iov, iovcnt, offset);
    chaos_io_leave_internal(previous);
    return result;
}

/* Calls the real `pwritev()` while preserving the recursion guard. */
static ssize_t chaos_io_call_real_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    int previous;
    ssize_t result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_pwritev(fd, iov, iovcnt, offset);
    chaos_io_leave_internal(previous);
    return result;
}

/*
 * Interposed `read(2)` entry point.
 *
 * This wrapper never simulates torn reads. If the call succeeds, byte-count
 * semantics come from libc; only the returned bytes may be corrupted afterward.
 */
CHAOS_IO_EXPORT ssize_t read(int fd, void *buffer, size_t count)
{
    chaos_io_rule_t rule;
    ssize_t rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_READ, &rule))
    {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_read(fd, buffer, count);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_read(fd, buffer, count);
    chaos_io_leave_internal(previous);
    if (rc > 0 && rule.effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(&rule))
    {
        chaos_io_corrupt_buffer(buffer, (size_t)rc);
    }
    return rc;
}

/*
 * Interposed `readv(2)` entry point.
 *
 * Semantics match `read()` exactly, but corruption is sampled across the
 * logical concatenation of all returned iovec bytes.
 */
CHAOS_IO_EXPORT ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
    chaos_io_rule_t rule;
    ssize_t rc;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_READ, &rule))
    {
        return chaos_io_call_real_readv(fd, iov, iovcnt);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    rc = chaos_io_call_real_readv(fd, iov, iovcnt);
    if (rc > 0 && rule.effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(&rule))
    {
        chaos_io_corrupt_iovecs(iov, iovcnt, (size_t)rc);
    }
    return rc;
}

/*
 * Interposed `write(2)` entry point.
 *
 * Torn writes are modeled as successful short writes, not as post-write
 * corruption. That distinction matters because higher-level callers often
 * branch on the returned byte count.
 */
CHAOS_IO_EXPORT ssize_t write(int fd, const void *buffer, size_t count)
{
    chaos_io_rule_t rule;
    ssize_t rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_WRITE, &rule))
    {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_write(fd, buffer, count);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_TORN && chaos_io_rule_should_trigger(&rule))
    {
        count = chaos_io_torn_count(count);
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_write(fd, buffer, count);
    chaos_io_leave_internal(previous);
    return rc;
}

/*
 * Interposed `writev(2)` entry point.
 *
 * `TORN` is applied across the logical total byte span, then translated back
 * into a shortened iovec array for the real libc call.
 */
CHAOS_IO_EXPORT ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    chaos_io_rule_t rule;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_WRITE, &rule))
    {
        return chaos_io_call_real_writev(fd, iov, iovcnt);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_TORN && chaos_io_rule_should_trigger(&rule))
    {
        if (iov != NULL && iovcnt > 0)
        {
            struct iovec torn_iov[iovcnt];
            int torn_iovcnt;

            if (chaos_io_build_torn_iovecs(iov, iovcnt, torn_iov, &torn_iovcnt))
            {
                return chaos_io_call_real_writev(fd, torn_iov, torn_iovcnt);
            }
        }
    }

    return chaos_io_call_real_writev(fd, iov, iovcnt);
}

#ifdef __linux__
/*
 * Call the real Linux `sendfile()` while preserving the recursion guard.
 *
 * `sendfile()` is Linux-specific in this library because non-Linux libcs expose
 * incompatible ABIs. The wrapper therefore lives behind `__linux__` and reuses
 * the existing logical `write` rule class on the destination fd.
 */
static ssize_t chaos_io_call_real_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    int previous;
    ssize_t result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_sendfile(out_fd, in_fd, offset, count);
    chaos_io_leave_internal(previous);
    return result;
}

/*
 * Interposed `sendfile(2)` entry point.
 *
 * The library treats Linux `sendfile()` as a destination-side logical write.
 * Matching therefore happens on `out_fd`, and the supported effects mirror the
 * write path: `ERRNO`, `LATENCY`, and `TORN`.
 */
CHAOS_IO_EXPORT ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    chaos_io_rule_t rule;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(out_fd, CHAOS_IO_OP_WRITE, &rule))
    {
        return chaos_io_call_real_sendfile(out_fd, in_fd, offset, count);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (rule.effect == CHAOS_IO_EFFECT_ERRNO && chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_TORN && chaos_io_rule_should_trigger(&rule))
    {
        count = chaos_io_torn_count(count);
    }

    return chaos_io_call_real_sendfile(out_fd, in_fd, offset, count);
}

/*
 * Call the real Linux `copy_file_range()` while preserving the recursion guard.
 *
 * Like `sendfile()`, this wrapper exists only on Linux and reuses the logical
 * `write` rule class on the destination fd.
 */
static ssize_t chaos_io_call_real_copy_file_range(
    int in_fd, off_t *in_offset, int out_fd, off_t *out_offset, size_t count, unsigned int flags
)
{
    int previous;
    ssize_t result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_copy_file_range(in_fd, in_offset, out_fd, out_offset, count, flags);
    chaos_io_leave_internal(previous);
    return result;
}

/*
 * Interposed `copy_file_range(2)` entry point.
 *
 * The library treats Linux `copy_file_range()` as a destination-side logical
 * write. Matching therefore happens on `out_fd`, and the supported effects
 * mirror the write path: `ERRNO`, `LATENCY`, and `TORN`.
 */
CHAOS_IO_EXPORT ssize_t copy_file_range(
    int in_fd, off_t *in_offset, int out_fd, off_t *out_offset, size_t count, unsigned int flags
)
{
    chaos_io_rule_t rule;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(out_fd, CHAOS_IO_OP_WRITE, &rule))
    {
        return chaos_io_call_real_copy_file_range(
            in_fd, in_offset, out_fd, out_offset, count, flags
        );
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (rule.effect == CHAOS_IO_EFFECT_ERRNO && chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_TORN && chaos_io_rule_should_trigger(&rule))
    {
        count = chaos_io_torn_count(count);
    }

    return chaos_io_call_real_copy_file_range(in_fd, in_offset, out_fd, out_offset, count, flags);
}
#endif

/*
 * Interposed `pread(2)` entry point.
 *
 * Execution sequence matches `read()` exactly except that the supplied `offset`
 * is part of the real libc call.
 */
CHAOS_IO_EXPORT ssize_t pread(int fd, void *buffer, size_t count, off_t offset)
{
    chaos_io_rule_t rule;
    ssize_t rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_PREAD, &rule))
    {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_pread(fd, buffer, count, offset);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_pread(fd, buffer, count, offset);
    chaos_io_leave_internal(previous);
    if (rc > 0 && rule.effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(&rule))
    {
        chaos_io_corrupt_buffer(buffer, (size_t)rc);
    }
    return rc;
}

/*
 * Interposed `preadv(2)` entry point.
 *
 * Execution order matches `pread()`, including post-read corruption over the
 * logical concatenation of returned bytes.
 */
CHAOS_IO_EXPORT ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    chaos_io_rule_t rule;
    ssize_t rc;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_PREAD, &rule))
    {
        return chaos_io_call_real_preadv(fd, iov, iovcnt, offset);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    rc = chaos_io_call_real_preadv(fd, iov, iovcnt, offset);
    if (rc > 0 && rule.effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(&rule))
    {
        chaos_io_corrupt_iovecs(iov, iovcnt, (size_t)rc);
    }
    return rc;
}

/*
 * Interposed `pwrite(2)` entry point.
 *
 * Execution sequence matches `write()` exactly except that the supplied
 * `offset` is part of the real libc call.
 */
CHAOS_IO_EXPORT ssize_t pwrite(int fd, const void *buffer, size_t count, off_t offset)
{
    chaos_io_rule_t rule;
    ssize_t rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_PWRITE, &rule))
    {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_pwrite(fd, buffer, count, offset);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_TORN && chaos_io_rule_should_trigger(&rule))
    {
        count = chaos_io_torn_count(count);
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_pwrite(fd, buffer, count, offset);
    chaos_io_leave_internal(previous);
    return rc;
}

/*
 * Interposed `pwritev(2)` entry point.
 *
 * Semantics match `pwrite()`, with torn writes modeled over the logical total
 * byte span before translating the shortened request back to an iovec array.
 */
CHAOS_IO_EXPORT ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    chaos_io_rule_t rule;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_PWRITE, &rule))
    {
        return chaos_io_call_real_pwritev(fd, iov, iovcnt, offset);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_TORN && chaos_io_rule_should_trigger(&rule))
    {
        if (iov != NULL && iovcnt > 0)
        {
            struct iovec torn_iov[iovcnt];
            int torn_iovcnt;

            if (chaos_io_build_torn_iovecs(iov, iovcnt, torn_iov, &torn_iovcnt))
            {
                return chaos_io_call_real_pwritev(fd, torn_iov, torn_iovcnt, offset);
            }
        }
    }

    return chaos_io_call_real_pwritev(fd, iov, iovcnt, offset);
}
