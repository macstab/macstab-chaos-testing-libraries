/**
 * @file chaos_io_rw.c
 * @brief Read and write wrappers for libchaos-io.
 *
 * @details
 * This file implements the interposed entry points for all read- and
 * write-class I/O operations: `read`, `readv`, `write`, `writev`, `pread`,
 * `preadv`, `pwrite`, `pwritev`, and (on Linux) `sendfile` and
 * `copy_file_range`.  All of them operate on existing file descriptors and
 * share the same fd-backed rule lookup path (`chaos_io_match_fd_rule`).
 *
 * **Effect application for read-class operations:**
 * - `LATENCY`: applied pre-call, before the real syscall.
 * - `ERRNO`: applied pre-call; the real syscall is skipped.
 * - `CORRUPT`: applied post-call, to the bytes returned by the real syscall.
 *   Corruption is only applied when `rc > 0` (data was actually returned).
 * - `TORN` is not supported for reads.  A torn read cannot be distinguished
 *   from a genuine short read (EOF, socket, pipe) by the caller, and the
 *   library cannot guarantee the real call will return a predictable count.
 *
 * **Effect application for write-class operations:**
 * - `LATENCY`: applied pre-call.
 * - `ERRNO`: applied pre-call; the real syscall is skipped.
 * - `TORN`: applied pre-call by reducing the byte count (or iovec span)
 *   passed to the real syscall.  The real call succeeds with the shortened
 *   count, which is returned to the caller as-is.  This models the kernel
 *   returning a partial write, which higher-level callers that check return
 *   values must handle.
 * - `CORRUPT` is not supported for writes.
 *
 * **Vectored I/O and torn writes.**
 * For `writev` and `pwritev`, a torn write cannot be expressed as a simple
 * byte-count reduction; the real call expects a valid iovec array.
 * `chaos_io_build_torn_iovecs()` converts the total torn byte budget back
 * into a truncated iovec view.  The VLA `torn_iov[iovcnt]` is used to avoid
 * a heap allocation in the hot path.
 *
 * **Corruption over vectored reads.**
 * `readv` and `preadv` return bytes scattered across multiple iovec segments.
 * `chaos_io_corrupt_iovecs()` treats the segments as a single logical byte
 * stream and picks a corruption target from the combined range, then maps
 * the selected byte index back to the correct segment.
 *
 * **`sendfile` and `copy_file_range` (Linux only).**
 * Both are treated as write-class operations on `out_fd`.  Only `ERRNO`,
 * `LATENCY`, and `TORN` are supported; `CORRUPT` would require copying the
 * kernel-to-kernel data into user space, which is contrary to the entire
 * purpose of these syscalls.
 *
 * **Module ownership:** wrappers/
 * **Stability:** internal
 */

/*
 * Read- and write-side wrappers for libchaos-io.
 *
 * These wrappers all operate on existing file descriptors and therefore share
 * the same fd-backed rule lookup path.
 */

#include "chaos_io_actions.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

/**
 * @brief Returns the total byte count covered by an iovec array when it fits in `ssize_t`.
 *
 * @details Torn vectored writes need a concrete byte budget so the wrapper can present a
 * shortened logical request to libc. If the vector metadata is invalid or the
 * sum would overflow the real system-call contract, the helper returns zero and
 * the wrapper falls back to the original call without trying to reshape it.
 *
 * The overflow check uses `SSIZE_MAX` rather than `SIZE_MAX` because the write
 * syscall's return type is `ssize_t`; a total that overflows `ssize_t` would
 * be impossible to report correctly even if the kernel accepted it.
 *
 * @param[in]  iov     iovec array.  May be NULL (returns 0 immediately).
 * @param[in]  iovcnt  Number of entries in `iov`.
 * @param[out] total   Receives the summed byte count on success.  Must not be NULL.
 * @return Non-zero when the sum was computed successfully; zero on overflow or
 *         invalid input.
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

/**
 * @brief Builds a truncated iovec view that covers exactly `limit` bytes.
 *
 * @details The wrapper uses this for `TORN` on vectored writes so the real libc call
 * still receives a structurally valid iovec array whose total byte span matches
 * the shortened logical write size.
 *
 * Segments whose full length fits within the remaining budget are copied
 * verbatim.  The segment that straddles the budget boundary has its `iov_len`
 * trimmed to the remaining byte count.  Segments beyond that boundary are
 * simply not included (the target array is written only up to `*target_count`).
 *
 * An empty segment (`iov_len == 0`) is included in the output only if `remaining > 0`
 * when it is encountered; otherwise the loop exits because the budget is
 * already exhausted.
 *
 * @param[in]  source        Original iovec array.  Must not be NULL.
 * @param[in]  source_count  Number of entries in `source`.
 * @param[in]  limit         Maximum total byte count for the output array.
 * @param[out] target        Pre-allocated array for the truncated view.  Must
 *                           not be NULL and must have room for at least
 *                           `source_count` entries.
 * @param[out] target_count  Receives the number of valid entries written to
 *                           `target`.  Must not be NULL.
 * @return Non-zero when at least one segment was written; zero on invalid input.
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

/**
 * @brief Derives a torn vectored-write view from the caller's original iovec array.
 *
 * @details Computes the total byte count of `source`, draws a torn count from
 * the PRNG, and delegates to `chaos_io_trim_iovecs()` with the shortened
 * budget.
 *
 * Returns zero (passthrough) when the total byte count cannot be computed,
 * when the total is zero, or when the PRNG returns a torn count equal to or
 * greater than the total (which would be a zero-length "partial" write and
 * should not happen given `chaos_io_torn_count` guarantees, but is guarded
 * defensively).
 *
 * @param[in]  source        Original iovec.  Must not be NULL.
 * @param[in]  source_count  Number of entries.
 * @param[out] target        Pre-allocated iovec array (at least `source_count`
 *                           entries) for the truncated view.  Must not be NULL.
 * @param[out] target_count  Receives the valid entry count.  Must not be NULL.
 * @return Non-zero when a valid torn view was built; zero to fall back to the
 *         original write.
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

/**
 * @brief Corrupts one byte across a logical iovec byte stream.
 *
 * @details `readv()` and `preadv()` expose one contiguous logical read result even
 * though the destination spans multiple buffers, so corruption sampling happens
 * across the logical byte range and then targets the selected segment.
 *
 * The byte index is sampled from [0, size) treating all segments as a
 * contiguous address space.  The helper then walks the iovec array, subtracting
 * each segment's length until it finds the segment that contains the target
 * index, then calls `chaos_io_corrupt_buffer_sample()` with the within-segment
 * index.
 *
 * Both PRNG samples are drawn before the walk so the two-draw sequence is
 * consistent with `chaos_io_corrupt_buffer()`.
 *
 * @param[in,out] iov     The iovec array whose buffers may be corrupted.
 * @param[in]     iovcnt  Number of entries in `iov`.
 * @param[in]     size    Total number of bytes returned by the real read call.
 *                        May be smaller than the sum of `iov_len` values.
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

/* --- Real-call trampolines ------------------------------------------------------- */

/** @brief Calls the real `readv()` while preserving the recursion guard. */
static ssize_t chaos_io_call_real_readv(int fd, const struct iovec *iov, int iovcnt)
{
    int previous;
    ssize_t result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_readv(fd, iov, iovcnt);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Calls the real `writev()` while preserving the recursion guard. */
static ssize_t chaos_io_call_real_writev(int fd, const struct iovec *iov, int iovcnt)
{
    int previous;
    ssize_t result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_writev(fd, iov, iovcnt);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Calls the real `preadv()` while preserving the recursion guard. */
static ssize_t chaos_io_call_real_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    int previous;
    ssize_t result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_preadv(fd, iov, iovcnt, offset);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Calls the real `pwritev()` while preserving the recursion guard. */
static ssize_t chaos_io_call_real_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    int previous;
    ssize_t result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_pwritev(fd, iov, iovcnt, offset);
    chaos_io_leave_internal(previous);
    return result;
}

/* --- Exported interposed symbols ------------------------------------------------- */

/**
 * @brief Interposed `read(2)` entry point.
 *
 * @details The `CORRUPT` effect is applied only when `rc > 0`.  Applying
 * corruption to a 0-byte return (EOF) would write out of bounds on a
 * zero-size buffer and has no meaningful interpretation.  Applying it to a
 * negative return (error) would corrupt the caller's buffer even though no
 * data was delivered, which would silently change a detectable I/O error into
 * an undetectable data corruption—a strictly worse outcome.
 *
 * This wrapper never simulates torn reads. If the call succeeds, byte-count
 * semantics come from libc; only the returned bytes may be corrupted afterward.
 *
 * @param[in]  fd      File descriptor to read from.
 * @param[out] buffer  Destination buffer.  Must not be NULL for `count > 0`.
 * @param[in]  count   Maximum number of bytes to read.
 * @return Number of bytes read (≥ 0) on success; -1 with `errno` set on error.
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

/**
 * @brief Interposed `readv(2)` entry point.
 *
 * @details Semantics match `read()` exactly, but corruption is sampled across the
 * logical concatenation of all returned iovec bytes.
 *
 * @param[in]  fd      File descriptor to read from.
 * @param[out] iov     Scatter-gather destination.  Must not be NULL for `iovcnt > 0`.
 * @param[in]  iovcnt  Number of entries in `iov`.
 * @return Number of bytes read (≥ 0) on success; -1 with `errno` set on error.
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

/**
 * @brief Interposed `write(2)` entry point.
 *
 * @details Torn writes are modeled as successful short writes, not as post-write
 * corruption. That distinction matters because higher-level callers often
 * branch on the returned byte count.  A caller that writes in a loop checking
 * return values will retry the remaining bytes—which is exactly the
 * interrupted-write scenario this effect is designed to test.
 *
 * @param[in] fd      File descriptor to write to.
 * @param[in] buffer  Source data.  Must not be NULL for `count > 0`.
 * @param[in] count   Number of bytes to write.
 * @return Number of bytes written (≥ 0) on success; -1 with `errno` set on error.
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

/**
 * @brief Interposed `writev(2)` entry point.
 *
 * @details `TORN` is applied across the logical total byte span, then translated back
 * into a shortened iovec array for the real libc call.
 *
 * The VLA `torn_iov[iovcnt]` is allocated on the stack rather than the heap
 * to avoid any dynamic allocation in the hot path.  The library is compiled
 * with `-fno-stack-protector`, so VLA usage is safe from the canary-write
 * reentrancy hazard.
 *
 * @param[in] fd      File descriptor to write to.
 * @param[in] iov     Gather-I/O source array.
 * @param[in] iovcnt  Number of entries in `iov`.
 * @return Number of bytes written on success; -1 with `errno` set on error.
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

/**
 * @brief Calls the real Linux `sendfile()` while preserving the recursion guard.
 *
 * @details `sendfile()` is Linux-specific in this library because non-Linux libcs expose
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

/**
 * @brief Interposed `sendfile(2)` entry point (Linux only).
 *
 * @details The library treats Linux `sendfile()` as a destination-side logical write.
 * Matching therefore happens on `out_fd`, and the supported effects mirror the
 * write path: `ERRNO`, `LATENCY`, and `TORN`.
 *
 * `CORRUPT` is not supported because the data transfer happens entirely inside
 * the kernel and never passes through a user-space buffer that could be modified.
 *
 * The `TORN` effect reduces `count`; when `sendfile` returns the shortened
 * count the caller observes a partial transfer, which is the intended chaos
 * scenario.
 *
 * @param[in]  out_fd  Destination file descriptor (write side); used for rule matching.
 * @param[in]  in_fd   Source file descriptor (read side).
 * @param[in,out] offset  If non-NULL, starting file offset in `in_fd`;
 *                        updated by the kernel to reflect bytes transferred.
 * @param[in]  count   Maximum bytes to transfer.
 * @return Bytes transferred on success; -1 with `errno` set on error.
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

/**
 * @brief Calls the real Linux `copy_file_range()` while preserving the recursion guard.
 *
 * @details Like `sendfile()`, this wrapper exists only on Linux and reuses the logical
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

/**
 * @brief Interposed `copy_file_range(2)` entry point (Linux only).
 *
 * @details The library treats Linux `copy_file_range()` as a destination-side logical
 * write. Matching therefore happens on `out_fd`, and the supported effects
 * mirror the write path: `ERRNO`, `LATENCY`, and `TORN`.
 *
 * `CORRUPT` is not supported for the same reason as `sendfile`: the data
 * never passes through user space.
 *
 * @param[in]  in_fd       Source file descriptor.
 * @param[in,out] in_offset  Byte offset in source; updated on success.
 * @param[in]  out_fd      Destination file descriptor; used for rule matching.
 * @param[in,out] out_offset Byte offset in destination; updated on success.
 * @param[in]  count       Maximum bytes to copy.
 * @param[in]  flags       Reserved; must be zero.
 * @return Bytes copied on success; -1 with `errno` set on error.
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

/**
 * @brief Interposed `pread(2)` entry point.
 *
 * @details Execution sequence matches `read()` exactly except that the supplied `offset`
 * is part of the real libc call.  The offset does not affect rule matching;
 * the same `PREAD` operation rule applies regardless of the offset value.
 *
 * @param[in]  fd      File descriptor.
 * @param[out] buffer  Destination buffer.
 * @param[in]  count   Maximum bytes to read.
 * @param[in]  offset  File offset at which to read; does not advance `fd`'s position.
 * @return Number of bytes read on success; -1 on error.
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

/**
 * @brief Interposed `preadv(2)` entry point.
 *
 * @details Execution order matches `pread()`, including post-read corruption over the
 * logical concatenation of returned bytes.
 *
 * @param[in]  fd      File descriptor.
 * @param[out] iov     Scatter-gather destination array.
 * @param[in]  iovcnt  Number of entries in `iov`.
 * @param[in]  offset  File offset; does not advance `fd`'s position.
 * @return Number of bytes read on success; -1 on error.
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

/**
 * @brief Interposed `pwrite(2)` entry point.
 *
 * @details Execution sequence matches `write()` exactly except that the supplied
 * `offset` is part of the real libc call.  The `TORN` effect reduces `count`
 * before the call, making the real call write fewer bytes than the caller
 * intended.
 *
 * @param[in] fd      File descriptor.
 * @param[in] buffer  Source data.
 * @param[in] count   Number of bytes to write.
 * @param[in] offset  File offset; does not advance `fd`'s position.
 * @return Number of bytes written on success; -1 on error.
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

/**
 * @brief Interposed `pwritev(2)` entry point.
 *
 * @details Semantics match `pwrite()`, with torn writes modeled over the logical total
 * byte span before translating the shortened request back to an iovec array.
 *
 * The VLA `torn_iov[iovcnt]` is stack-allocated for the same reason as in the
 * `writev` wrapper.
 *
 * @param[in] fd      File descriptor.
 * @param[in] iov     Gather-I/O source array.
 * @param[in] iovcnt  Number of entries in `iov`.
 * @param[in] offset  File offset; does not advance `fd`'s position.
 * @return Number of bytes written on success; -1 on error.
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
