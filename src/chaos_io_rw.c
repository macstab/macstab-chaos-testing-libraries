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

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_READ, &rule)) {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_read(fd, buffer, count);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_read(fd, buffer, count);
    chaos_io_leave_internal(previous);
    if (rc > 0 && rule.effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(&rule)) {
        chaos_io_corrupt_buffer(buffer, (size_t)rc);
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

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_WRITE, &rule)) {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_write(fd, buffer, count);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    } else if (rule.effect == CHAOS_IO_EFFECT_TORN && chaos_io_rule_should_trigger(&rule)) {
        count = chaos_io_torn_count(count);
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_write(fd, buffer, count);
    chaos_io_leave_internal(previous);
    return rc;
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

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(out_fd, CHAOS_IO_OP_WRITE, &rule)) {
        return chaos_io_call_real_sendfile(out_fd, in_fd, offset, count);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (rule.effect == CHAOS_IO_EFFECT_ERRNO && chaos_io_rule_apply_errno(&rule)) {
        return -1;
    } else if (rule.effect == CHAOS_IO_EFFECT_TORN && chaos_io_rule_should_trigger(&rule)) {
        count = chaos_io_torn_count(count);
    }

    return chaos_io_call_real_sendfile(out_fd, in_fd, offset, count);
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

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_PREAD, &rule)) {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_pread(fd, buffer, count, offset);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_pread(fd, buffer, count, offset);
    chaos_io_leave_internal(previous);
    if (rc > 0 && rule.effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(&rule)) {
        chaos_io_corrupt_buffer(buffer, (size_t)rc);
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

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_PWRITE, &rule)) {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_pwrite(fd, buffer, count, offset);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    } else if (rule.effect == CHAOS_IO_EFFECT_TORN && chaos_io_rule_should_trigger(&rule)) {
        count = chaos_io_torn_count(count);
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_pwrite(fd, buffer, count, offset);
    chaos_io_leave_internal(previous);
    return rc;
}
