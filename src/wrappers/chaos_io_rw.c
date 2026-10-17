/**
 * @file chaos_io_rw.c
 * @brief Descriptor read/write wrappers: read, readv, pread, preadv, write, writev, pwrite,
 *        pwritev, sendfile, copy_file_range (and glibc `64` and fortified `_chk` variants).
 *
 * @details
 * All of them look up their rule with chaos_io_match_fd_rule() on the descriptor.
 *
 * | Wrapper | Operation | Effects applied |
 * |---------|-----------|-----------------|
 * | read, readv | `read` | ERRNO, LATENCY before; CORRUPT after a read of > 0 bytes |
 * | pread, preadv | `pread` | ERRNO, LATENCY before; CORRUPT after a read of > 0 bytes |
 * | write, writev | `write` | ERRNO, LATENCY before; TORN shortens the request |
 * | pwrite, pwritev | `pwrite` | ERRNO, LATENCY before; TORN shortens the request |
 * | sendfile, copy_file_range | `write` on the output descriptor | ERRNO, LATENCY, TORN |
 *
 * @par TORN
 * The real call runs with a byte count in [1, n-1], so the caller sees a successful short
 * write, exactly what a kernel may return and what a correct write loop must handle.
 * Vectored writes get a trimmed copy of the iovec array covering that many bytes; vectors
 * longer than CHAOS_IO_TORN_MAX_IOV (64) entries are written whole and count no hit.
 *
 * @par CORRUPT
 * One bit of the bytes actually returned is flipped after the real call. For readv/preadv
 * the returned bytes are treated as one stream across the segments. No corruption on EOF
 * or error: there are no bytes to corrupt, and turning a detectable error into silent
 * corruption would change what is being tested.
 *
 * @par The caller's iovec array
 * Read only after a rule matched, never past IOV_MAX entries, and through a checked copy
 * (process_vm_readv on this process), so an invalid array still fails in the kernel with
 * EINVAL or EFAULT instead of crashing in the wrapper.
 *
 * @par sendfile and copy_file_range (Linux)
 * Treated as writes to the output descriptor. CORRUPT cannot be applied: the data moves
 * inside the kernel and never passes through a user buffer.
 */

#include "chaos_io_actions.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

#include <limits.h>
#include <sys/syscall.h>
#include <sys/uio.h>

/** @brief Most iovec entries the kernel accepts (IOV_MAX, 1024 on Linux). */
#ifdef IOV_MAX
#define CHAOS_IO_MAX_IOV IOV_MAX
#else
#define CHAOS_IO_MAX_IOV 1024
#endif

/** @brief Longest vector TORN shortens (bounds the on-stack copy); longer ones are written
 *         whole. */
#define CHAOS_IO_TORN_MAX_IOV 64

/**
 * @brief Copies @p count entries of the caller's iovec array into @p out without faulting
 *        on an invalid pointer.
 *
 * @details process_vm_readv(2) on this process returns EFAULT for unmapped memory instead
 * of raising SIGSEGV in the wrapper. Where it is unavailable (ENOSYS, or EPERM from a
 * seccomp profile such as Docker's default) the array is copied with memcpy: the kernel
 * is about to read
 * it anyway, so a fault there is the one the program would have taken. errno is
 * preserved. Test seam: CHAOS_IO_PROCESS_VM_READV.
 *
 * @return 0 when all entries were copied; -1 when the array cannot be read.
 */
#ifndef CHAOS_IO_PROCESS_VM_READV
#define CHAOS_IO_PROCESS_VM_READV(local, remote)                                                   \
    syscall(SYS_process_vm_readv, syscall(SYS_getpid), (local), 1UL, (remote), 1UL, 0UL)
#endif
static int chaos_io_read_iovecs(const struct iovec *iov, int count, struct iovec *out)
{
    const int saved_errno = errno;
    struct iovec local;
    struct iovec remote;
    long copied;

    local.iov_base = out;
    local.iov_len = (size_t)count * sizeof(*out);
    remote.iov_base = (void *)(uintptr_t)iov;
    remote.iov_len = local.iov_len;
    copied = (long)CHAOS_IO_PROCESS_VM_READV(&local, &remote);
    if (copied < 0 && (errno == ENOSYS || errno == EPERM))
    {
        (void)memcpy(out, iov, local.iov_len);
        copied = (long)local.iov_len;
    }
    errno = saved_errno;
    return copied == (long)local.iov_len ? 0 : -1;
}

/**
 * @brief Sums the lengths of an iovec array (already copied into wrapper memory).
 *
 * @details The bound is SSIZE_MAX, not SIZE_MAX, because the kernel rejects a vector
 * whose total exceeds it with EINVAL; such a call is passed through unchanged.
 *
 * @param[in]  iov     Array; NULL returns 0.
 * @param[in]  iovcnt  Entries; <= 0 returns 0.
 * @param[out] total   Receives the sum (0 on failure); NULL returns 0.
 * @return Non-zero when the sum fits in ssize_t; 0 otherwise.
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
 * @brief Byte count of the caller's iovec array for `@size` gates; CHAOS_POLICY_NO_SIZE when
 *        the array is invalid or unreadable.
 *
 * @details Reads the array through chaos_io_read_iovecs() in chunks of 64 entries, so any
 * length up to IOV_MAX is summed with a bounded stack buffer.
 */
static uint64_t chaos_io_iovec_size(const struct iovec *iov, int iovcnt)
{
    struct iovec chunk[CHAOS_IO_TORN_MAX_IOV];
    uint64_t total = 0U;
    int done = 0;

    if (iov == NULL || iovcnt < 0 || iovcnt > CHAOS_IO_MAX_IOV)
    {
        return CHAOS_POLICY_NO_SIZE; /* the kernel rejects it with EINVAL: do not read it */
    }
    while (done < iovcnt)
    {
        const int count =
            iovcnt - done < CHAOS_IO_TORN_MAX_IOV ? iovcnt - done : CHAOS_IO_TORN_MAX_IOV;
        size_t part;

        if (chaos_io_read_iovecs(iov + done, count, chunk) != 0 ||
            !chaos_io_iovec_total_bytes(chunk, count, &part) || part > (uint64_t)SSIZE_MAX - total)
        {
            return CHAOS_POLICY_NO_SIZE;
        }
        total += part;
        done += count;
    }
    return total;
}

/**
 * @brief Writes into @p target the prefix of @p source that covers exactly @p limit bytes.
 *
 * @details Whole segments are copied while they fit; the segment that crosses the limit
 * is trimmed; later segments are dropped. Zero-length segments before the limit is
 * reached are kept, so buffer pointers stay in their original order.
 *
 * @param[in]  source        Array (wrapper copy); NULL returns 0.
 * @param[in]  source_count  Entries; <= 0 returns 0.
 * @param[in]  limit         Bytes the result covers; must not exceed the source total.
 * @param[out] target        Room for @p source_count entries; NULL returns 0.
 * @param[out] target_count  Entries written; NULL returns 0.
 * @return Non-zero when at least one entry was written.
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
 * @brief Draws a torn byte count for @p source and builds the trimmed vector.
 *
 * @details Returns 0 (write unchanged) when the total is unknown or 0, or when the drawn
 * count is not a real tear: a total of 1 byte cannot be torn (chaos_io_torn_count()
 * returns 1), and the check also guards the [1, total-1] contract.
 *
 * @param[in]  source        Array (wrapper copy).
 * @param[in]  source_count  Entries.
 * @param[out] target        Room for @p source_count entries.
 * @param[out] target_count  Entries written.
 * @return Non-zero when a torn vector was built.
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
 * @brief Builds a torn copy of the caller's vector in @p torn (room for
 *        CHAOS_IO_TORN_MAX_IOV entries); 0 when it cannot be torn.
 *
 * @details Works on a checked copy (chaos_io_read_iovecs()) of at most 64 entries, so an
 * invalid or long array reaches only the kernel. Draws one PRNG sample when it tears.
 */
static int chaos_io_tear_iovecs(const struct iovec *iov, int iovcnt, struct iovec *torn, int *count)
{
    struct iovec copy[CHAOS_IO_TORN_MAX_IOV];

    return iov != NULL && iovcnt > 0 && iovcnt <= CHAOS_IO_TORN_MAX_IOV &&
           chaos_io_read_iovecs(iov, iovcnt, copy) == 0 &&
           chaos_io_build_torn_iovecs(copy, iovcnt, torn, count);
}

/**
 * @brief CORRUPT for readv/preadv: flips one bit among the first @p size bytes of the
 *        scattered result, chosen uniformly over the whole stream.
 *
 * @details Draws byte then bit sample, like chaos_io_corrupt_buffer(), maps the byte
 * offset to its segment and flips the bit there. Reads the caller's array directly: the
 * real call just succeeded with it, so it is valid.
 *
 * @param[in] iov     Caller's array; the bytes its entries point to are modified.
 * @param[in] iovcnt  Entries.
 * @param[in] size    Bytes the real call returned; may be less than the array's total.
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

/*
 * Each trampoline calls the real function inside a library section, so libc I/O made from
 * inside it is not matched again, and issues the system call itself while its
 * `g_chaos_io_real_*` pointer is still NULL (a call during symbol resolution).
 */

/**
 * @brief The offset as the low and high words the preadv/pwritev system calls take (they
 *        split it even on 64-bit kernels; the high word is ignored there).
 */
#define CHAOS_IO_OFFSET_WORDS(offset) (long)(offset), (long)((uint64_t)(offset) >> 32)

/** @brief Real read() inside a library section; raw system call before resolution. */
static ssize_t chaos_io_call_real_read(int fd, void *buffer, size_t count)
{
    int previous;
    ssize_t result;

    if (g_chaos_io_real_read == NULL)
    {
        return (ssize_t)CHAOS_IO_SYSCALL(SYS_read, fd, buffer, count);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_read(fd, buffer, count);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Real write() inside a library section; raw system call before resolution. */
static ssize_t chaos_io_call_real_write(int fd, const void *buffer, size_t count)
{
    int previous;
    ssize_t result;

    if (g_chaos_io_real_write == NULL)
    {
        return (ssize_t)CHAOS_IO_SYSCALL(SYS_write, fd, buffer, count);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_write(fd, buffer, count);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Real pread() inside a library section; raw pread64 before resolution. */
static ssize_t chaos_io_call_real_pread(int fd, void *buffer, size_t count, off_t offset)
{
    int previous;
    ssize_t result;

    if (g_chaos_io_real_pread == NULL)
    {
        return (ssize_t)CHAOS_IO_SYSCALL(SYS_pread64, fd, buffer, count, offset);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_pread(fd, buffer, count, offset);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Real pwrite() inside a library section; raw pwrite64 before resolution. */
static ssize_t chaos_io_call_real_pwrite(int fd, const void *buffer, size_t count, off_t offset)
{
    int previous;
    ssize_t result;

    if (g_chaos_io_real_pwrite == NULL)
    {
        return (ssize_t)CHAOS_IO_SYSCALL(SYS_pwrite64, fd, buffer, count, offset);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_pwrite(fd, buffer, count, offset);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Real readv() inside a library section; raw system call before resolution. */
static ssize_t chaos_io_call_real_readv(int fd, const struct iovec *iov, int iovcnt)
{
    int previous;
    ssize_t result;

    if (g_chaos_io_real_readv == NULL)
    {
        return (ssize_t)CHAOS_IO_SYSCALL(SYS_readv, fd, iov, iovcnt);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_readv(fd, iov, iovcnt);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Real writev() inside a library section; raw system call before resolution. */
static ssize_t chaos_io_call_real_writev(int fd, const struct iovec *iov, int iovcnt)
{
    int previous;
    ssize_t result;

    if (g_chaos_io_real_writev == NULL)
    {
        return (ssize_t)CHAOS_IO_SYSCALL(SYS_writev, fd, iov, iovcnt);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_writev(fd, iov, iovcnt);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Real preadv() inside a library section; raw system call before resolution. */
static ssize_t chaos_io_call_real_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    int previous;
    ssize_t result;

    if (g_chaos_io_real_preadv == NULL)
    {
        return (ssize_t
        )CHAOS_IO_SYSCALL(SYS_preadv, fd, iov, iovcnt, CHAOS_IO_OFFSET_WORDS(offset));
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_preadv(fd, iov, iovcnt, offset);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Real pwritev() inside a library section; raw system call before resolution. */
static ssize_t chaos_io_call_real_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    int previous;
    ssize_t result;

    if (g_chaos_io_real_pwritev == NULL)
    {
        return (ssize_t
        )CHAOS_IO_SYSCALL(SYS_pwritev, fd, iov, iovcnt, CHAOS_IO_OFFSET_WORDS(offset));
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_pwritev(fd, iov, iovcnt, offset);
    chaos_io_leave_internal(previous);
    return result;
}

/* --- Exported interposed symbols ------------------------------------------------- */

/**
 * @brief Interposed read(2): `read` rules; ERRNO or LATENCY before the call, CORRUPT on
 *        the bytes returned.
 *
 * @details `@size` gates see @p count, the requested size. CORRUPT is decided (and
 * counted) only when the real call returned > 0 bytes; an error or EOF is returned
 * untouched. The byte count is always the real one.
 *
 * @return Bytes read; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT ssize_t read(int fd, void *buffer, size_t count)
{
    chaos_io_rule_t rule;
    ssize_t rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_match_fd_rule_sized(fd, CHAOS_IO_OP_READ, (uint64_t)count, &rule))
    {
        return chaos_io_call_real_read(fd, buffer, count);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    rc = chaos_io_call_real_read(fd, buffer, count);
    if (rc > 0 && rule.effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(&rule))
    {
        chaos_io_corrupt_buffer(buffer, (size_t)rc);
    }
    return rc;
}

/**
 * @brief Interposed readv(2): read() semantics; CORRUPT picks its byte across all segments.
 *
 * @details `@size` gates see the array's total, read only after a rule matched; an
 * invalid array yields CHAOS_POLICY_NO_SIZE, so a size-gated rule does not fire.
 *
 * @return Bytes read; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
    chaos_io_rule_t rule;
    ssize_t rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_READ, &rule))
    {
        return chaos_io_call_real_readv(fd, iov, iovcnt);
    }
    /* The caller's array is read only now that a rule matched: unmatched calls never
     * touch it. */
    rule.call_size = chaos_io_iovec_size(iov, iovcnt);

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
 * @brief Interposed write(2): `write` rules; ERRNO or LATENCY before the call, TORN
 *        shortens it.
 *
 * @details TORN passes a count in [1, count-1] to the real write, which succeeds short; a
 * correct caller loops and writes the rest, an incorrect one loses data, which is what
 * the effect exposes. A 1-byte write cannot be torn (passes whole, still counted as a hit).
 *
 * @return Bytes written; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT ssize_t write(int fd, const void *buffer, size_t count)
{
    chaos_io_rule_t rule;
    ssize_t rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_match_fd_rule_sized(fd, CHAOS_IO_OP_WRITE, (uint64_t)count, &rule))
    {
        return chaos_io_call_real_write(fd, buffer, count);
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

    rc = chaos_io_call_real_write(fd, buffer, count);
    return rc;
}

/**
 * @brief Interposed writev(2): write() semantics; TORN trims the vector to a byte count in
 *        [1, total-1].
 *
 * @details The trimmed vector lives in a fixed 64-entry stack array (1 KiB on LP64), so the
 * wrapper never allocates. A vector that cannot be torn (more than 64 entries, unreadable,
 * total < 2 bytes) is written whole and the rule counts no hit.
 *
 * @return Bytes written; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    chaos_io_rule_t rule;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_WRITE, &rule))
    {
        return chaos_io_call_real_writev(fd, iov, iovcnt);
    }
    /* The caller's array is read only now that a rule matched. */
    rule.call_size = chaos_io_iovec_size(iov, iovcnt);

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_TORN)
    {
        struct iovec torn_iov[CHAOS_IO_TORN_MAX_IOV];
        int torn_iovcnt;

        /* Tear first, decide second: a hit (and an @first allowance) is consumed only
         * when the tear can actually be applied. */
        if (chaos_io_tear_iovecs(iov, iovcnt, torn_iov, &torn_iovcnt) &&
            chaos_io_rule_should_trigger(&rule))
        {
            return chaos_io_call_real_writev(fd, torn_iov, torn_iovcnt);
        }
    }

    return chaos_io_call_real_writev(fd, iov, iovcnt);
}

#ifdef __linux__

/**
 * @brief Real sendfile() inside a library section; raw system call before resolution.
 *        Linux only: the BSD and macOS sendfile have different signatures.
 */
static ssize_t chaos_io_call_real_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    int previous;
    ssize_t result;

    if (g_chaos_io_real_sendfile == NULL)
    {
        return (ssize_t)CHAOS_IO_SYSCALL(SYS_sendfile, out_fd, in_fd, offset, count);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_sendfile(out_fd, in_fd, offset, count);
    chaos_io_leave_internal(previous);
    return result;
}

/**
 * @brief Interposed sendfile(2): `write` rules on @p out_fd; ERRNO, LATENCY, TORN.
 *
 * @details TORN shortens @p count, so the caller sees a partial transfer (and the kernel
 * advances @p offset only by what was sent). CORRUPT never applies: the data stays in the
 * kernel. `pread`/`read` rules on @p in_fd are not consulted.
 *
 * @return Bytes transferred; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    chaos_io_rule_t rule;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_match_fd_rule_sized(out_fd, CHAOS_IO_OP_WRITE, (uint64_t)count, &rule))
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
 * @brief Real copy_file_range() inside a library section; raw system call before resolution,
 *        ENOSYS where the headers lack the system call number.
 */
static ssize_t chaos_io_call_real_copy_file_range(
    int in_fd, off_t *in_offset, int out_fd, off_t *out_offset, size_t count, unsigned int flags
)
{
    int previous;
    ssize_t result;

    if (g_chaos_io_real_copy_file_range == NULL)
    {
#ifdef SYS_copy_file_range
        return (ssize_t
        )CHAOS_IO_SYSCALL(SYS_copy_file_range, in_fd, in_offset, out_fd, out_offset, count, flags);
#else
        errno = ENOSYS;
        return -1;
#endif
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_copy_file_range(in_fd, in_offset, out_fd, out_offset, count, flags);
    chaos_io_leave_internal(previous);
    return result;
}

/**
 * @brief Interposed copy_file_range(2): `write` rules on @p out_fd; ERRNO, LATENCY, TORN.
 *
 * @details Same model as sendfile(): TORN shortens @p count, CORRUPT never applies, the
 * input descriptor is not matched.
 *
 * @return Bytes copied; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT ssize_t copy_file_range(
    int in_fd, off_t *in_offset, int out_fd, off_t *out_offset, size_t count, unsigned int flags
)
{
    chaos_io_rule_t rule;

    chaos_io_ensure_symbols();

    if (chaos_io_in_internal() ||
        !chaos_io_match_fd_rule_sized(out_fd, CHAOS_IO_OP_WRITE, (uint64_t)count, &rule))
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
 * @brief Interposed pread(2): read() semantics with `pread` rules; the offset does not
 *        take part in matching.
 *
 * @return Bytes read; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT ssize_t pread(int fd, void *buffer, size_t count, off_t offset)
{
    chaos_io_rule_t rule;
    ssize_t rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_match_fd_rule_sized(fd, CHAOS_IO_OP_PREAD, (uint64_t)count, &rule))
    {
        return chaos_io_call_real_pread(fd, buffer, count, offset);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    rc = chaos_io_call_real_pread(fd, buffer, count, offset);
    if (rc > 0 && rule.effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(&rule))
    {
        chaos_io_corrupt_buffer(buffer, (size_t)rc);
    }
    return rc;
}

/**
 * @brief Interposed preadv(2): readv() semantics with `pread` rules.
 *
 * @return Bytes read; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    chaos_io_rule_t rule;
    ssize_t rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_PREAD, &rule))
    {
        return chaos_io_call_real_preadv(fd, iov, iovcnt, offset);
    }
    /* The caller's array is read only now that a rule matched. */
    rule.call_size = chaos_io_iovec_size(iov, iovcnt);

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
 * @brief Interposed pwrite(2): write() semantics with `pwrite` rules, TORN included.
 *
 * @return Bytes written; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT ssize_t pwrite(int fd, const void *buffer, size_t count, off_t offset)
{
    chaos_io_rule_t rule;
    ssize_t rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_match_fd_rule_sized(fd, CHAOS_IO_OP_PWRITE, (uint64_t)count, &rule))
    {
        return chaos_io_call_real_pwrite(fd, buffer, count, offset);
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

    rc = chaos_io_call_real_pwrite(fd, buffer, count, offset);
    return rc;
}

/**
 * @brief Interposed pwritev(2): writev() semantics with `pwrite` rules, including the
 *        64-entry TORN limit.
 *
 * @return Bytes written; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    chaos_io_rule_t rule;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_PWRITE, &rule))
    {
        return chaos_io_call_real_pwritev(fd, iov, iovcnt, offset);
    }
    rule.call_size = chaos_io_iovec_size(iov, iovcnt);

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_TORN)
    {
        struct iovec torn_iov[CHAOS_IO_TORN_MAX_IOV];
        int torn_iovcnt;

        if (chaos_io_tear_iovecs(iov, iovcnt, torn_iov, &torn_iovcnt) &&
            chaos_io_rule_should_trigger(&rule))
        {
            return chaos_io_call_real_pwritev(fd, torn_iov, torn_iovcnt, offset);
        }
    }

    return chaos_io_call_real_pwritev(fd, iov, iovcnt, offset);
}

/* ---------------------------------------------------------------------------
 * glibc alternate entry points
 *
 * On 64-bit glibc the large-file names (`pread64`, `sendfile64`, ...) are separate
 * symbols with the same signature as the base functions, and binaries built with
 * large-file support, or the JDK, bind to them; without these aliases such calls would
 * bypass the library. The fortified `_chk` variants are what `_FORTIFY_SOURCE` builds
 * (Debian and Ubuntu packages) call instead of read/pread; they apply glibc's buffer check
 * and then run the wrapper. musl has neither, so all of this is glibc-only (LP64).
 * ------------------------------------------------------------------------- */
#if defined(__GLIBC__) && defined(__LP64__)

extern void __chk_fail(void) __attribute__((__noreturn__));

/** @brief Failure handler of the fortified variants (glibc's __chk_fail, which aborts);
 *         a test seam. */
static void (*g_chaos_io_rw_chk_fail)(void) = __chk_fail;

CHAOS_IO_EXPORT ssize_t pread64(int fd, void *buffer, size_t count, off_t offset)
    __attribute__((alias("pread")));
CHAOS_IO_EXPORT ssize_t pwrite64(int fd, const void *buffer, size_t count, off_t offset)
    __attribute__((alias("pwrite")));
CHAOS_IO_EXPORT ssize_t preadv64(int fd, const struct iovec *iov, int iovcnt, off_t offset)
    __attribute__((alias("preadv")));
CHAOS_IO_EXPORT ssize_t pwritev64(int fd, const struct iovec *iov, int iovcnt, off_t offset)
    __attribute__((alias("pwritev")));
CHAOS_IO_EXPORT ssize_t sendfile64(int out_fd, int in_fd, off_t *offset, size_t count)
    __attribute__((alias("sendfile")));

/** @brief Fortified read(): aborts like glibc when @p count exceeds @p buffer_size,
 *         otherwise read(). */
CHAOS_IO_EXPORT ssize_t __read_chk(int fd, void *buffer, size_t count, size_t buffer_size)
{
    if (count > buffer_size)
    {
        g_chaos_io_rw_chk_fail();
        return -1;
    }
    return read(fd, buffer, count);
}

/** @brief Fortified pread(): aborts like glibc when @p count exceeds @p buffer_size,
 *         otherwise pread(). */
CHAOS_IO_EXPORT ssize_t
__pread_chk(int fd, void *buffer, size_t count, off_t offset, size_t buffer_size)
{
    if (count > buffer_size)
    {
        g_chaos_io_rw_chk_fail();
        return -1;
    }
    return pread(fd, buffer, count, offset);
}

CHAOS_IO_EXPORT ssize_t
__pread64_chk(int fd, void *buffer, size_t count, off_t offset, size_t buffer_size)
    __attribute__((alias("__pread_chk")));

#endif
