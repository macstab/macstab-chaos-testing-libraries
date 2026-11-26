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
 * | write, writev | `write` | ERRNO, LATENCY before; TORN shortens the request, DROP skips it |
 * | pwrite, pwritev | `pwrite` | ERRNO, LATENCY before; TORN shortens the request, DROP skips it |
 * | sendfile, copy_file_range | `write` on the output descriptor | ERRNO, LATENCY, TORN |
 *
 * @par TORN
 * The real call runs with a byte count in [1, n-1], so the caller sees a successful short
 * write, exactly what a kernel may return and what a correct write loop must handle.
 * Vectored writes get a trimmed copy of the iovec array covering that many bytes; vectors
 * longer than CHAOS_IO_TORN_MAX_IOV (64) entries are written whole and count no hit.
 *
 * @par DROP
 * The real call does not run and the full count is reported as written. The file offset is
 * moved on by that many bytes, so the caller's next write does not land on top of what it
 * believes it already wrote; an `O_APPEND` descriptor needs no correction, and one without
 * an offset keeps the rule from firing (chaos_io_drop_write()). `sendfile` and
 * `copy_file_range` carry a `write` rule but never a DROP: they move bytes between two
 * descriptors, and faking both sides of that is not a lost write any program can suffer.
 * The stdio writers ignore DROP as they ignore TORN.
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

#include "chaos_bucket.h"
#include "chaos_io_actions.h"
#include "chaos_sleep.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

#include <fcntl.h>
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
 * @param[in]  rule          Firing rule; its first effect draw gives the torn length.
 * @param[in]  source        Array (wrapper copy).
 * @param[in]  source_count  Entries.
 * @param[out] target        Room for @p source_count entries.
 * @param[out] target_count  Entries written.
 * @return Non-zero when a torn vector was built.
 */
static int chaos_io_build_torn_iovecs(
    const chaos_io_rule_t *rule,
    const struct iovec *source,
    int source_count,
    struct iovec *target,
    int *target_count
)
{
    size_t total;
    size_t torn_total;

    if (!chaos_io_iovec_total_bytes(source, source_count, &total) || total == 0U)
    {
        return 0;
    }

    torn_total = chaos_io_torn_count(rule, total);
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
 * invalid or long array reaches only the kernel. The torn length is the rule's first
 * effect draw.
 */
static int chaos_io_tear_iovecs(
    const chaos_io_rule_t *rule, const struct iovec *iov, int iovcnt, struct iovec *torn, int *count
)
{
    struct iovec copy[CHAOS_IO_TORN_MAX_IOV];

    return iov != NULL && iovcnt > 0 && iovcnt <= CHAOS_IO_TORN_MAX_IOV &&
           chaos_io_read_iovecs(iov, iovcnt, copy) == 0 &&
           chaos_io_build_torn_iovecs(rule, copy, iovcnt, torn, count);
}

/**
 * @brief CORRUPT for readv/preadv: flips one bit among the first @p size bytes of the
 *        scattered result, chosen uniformly over the whole stream.
 *
 * @details Takes the byte index from the rule's first effect draw and the bit from its
 * second, like chaos_io_corrupt_buffer(), maps the byte offset to its segment and flips
 * the bit there. Reads the caller's array directly: the real call just succeeded with it,
 * so it is valid.
 *
 * @param[in] rule    Firing rule, after chaos_io_rule_should_trigger() returned 1.
 * @param[in] iov     Caller's array; the bytes its entries point to are modified.
 * @param[in] iovcnt  Entries.
 * @param[in] size    Bytes the real call returned; may be less than the array's total.
 */
static void chaos_io_corrupt_iovecs(
    const chaos_io_rule_t *rule, const struct iovec *iov, int iovcnt, size_t size
)
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

    index_sample = chaos_io_rule_draw(rule, CHAOS_IO_DRAW_FIRST_EFFECT);
    bit_sample = chaos_io_rule_draw(rule, CHAOS_IO_DRAW_SECOND_EFFECT);
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
        chaos_io_corrupt_buffer(&rule, buffer, (size_t)rc);
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
        chaos_io_corrupt_iovecs(&rule, iov, iovcnt, (size_t)rc);
    }
    return rc;
}

/*---------------------------------------------------------------------------*
 * THROTTLE: hold the write side to a byte rate
 *---------------------------------------------------------------------------*/

/** @brief Descriptors whose write rate is tracked at once (slots indexed by fd % 64). */
#define CHAOS_IO_THROTTLE_SLOTS 64U

/**
 * @brief One descriptor's token bucket.
 *
 * @details Slot `fd % CHAOS_IO_THROTTLE_SLOTS`, tagged with the descriptor and the rate it
 * was armed with. A colliding descriptor takes the slot over, so two heavily written
 * descriptors that land on the same slot share one bucket and are held to one rate
 * together rather than to one each; a changed rate starts a fresh bucket, because the
 * tokens of the old rate say nothing about the new one.
 *
 * Plain statics, not a mapping: a bucket is three words, and a fork child inheriting its
 * parent's buckets is right -- the rate belongs to the descriptor, which it inherited too.
 */
typedef struct chaos_io_throttle
{
    volatile int fd;
    volatile uint64_t rate;
    chaos_bucket_t bucket;
    /** Whether this slot has ever had an owner: a takeover starts empty, a first use full. */
    int taken;
} chaos_io_throttle_t;

static chaos_io_throttle_t g_chaos_io_throttles[CHAOS_IO_THROTTLE_SLOTS];

/** @brief The bucket of (@p fd, @p rate), reset when the slot held something else. */
static chaos_bucket_t *chaos_io_throttle_bucket(int fd, uint64_t rate)
{
    chaos_io_throttle_t *entry = &g_chaos_io_throttles[(unsigned)fd % CHAOS_IO_THROTTLE_SLOTS];

    if (entry->fd != fd || entry->rate != rate)
    {
        /* A slot that already belonged to somebody starts empty for its new owner, not
         * full: `state = 0` means "never used" to the refill, which hands out a whole
         * second's worth. Two descriptors that collide here would then reset each other on
         * every call and the rate would not be enforced at all -- measured at 479 MB/s
         * under a 16 KiB/s rule, with no hit counted either, so nothing showed it. Two
         * live descriptors on one slot now hold each other back instead, which errs on the
         * side of the rate the rule asked for. A new *rate* on the same descriptor is a
         * different thing -- the rule changed, and a newly loaded rule does not punish the
         * first call -- so that one still starts full. */
        const int stolen = entry->taken && entry->fd != fd;

        entry->bucket.state = stolen ? chaos_bucket_state(0U, chaos_hits_now_ms()) : 0U;
        entry->taken = 1;
        entry->rate = rate;
        entry->fd = fd;
    }
    return &entry->bucket;
}

/**
 * @brief Drops the rate bucket of @p fd, if it holds one.
 *
 * @details Called when the descriptor is closed. Without it the next descriptor to get
 * that number inherits a drained bucket and is held back for bytes somebody else moved --
 * and since a taken-over slot now starts empty rather than full, inheriting one is no
 * longer harmless. The number is the whole key here, so there is nothing else to check.
 */
void chaos_io_throttle_forget(int fd)
{
    chaos_io_throttle_t *entry = &g_chaos_io_throttles[(unsigned)fd % CHAOS_IO_THROTTLE_SLOTS];

    if (entry->taken && entry->fd == fd)
    {
        entry->taken = 0;
        entry->fd = -1;
        entry->rate = 0U;
        entry->bucket.state = 0U;
    }
}

/**
 * @brief Whether @p fd was opened non-blocking; 0 when the flags cannot be read.
 *
 * @details With errno preserved, as the net side's descriptor queries are: a wrapper that
 * does not inject leaves errno exactly as the real call left it, and this query runs on
 * the way to deciding whether to inject at all.
 */
static int chaos_io_nonblocking(int fd)
{
    const int saved_errno = errno;
    const long flags = CHAOS_IO_SYSCALL(SYS_fcntl, fd, F_GETFL, 0);

    errno = saved_errno;
    return flags >= 0 && (flags & O_NONBLOCK) != 0;
}

/**
 * @brief How many of @p count bytes the rule's rate lets through now.
 *
 * @details The bucket is charged first and the rule asked second, as the TORN path does:
 * an allowance that covers the whole call changes nothing, so it spends neither a hit nor
 * a `@first` claim. When the bucket is empty the caller is not left waiting for a whole
 * second: a non-blocking descriptor is told `EAGAIN`, which is what its event loop is
 * written for, and a blocking one reserves a tenth of a second's worth, waits for exactly
 * that reservation and writes it. Reserving rather than sleeping and taking again is what
 * keeps the rate the rate when several threads write to one descriptor: each of them is
 * charged what it will write, so no two of them wait for the same bytes.
 *
 * @param refuse  Output: non-zero when the caller must report EAGAIN instead of writing.
 * @return Bytes to pass to the real call; @p count when the rule does not hold it back.
 */
static size_t chaos_io_throttle_count(chaos_io_rule_t *rule, int fd, size_t count, int *refuse)
{
    chaos_bucket_t *bucket = chaos_io_throttle_bucket(fd, rule->rate_bps);
    uint64_t allowed = chaos_bucket_take(bucket, rule->rate_bps, count, chaos_hits_now_ms());

    *refuse = 0;
    if (allowed == (uint64_t)count)
    {
        return count;
    }
    if (allowed == 0U)
    {
        const uint64_t chunk = chaos_bucket_chunk(rule->rate_bps);

        if (chaos_io_nonblocking(fd))
        {
            if (!chaos_io_rule_should_trigger(rule))
            {
                return count;
            }
            *refuse = 1;
            return 0U;
        }
        /* Asked before the wait, unlike the partial allowance below: there is nothing to
         * hand out, so a rule that does not fire must not cost the caller the wait. */
        if (!chaos_io_rule_should_trigger(rule))
        {
            return count;
        }
        allowed = chunk < (uint64_t)count ? chunk : (uint64_t)count;
        chaos_sleep_ms(chaos_bucket_reserve(bucket, rule->rate_bps, allowed, chaos_hits_now_ms()));
        return (size_t)allowed;
    }
    return chaos_io_rule_should_trigger(rule) ? (size_t)allowed : count;
}

/**
 * @brief The vectored form of chaos_io_throttle_count(): trims the vector to the allowance.
 *
 * @details A vector too long for the stack copy, or one that cannot be read, is written
 * whole and counts no hit, as a vector that cannot be torn is.
 *
 * @param refuse  Output: non-zero when the caller must report EAGAIN instead of writing.
 * @return Non-zero when @p target holds the trimmed vector to write instead.
 */
static int chaos_io_throttle_iovecs(
    chaos_io_rule_t *rule,
    int fd,
    const struct iovec *iov,
    int iovcnt,
    struct iovec *target,
    int *target_count,
    int *refuse
)
{
    struct iovec copy[CHAOS_IO_TORN_MAX_IOV];
    size_t total;
    size_t allowed;

    *refuse = 0;
    if (iov == NULL || iovcnt <= 0 || iovcnt > CHAOS_IO_TORN_MAX_IOV ||
        chaos_io_read_iovecs(iov, iovcnt, copy) != 0 ||
        !chaos_io_iovec_total_bytes(copy, iovcnt, &total) || total == 0U)
    {
        return 0;
    }
    allowed = chaos_io_throttle_count(rule, fd, total, refuse);
    if (*refuse || allowed >= total)
    {
        return 0;
    }
    return chaos_io_trim_iovecs(copy, iovcnt, allowed, target, target_count);
}

/**
 * @brief Decides a DROP on a write and leaves the descriptor consistent.
 *
 * @details DROP reports the whole write as done without doing it, which is the lost write
 * a buffered writer, a fsync-less commit or a cache flush can suffer. Reporting it needs
 * one correction: a write advances the file offset, so a dropped one has to advance it too
 * or the caller's next write lands on top of the bytes it thinks it already wrote, and the
 * file ends up differently damaged than any real loss would make it.
 *
 * - `O_APPEND`: nothing to correct. The kernel ignores the offset and writes at the end,
 *   so consecutive writes never overwrite each other.
 * - Otherwise the offset is moved on by @p count. A descriptor with no offset (a pipe, a
 *   FIFO, a socket) answers ESPIPE and keeps the rule from firing: nothing there is
 *   inconsistent, but the data would simply be gone, and the operation class `write` is
 *   not where that case belongs -- net's DROP covers datagrams, which is the version of it
 *   that models a network.
 *
 * The decision comes last, after the correction is known to be possible, so a `@first`
 * allowance and a hit are spent only on a call that is really dropped -- the same order
 * the TORN path uses.
 *
 * @param rule   Matched DROP rule.
 * @param fd     Descriptor being written.
 * @param count  Bytes the caller asked to write.
 * @return Non-zero when the real write must be skipped and @p count reported as written.
 */
static int chaos_io_drop_write(chaos_io_rule_t *rule, int fd, size_t count)
{

    /* Both queries below are asked on the way to a decision, so errno has to come out of
     * here as it went in: the common case is that this returns 0 and the real write runs
     * and succeeds, and a caller that then reads errno must not find the ESPIPE of the
     * probe on a pipe or a socket. */
    const int saved_errno = errno;
    const long flags = CHAOS_IO_SYSCALL(SYS_fcntl, fd, F_GETFL, 0);
    int correct;

    /* A count the call could not have returned is left alone: reported as written it would
     * come back as a negative ssize_t -- an error with no errno -- and the offset
     * correction would move backwards by the same amount. The kernel refuses such a call
     * with EINVAL anyway. The net twin bounds the same thing and says so; asked before the
     * draw, so a call this leaves alone counts no hit. */
    if (flags < 0 || count > (size_t)SSIZE_MAX)
    {
        errno = saved_errno;
        return 0;
    }
    correct = (flags & O_APPEND) == 0 && count > 0U;
    /* Asking where the offset is has no effect of its own, so it is safe before the
     * probability draw; it is also the only way to learn whether there is one. */
    if (correct && CHAOS_IO_SYSCALL(SYS_lseek, fd, (long)0, SEEK_CUR) < 0)
    {
        errno = saved_errno;
        return 0;
    }
    errno = saved_errno;
    if (!chaos_io_rule_should_trigger(rule))
    {
        return 0;
    }
    if (correct)
    {
        (void)CHAOS_IO_SYSCALL(SYS_lseek, fd, (long)count, SEEK_CUR);
        errno = saved_errno;
    }
    return 1;
}

/**
 * @brief Interposed write(2): `write` rules; ERRNO or LATENCY before the call, TORN
 *        shortens it, DROP skips it.
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
        count = chaos_io_torn_count(&rule, count);
    }
    else if (rule.effect == CHAOS_IO_EFFECT_DROP && chaos_io_drop_write(&rule, fd, count))
    {
        return (ssize_t)count;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_THROTTLE)
    {
        int refuse = 0;

        count = chaos_io_throttle_count(&rule, fd, count, &refuse);
        if (refuse)
        {
            errno = EAGAIN;
            return -1;
        }
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
        if (chaos_io_tear_iovecs(&rule, iov, iovcnt, torn_iov, &torn_iovcnt) &&
            chaos_io_rule_should_trigger(&rule))
        {
            return chaos_io_call_real_writev(fd, torn_iov, torn_iovcnt);
        }
    }
    else if (rule.effect == CHAOS_IO_EFFECT_DROP && rule.call_size != CHAOS_POLICY_NO_SIZE &&
             chaos_io_drop_write(&rule, fd, (size_t)rule.call_size))
    {
        return (ssize_t)rule.call_size;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_THROTTLE)
    {
        struct iovec held_iov[CHAOS_IO_TORN_MAX_IOV];
        int held_iovcnt;
        int refuse = 0;

        if (chaos_io_throttle_iovecs(&rule, fd, iov, iovcnt, held_iov, &held_iovcnt, &refuse))
        {
            return chaos_io_call_real_writev(fd, held_iov, held_iovcnt);
        }
        if (refuse)
        {
            errno = EAGAIN;
            return -1;
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
        count = chaos_io_torn_count(&rule, count);
    }
    else if (rule.effect == CHAOS_IO_EFFECT_THROTTLE)
    {
        int refuse = 0;

        /* The same shortening TORN does here: the kernel moves both offsets on by the
         * count it transferred, so a shortened transfer is a short one, not a lost one.
         * The bucket is the destination descriptor's, as the rule is. */
        count = chaos_io_throttle_count(&rule, out_fd, count, &refuse);
        if (refuse)
        {
            errno = EAGAIN;
            return -1;
        }
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
        count = chaos_io_torn_count(&rule, count);
    }
    else if (rule.effect == CHAOS_IO_EFFECT_THROTTLE)
    {
        int refuse = 0;

        count = chaos_io_throttle_count(&rule, out_fd, count, &refuse);
        if (refuse)
        {
            errno = EAGAIN;
            return -1;
        }
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
        chaos_io_corrupt_buffer(&rule, buffer, (size_t)rc);
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
        chaos_io_corrupt_iovecs(&rule, iov, iovcnt, (size_t)rc);
    }
    return rc;
}

/**
 * @brief Interposed pwrite(2): write() semantics with `pwrite` rules, TORN and DROP
 *        included.
 *
 * @details DROP needs no offset correction here: a positioned write leaves the
 * descriptor's own offset alone, so dropping it leaves nothing behind to keep straight.
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
        count = chaos_io_torn_count(&rule, count);
    }
    else if (rule.effect == CHAOS_IO_EFFECT_DROP && chaos_io_rule_should_trigger(&rule))
    {
        return (ssize_t)count;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_THROTTLE)
    {
        int refuse = 0;

        count = chaos_io_throttle_count(&rule, fd, count, &refuse);
        if (refuse)
        {
            errno = EAGAIN;
            return -1;
        }
    }

    rc = chaos_io_call_real_pwrite(fd, buffer, count, offset);
    return rc;
}

/**
 * @brief Interposed pwritev(2): writev() semantics with `pwrite` rules, including the
 *        64-entry TORN limit and DROP.
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

        if (chaos_io_tear_iovecs(&rule, iov, iovcnt, torn_iov, &torn_iovcnt) &&
            chaos_io_rule_should_trigger(&rule))
        {
            return chaos_io_call_real_pwritev(fd, torn_iov, torn_iovcnt, offset);
        }
    }
    else if (rule.effect == CHAOS_IO_EFFECT_DROP && rule.call_size != CHAOS_POLICY_NO_SIZE &&
             chaos_io_rule_should_trigger(&rule))
    {
        return (ssize_t)rule.call_size;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_THROTTLE)
    {
        struct iovec held_iov[CHAOS_IO_TORN_MAX_IOV];
        int held_iovcnt;
        int refuse = 0;

        if (chaos_io_throttle_iovecs(&rule, fd, iov, iovcnt, held_iov, &held_iovcnt, &refuse))
        {
            return chaos_io_call_real_pwritev(fd, held_iov, held_iovcnt, offset);
        }
        if (refuse)
        {
            errno = EAGAIN;
            return -1;
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
