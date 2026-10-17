/**
 * @file chaos_memory_hooks.c
 * @brief The wrappers of libchaos-memory: mmap(2) (and mmap64 on 64-bit glibc),
 *        munmap(2), mprotect(2), madvise(2) and posix_madvise(3).
 *
 * @details
 * Every wrapper runs the same sequence:
 *  1. chaos_memory_ensure_symbols(): resolve the real functions if no one has.
 *  2. Reentrancy bypass: inside library code (guard set) call the real function
 *     without matching rules.
 *  3. LATENCY pass: match the most specific LATENCY rule; if it fires, sleep.
 *  4. ERRNO pass: match the most specific ERRNO rule; if it fires, return the
 *     failure value without calling the real function.
 *  5. Call the real function under the reentrancy guard.
 * Matching includes the throttled look at the rule file (at most once per 1 ms;
 * see chaos_memory_config.c).
 *
 * @par Selectors
 * | Wrapper         | Selectors                                          |
 * |-----------------|----------------------------------------------------|
 * | mmap, mmap64    | `mmap`; `mmap/anon` or `mmap/file` by MAP_ANONYMOUS |
 * | munmap          | `munmap`                                           |
 * | mprotect        | `mprotect`                                         |
 * | madvise         | `madvise`                                          |
 * | posix_madvise   | `madvise`                                          |
 * `*` matches all of them. Every wrapper passes its length for `@size`.
 *
 * @par Failure values
 * | Function                  | Injected failure                            |
 * |---------------------------|---------------------------------------------|
 * | mmap, mmap64              | MAP_FAILED, errno set                       |
 * | munmap, mprotect, madvise | -1, errno set                               |
 * | posix_madvise             | the error number returned, errno unchanged  |
 *
 * @par Why reentrancy matters more here than in other libraries
 * mmap() is how preloaded allocators get memory, so library code can reach these
 * wrappers on the same thread:
 *  - Symbol lookup: dlsym() may allocate, and a preloaded allocator (jemalloc,
 *    tcmalloc) then calls mmap() while the real pointers are still NULL. The
 *    call-through helpers detect NULL and issue the system call directly, which is
 *    what libc's wrapper would do.
 *  - The look at the rule file and its read run under the guard; anything they
 *    map passes through uninjected.
 *  - The real function itself runs under the guard: a further interposer below
 *    this library that allocates does not re-enter rule matching.
 * The library allocates nothing itself: buffers are static or on the stack.
 *
 * @par munmap failures
 * An injected munmap() failure leaves the mapping in place, as a real failure
 * would. A caller that ignores munmap()'s result leaks the mapping; that is the
 * fault being tested.
 *
 * @par Stability
 * The exported symbols are the interposition interface; the static helpers are
 * internal.
 */

#include "chaos_memory_actions.h"
#include "chaos_memory_config.h"
#include "chaos_memory_internal.h"

#include <sys/syscall.h>
#include <unistd.h>

/* =========================================================================
 * Call-through helpers
 * =========================================================================
 * Each helper calls the real function with the reentrancy guard set, so that
 * whatever the next definition does that reaches a wrapper of this library again
 * (an interposer below this one that allocates) passes through uninjected. While
 * the real pointer is still NULL (a call from inside dlsym()), the helper issues
 * the system call directly.
 */

/**
 * @brief chaos_memory_config_match() for a call on @p length bytes.
 *
 * @details Stores the length in the matched copy, so the rule's `@size>N` /
 * `@size<N` gate is checked when the firing is decided.
 */
static int chaos_memory_match_sized(
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    size_t length,
    chaos_memory_rule_t *rule
)
{
    if (!chaos_memory_config_match(effect, operation, mmap_flags, rule))
    {
        return 0;
    }
    rule->call_size = (uint64_t)length;
    return 1;
}

/**
 * @brief Calls the real mmap(2) with the reentrancy guard set (restored after).
 *
 * @details Arguments as mmap(2). The SYS_mmap fallback matches libc on the
 * supported 64-bit targets, where off_t and the system call's offset are both
 * 64-bit bytes.
 *
 * @return The real result: the mapping, or MAP_FAILED with errno set.
 */
static void *chaos_memory_call_real_mmap(
    void *address, size_t length, int protection, int flags, int fd, off_t offset
)
{
    int previous;
    void *result;

    if (g_chaos_memory_real_mmap == NULL)
    {
        /* Not resolved yet: a call from inside the symbol lookup (an allocator
         * mapping memory for dlsym()). The system call does what libc's mmap() does;
         * syscall() returns -1 (== MAP_FAILED) with errno set on failure. */
        return (void *)syscall(SYS_mmap, address, length, protection, flags, fd, offset);
    }
    previous = chaos_memory_enter_internal();
    result = g_chaos_memory_real_mmap(address, length, protection, flags, fd, offset);
    chaos_memory_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real mprotect(2) with the reentrancy guard set; SYS_mprotect
 *        while unresolved.
 *
 * @return 0 on success; -1 with errno set on failure.
 */
static int chaos_memory_call_real_mprotect(void *address, size_t length, int protection)
{
    int previous;
    int rc;

    if (g_chaos_memory_real_mprotect == NULL)
    {
        return (int)syscall(SYS_mprotect, address, length, protection);
    }
    previous = chaos_memory_enter_internal();
    rc = g_chaos_memory_real_mprotect(address, length, protection);
    chaos_memory_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real munmap(2) with the reentrancy guard set; SYS_munmap while
 *        unresolved.
 *
 * @return 0 on success; -1 with errno set on failure.
 */
static int chaos_memory_call_real_munmap(void *address, size_t length)
{
    int previous;
    int rc;

    if (g_chaos_memory_real_munmap == NULL)
    {
        return (int)syscall(SYS_munmap, address, length);
    }
    previous = chaos_memory_enter_internal();
    rc = g_chaos_memory_real_munmap(address, length);
    chaos_memory_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real posix_madvise(3) with the reentrancy guard set.
 *
 * @details While unresolved it reproduces glibc and musl: POSIX_MADV_DONTNEED is
 * a successful no-op, other advice goes to SYS_madvise, and errno is preserved.
 *
 * @return 0 on success; the error number on failure (errno unchanged).
 */
static int chaos_memory_call_real_posix_madvise(void *address, size_t length, int advice)
{
    int previous;
    int rc;

    if (g_chaos_memory_real_posix_madvise == NULL)
    {
        const int saved_errno = errno;

        /* POSIX_MADV_DONTNEED is only advice; MADV_DONTNEED, the same number, would
         * discard the pages' contents. glibc and musl ignore it; so does this. */
        if (advice == POSIX_MADV_DONTNEED)
        {
            return 0;
        }
        rc = syscall(SYS_madvise, address, length, advice) == 0 ? 0 : errno;
        errno = saved_errno;
        return rc;
    }
    previous = chaos_memory_enter_internal();
    rc = g_chaos_memory_real_posix_madvise(address, length, advice);
    chaos_memory_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real madvise(2) with the reentrancy guard set; SYS_madvise while
 *        unresolved.
 *
 * @return 0 on success; -1 with errno set on failure.
 */
static int chaos_memory_call_real_madvise(void *address, size_t length, int advice)
{
    int previous;
    int rc;

    if (g_chaos_memory_real_madvise == NULL)
    {
        return (int)syscall(SYS_madvise, address, length, advice);
    }
    previous = chaos_memory_enter_internal();
    rc = g_chaos_memory_real_madvise(address, length, advice);
    chaos_memory_leave_internal(previous);
    return rc;
}

/* =========================================================================
 * Exported wrappers
 * =========================================================================
 */

/**
 * @brief mmap(2) wrapper: selectors `mmap`, `mmap/anon`, `mmap/file`, `*`.
 *
 * @details A firing LATENCY rule delays the call; a firing ERRNO rule returns
 * MAP_FAILED with errno set and creates no mapping. `mmap/anon` versus `mmap/file`
 * is decided by MAP_ANONYMOUS in @p flags; which allocations that reaches is
 * described at chaos_memory_mmap_is_anonymous(). There is no post-call effect
 * (see chaos_memory_actions.c). @p length is the size seen by `@size`.
 *
 * @param address     Address hint, or NULL.
 * @param length      Mapping length, bytes.
 * @param protection  PROT_* flags.
 * @param flags       MAP_* flags.
 * @param fd          File descriptor; -1 for anonymous mappings.
 * @param offset      File offset, bytes.
 * @return The mapping, or MAP_FAILED with errno set (injected or real).
 */
CHAOS_MEMORY_EXPORT void *
mmap(void *address, size_t length, int protection, int flags, int fd, off_t offset)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    chaos_memory_ensure_symbols();

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_mmap(address, length, protection, flags, fd, offset);
    }

    if (chaos_memory_match_sized(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MMAP, flags, length, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_match_sized(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MMAP, flags, length, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        return MAP_FAILED;
    }

    return chaos_memory_call_real_mmap(address, length, protection, flags, fd, offset);
}

/**
 * @brief munmap(2) wrapper: selectors `munmap`, `*`.
 *
 * @details A firing ERRNO rule returns -1 and leaves the mapping in place, as a
 * real failure (e.g. EINVAL for an unaligned address) would; callers that ignore
 * the result leak it. The injected path does not validate the arguments.
 *
 * @param address  Start of the range.
 * @param length   Range length, bytes (seen by `@size`).
 * @return 0 on success; -1 with errno set (injected or real).
 */
CHAOS_MEMORY_EXPORT int munmap(void *address, size_t length)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    chaos_memory_ensure_symbols();

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_munmap(address, length);
    }

    if (chaos_memory_match_sized(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MUNMAP, 0, length, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_match_sized(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MUNMAP, 0, length, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        /* The mapping stays: an injected failure must not change the address space. */
        return -1;
    }

    return chaos_memory_call_real_munmap(address, length);
}

/**
 * @brief mprotect(2) wrapper: selectors `mprotect`, `*`.
 *
 * @details Typical rules: ERRNO:EACCES (protection the mapped file does not allow,
 * e.g. PROT_WRITE on a shared mapping of a read-only descriptor), ERRNO:EPERM
 * (PROT_EXEC refused by policy, or a sealed mapping), LATENCY (a slow change, as
 * under mmap_lock contention). JITs and W^X runtimes call mprotect() on hot paths.
 *
 * @param address     Start of the range.
 * @param length      Range length, bytes (seen by `@size`).
 * @param protection  New PROT_* flags.
 * @return 0 on success; -1 with errno set (injected or real).
 */
CHAOS_MEMORY_EXPORT int mprotect(void *address, size_t length, int protection)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    chaos_memory_ensure_symbols();

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_mprotect(address, length, protection);
    }

    if (chaos_memory_match_sized(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MPROTECT, 0, length, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_match_sized(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MPROTECT, 0, length, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        return -1;
    }

    return chaos_memory_call_real_mprotect(address, length, protection);
}

/**
 * @brief madvise(2) wrapper: selectors `madvise`, `*`.
 *
 * @details Typical rules: ERRNO:EINVAL (advice the kernel does not know, which is
 * how a kernel older than the advice reports it, or an unaligned address),
 * LATENCY (advice that makes the kernel work, such as MADV_PAGEOUT or
 * MADV_POPULATE_READ). Preloaded allocators (jemalloc, tcmalloc) call the exported
 * madvise(MADV_DONTNEED/MADV_FREE) to return memory, so a rule reaches their free()
 * paths; libc's own allocator uses its internal entry point and is not reached.
 *
 * @param address  Start of the range.
 * @param length   Range length, bytes (seen by `@size`).
 * @param advice   MADV_* value.
 * @return 0 on success; -1 with errno set (injected or real).
 */
CHAOS_MEMORY_EXPORT int madvise(void *address, size_t length, int advice)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    chaos_memory_ensure_symbols();

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_madvise(address, length, advice);
    }

    if (chaos_memory_match_sized(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MADVISE, 0, length, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_match_sized(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MADVISE, 0, length, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        return -1;
    }

    return chaos_memory_call_real_madvise(address, length, advice);
}

/**
 * @brief posix_madvise(3) wrapper: the `madvise` rules apply.
 *
 * @details Needed separately because glibc and musl implement posix_madvise() with
 * the madvise system call, never through madvise(). Following POSIX it returns the
 * error number and leaves errno alone, so an injected ERRNO is returned and errno
 * restored to its value before the ERRNO pass.
 *
 * @return 0 on success; the error number on failure (injected or real).
 */
CHAOS_MEMORY_EXPORT int posix_madvise(void *address, size_t length, int advice)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;
    int saved_errno;
    int injected;

    chaos_memory_ensure_symbols();

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_posix_madvise(address, length, advice);
    }

    if (chaos_memory_match_sized(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MADVISE, 0, length, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    saved_errno = errno;
    if (chaos_memory_match_sized(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MADVISE, 0, length, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        injected = errno;
        errno = saved_errno;
        return injected;
    }

    return chaos_memory_call_real_posix_madvise(address, length, advice);
}

/* On 64-bit glibc mmap64() is a separate symbol with mmap()'s signature (off_t is
 * already 64-bit); the JVM, Redis, nginx and MySQL bind to it, and without this
 * alias their mappings would bypass the library. Current musl exports no mmap64,
 * so the alias is glibc-only. */
#if defined(__GLIBC__) && defined(__LP64__)
CHAOS_MEMORY_EXPORT void *
mmap64(void *address, size_t length, int protection, int flags, int fd, off_t offset)
    __attribute__((alias("mmap")));
#endif
