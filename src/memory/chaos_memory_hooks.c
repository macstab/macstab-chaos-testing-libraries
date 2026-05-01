/**
 * @file chaos_memory_hooks.c
 * @brief LD_PRELOAD hook wrappers for mmap(2), munmap(2), mprotect(2), and
 *        madvise(2) in libchaos-memory.
 *
 * @details
 * This translation unit provides the four exported symbols that interpose the
 * corresponding libc functions when the library is preloaded.  Each wrapper
 * follows the same three-phase structure:
 *
 *  1. **Reentrancy bypass**: if the TLS guard is set, forward directly to the
 *     real function with no fault injection.
 *  2. **LATENCY phase**: match a LATENCY rule and sleep if one fires.  The
 *     real syscall is still issued afterwards.
 *  3. **ERRNO phase**: match an ERRNO rule and return the error sentinel if
 *     one fires.  The real syscall is suppressed.
 *
 * The real-symbol call-through helpers (chaos_memory_call_real_*) set the
 * guard around the call to the resolved function pointer so that any mmap
 * calls triggered by the real syscall's implementation (e.g., the kernel
 * mapping a VDSO page on first use) do not re-enter the injection logic.
 *
 * @par Why reentrancy is especially critical for mmap
 * The mmap hook intercepts one of the lowest-level memory management
 * primitives in the Linux process model.  It can be re-entered from at least
 * four distinct call chains:
 *
 *  1. **Dynamic linker (dlopen)**: RTLD_NEXT resolution in chaos_memory_init()
 *     triggers dlopen-like linker activity.  The linker calls mmap to map
 *     library segments.  Without the guard, this would recurse into the hook
 *     before g_chaos_memory_real_mmap is populated, causing a NULL dereference.
 *
 *  2. **glibc malloc (large allocations)**: any heap allocation larger than
 *     MMAP_THRESHOLD (default 128 KiB) inside the chaos library — including
 *     logging, config parsing if it used dynamic allocation, or any indirect
 *     call through a library that allocates — would call mmap(MAP_ANONYMOUS)
 *     and re-enter the hook.  The implementation avoids all heap allocation
 *     in the hot path for exactly this reason; the guard is the safety net.
 *
 *  3. **TLS block expansion**: the first time a new thread accesses a
 *     `__thread` variable that was not in the initial TLS image, the OS may
 *     map a new TLS block via mmap.  Reading g_chaos_memory_tls_guard itself
 *     is safe because it is part of the initial TLS image (declared in the
 *     library's own .tbss section) and does not require a dynamic mmap.
 *     However, any other `__thread` variable access in a new thread could
 *     trigger this path before the guard is set, which is why setting the
 *     guard is the very first operation in the hook.
 *
 *  4. **Config reload path**: chaos_memory_config_prepare() calls stat(2) and
 *     open()/read() through glibc wrappers.  glibc's file-descriptor table
 *     management may call mmap internally on some code paths.  The reentrancy
 *     guard in chaos_memory_config.c (set before each I/O operation) covers
 *     this; the hook-level guard here is a belt-and-suspenders defence.
 *
 * read(2) and write(2) hooks in other chaos modules face a subset of these
 * hazards (malloc re-entry is possible but the linker and TLS paths are not
 * triggered by those syscalls during normal library initialisation), making
 * the mmap reentrancy problem uniquely acute.
 *
 * @par Error sentinels
 * POSIX specifies different error return values for the four intercepted
 * syscalls:
 *  - mmap(2):    returns MAP_FAILED ((void*)-1) on error; errno is set.
 *  - munmap(2):  returns -1 on error; errno is set.
 *  - mprotect(2): returns -1 on error; errno is set.
 *  - madvise(2): returns -1 on error; errno is set.
 *
 * chaos_memory_rule_apply_errno() sets errno and returns 1 as a signal; the
 * hook then returns the correct sentinel for its syscall.  This separation
 * keeps the action layer unaware of which syscall is being intercepted.
 *
 * @par munmap synthetic failure note
 * When an ERRNO rule fires for munmap(2), the mapping is intentionally left
 * active.  This correctly simulates the kernel returning an error (e.g.,
 * EINVAL for an address not aligned to a page boundary) without corrupting the
 * process address space.  Applications that do not check munmap's return value
 * will leak the mapping; this is an intentional fault-injection outcome to
 * exercise leak detection in the target process.
 *
 * @par Stability
 * The exported symbols (mmap, munmap, mprotect, madvise) are part of the
 * library's public interposition interface.  The static call-through helpers
 * are internal.
 */

#include "chaos_memory_actions.h"
#include "chaos_memory_config.h"
#include "chaos_memory_internal.h"

/* =========================================================================
 * Real-symbol call-through helpers
 * =========================================================================
 * Each helper sets the TLS reentrancy guard before calling the resolved real
 * function pointer and restores it afterwards.  This ensures that any mmap
 * call triggered inside the real syscall's implementation (e.g., a kernel
 * page fault handler mapping a new page, or a glibc wrapper expanding its
 * internal state) does not re-enter the injection logic.
 */

/**
 * @brief Call the real mmap(2) under the reentrancy guard.
 *
 * @details
 * Sets the TLS guard before the call and restores it afterwards.  The guard
 * is already set when this function is called from the chaos_memory_call_real_mmap
 * path inside the hook (the hook checks chaos_memory_in_internal() first), but
 * the guard is not set when the hook bypasses to this helper directly via the
 * reentrancy bypass branch — in that case this function sets it.
 *
 * Calling convention mirrors mmap(2) exactly.
 *
 * @return  The value returned by the real mmap(2), including MAP_FAILED on error.
 */
static void *chaos_memory_call_real_mmap(
    void *address, size_t length, int protection, int flags, int fd, off_t offset
)
{
    int previous;
    void *result;

    previous = chaos_memory_enter_internal();
    result = g_chaos_memory_real_mmap(address, length, protection, flags, fd, offset);
    chaos_memory_leave_internal(previous);
    return result;
}

/**
 * @brief Call the real mprotect(2) under the reentrancy guard.
 *
 * @return  0 on success, -1 on error (errno set by the real function).
 */
static int chaos_memory_call_real_mprotect(void *address, size_t length, int protection)
{
    int previous;
    int rc;

    previous = chaos_memory_enter_internal();
    rc = g_chaos_memory_real_mprotect(address, length, protection);
    chaos_memory_leave_internal(previous);
    return rc;
}

/**
 * @brief Call the real munmap(2) under the reentrancy guard.
 *
 * @return  0 on success, -1 on error (errno set by the real function).
 */
static int chaos_memory_call_real_munmap(void *address, size_t length)
{
    int previous;
    int rc;

    previous = chaos_memory_enter_internal();
    rc = g_chaos_memory_real_munmap(address, length);
    chaos_memory_leave_internal(previous);
    return rc;
}

/**
 * @brief Call the real madvise(2) under the reentrancy guard.
 *
 * @return  0 on success, -1 on error (errno set by the real function).
 */
static int chaos_memory_call_real_madvise(void *address, size_t length, int advice)
{
    int previous;
    int rc;

    previous = chaos_memory_enter_internal();
    rc = g_chaos_memory_real_madvise(address, length, advice);
    chaos_memory_leave_internal(previous);
    return rc;
}

/* =========================================================================
 * Exported interposition hooks
 * =========================================================================
 */

/**
 * @brief Interposed mmap(2): inject latency and/or errno faults before the
 *        real mapping operation.
 *
 * @details
 * Intercepts every call to mmap(2) in the preloaded process.  The three-phase
 * structure is:
 *
 *  1. **Reentrancy bypass**: if g_chaos_memory_tls_guard is non-zero (the
 *     current thread is already inside the chaos library), forward immediately
 *     to chaos_memory_call_real_mmap() — which sets the guard again (no-op,
 *     it restores the previous value) and calls the real function.
 *
 *  2. **LATENCY**: chaos_memory_config_match() stats and (if stale) reloads
 *     the config file, then selects the best LATENCY rule for this call.  If
 *     found, chaos_memory_rule_apply_latency() draws a PRNG sample; if the
 *     probability fires, it sleeps for rule->latency_ms milliseconds.  The
 *     call proceeds to the real mmap regardless of whether latency was applied.
 *
 *  3. **ERRNO**: similarly selects the best ERRNO rule.  If found and the
 *     probability fires, errno is set to rule->errnum and MAP_FAILED is
 *     returned.  The real mmap is NOT called — the mapping is never created.
 *
 * @par MAP_ANONYMOUS and allocator implications
 * The flags word is passed as-is to both config_match() calls, allowing the
 * selector engine to distinguish mmap/anon (MAP_ANONYMOUS set) from mmap/file
 * (MAP_ANONYMOUS clear) at no extra cost.  Under glibc, ERRNO:ENOMEM on
 * mmap/anon simulates large-allocation pressure (> MMAP_THRESHOLD); small
 * allocations via brk() are unaffected because they do not reach this hook.
 * Under musl, which uses mmap(MAP_ANONYMOUS) for all allocations regardless of
 * size, the same rule causes every malloc() call to fail immediately.
 *
 * @par Why no post-call mutation
 * See the @file docblock for the full rationale.  In summary: mutating the
 * returned pointer after a successful mmap either produces an address with no
 * backing mapping (SIGSEGV on access) or writes into the newly-created mapping
 * (data corruption).  Neither is a useful fault simulation.
 *
 * @param address     Preferred mapping address, or NULL for OS choice.
 * @param length      Length of the mapping in bytes.
 * @param protection  PROT_* flags.
 * @param flags       MAP_* flags; MAP_ANONYMOUS controls mmap/anon selection.
 * @param fd          File descriptor for file-backed mappings; -1 for anonymous.
 * @param offset      Offset into the file for file-backed mappings.
 * @return            Address of the new mapping on success, MAP_FAILED on error.
 *                    errno is set on error (either by fault injection or by the
 *                    real syscall).
 */
CHAOS_MEMORY_EXPORT void *
mmap(void *address, size_t length, int protection, int flags, int fd, off_t offset)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_mmap(address, length, protection, flags, fd, offset);
    }

    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MMAP, flags, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MMAP, flags, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        return MAP_FAILED;
    }

    return chaos_memory_call_real_mmap(address, length, protection, flags, fd, offset);
}

/**
 * @brief Interposed munmap(2): inject latency and/or errno faults before the
 *        real unmap operation.
 *
 * @details
 * Follows the standard three-phase hook structure.  The mmap_flags argument to
 * config_match() is passed as 0 because munmap has no mapping-type flags.
 *
 * @par Synthetic failure semantics
 * When an ERRNO rule fires, -1 is returned without calling the real munmap.
 * The mapping remains active in the process address space.  This is the
 * correct simulation of a kernel-level munmap failure (e.g., EINVAL when the
 * address is not page-aligned) and intentionally exercises leak-detection and
 * error-recovery code paths in the target.
 *
 * @param address  Start of the region to unmap (must be page-aligned for the
 *                 real syscall; the injected error path does not validate this).
 * @param length   Length of the region.
 * @return         0 on success, -1 on error (errno set by injection or real syscall).
 */
CHAOS_MEMORY_EXPORT int munmap(void *address, size_t length)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_munmap(address, length);
    }

    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MUNMAP, 0, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MUNMAP, 0, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        /* Synthetic munmap failure intentionally leaves the mapping active. */
        return -1;
    }

    return chaos_memory_call_real_munmap(address, length);
}

/**
 * @brief Interposed mprotect(2): inject latency and/or errno faults before the
 *        real protection-change operation.
 *
 * @details
 * Follows the standard three-phase hook structure.  Common fault modes:
 *  - ERRNO:EACCES — simulates a sealed or execute-protected region.
 *  - ERRNO:EPERM  — simulates seccomp or LSM policy blocking PROT_EXEC.
 *  - LATENCY      — simulates contention on the kernel's mmap_lock.
 *
 * @param address     Start of the region (must be page-aligned for real call).
 * @param length      Length of the region.
 * @param protection  New PROT_* flags.
 * @return            0 on success, -1 on error (errno set by injection or real syscall).
 */
CHAOS_MEMORY_EXPORT int mprotect(void *address, size_t length, int protection)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_mprotect(address, length, protection);
    }

    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MPROTECT, 0, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MPROTECT, 0, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        return -1;
    }

    return chaos_memory_call_real_mprotect(address, length, protection);
}

/**
 * @brief Interposed madvise(2): inject latency and/or errno faults before the
 *        real advisory operation.
 *
 * @details
 * Follows the standard three-phase hook structure.  Common fault modes:
 *  - ERRNO:ENOSYS — simulates a kernel that does not support a given advice
 *    value (e.g., MADV_WIPEONFORK on older kernels).
 *  - ERRNO:EINVAL — simulates an unaligned address or unsupported advice.
 *  - LATENCY      — simulates I/O pressure when MADV_PAGEOUT or MADV_POPULATE_READ
 *    would cause significant kernel work.
 *
 * @param address  Start of the advisory range.
 * @param length   Length of the range.
 * @param advice   MADV_* advice constant.
 * @return         0 on success, -1 on error (errno set by injection or real syscall).
 */
CHAOS_MEMORY_EXPORT int madvise(void *address, size_t length, int advice)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_madvise(address, length, advice);
    }

    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MADVISE, 0, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MADVISE, 0, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        return -1;
    }

    return chaos_memory_call_real_madvise(address, length, advice);
}
