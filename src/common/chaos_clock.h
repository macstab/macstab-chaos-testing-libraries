/**
 * @file chaos_clock.h
 * @brief A monotonic clock read straight from the kernel's vDSO.
 *
 * @details
 * Every intercepted call asks whether the rule file changed. Answering with a
 * `stat()` each time made that check the largest part of a wrapper's cost. The
 * libraries now look at the file at most every CHAOS_CHECK_INTERVAL_NS and need a
 * clock to know when; it must be cheap, and it must not be `clock_gettime()` from
 * the C library, which libchaos-time interposes (a time rule would then change how
 * often the other libraries see their rules).
 *
 * The kernel maps a vDSO into every process and exports its clock_gettime from
 * there; the C library's own clock_gettime calls the same code. This header finds
 * that symbol once through the auxiliary vector and calls it directly: no system
 * call, no PLT, no interposition. Where there is no vDSO (or no known symbol for
 * the architecture) chaos_clock_now_ns() returns 0 and the callers check the file
 * on every call, as before.
 */

#ifndef CHAOS_CLOCK_H
#define CHAOS_CLOCK_H

#include "chaos_once.h"

#include <stdint.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include <elf.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

/** @brief Signature of the vDSO clock_gettime. */
typedef int (*chaos_clock_vdso_fn)(clockid_t, struct timespec *);

/** @brief Name of the vDSO clock_gettime on this architecture, or NULL. */
#if defined(__x86_64__)
#define CHAOS_CLOCK_VDSO_SYMBOL "__vdso_clock_gettime"
#elif defined(__aarch64__)
#define CHAOS_CLOCK_VDSO_SYMBOL "__kernel_clock_gettime"
#else
#define CHAOS_CLOCK_VDSO_SYMBOL NULL
#endif

/**
 * @brief Looks up @p name in the vDSO mapped at @p base; NULL when absent.
 *
 * @details Walks the vDSO's program headers for its load bias and dynamic section,
 * then its symbol table, sized by the DT_HASH chain count. A vDSO without DT_HASH
 * (none of the kernels we support) yields NULL, which only disables the throttle.
 */
static inline void *chaos_clock_vdso_lookup(uintptr_t base, const char *name)
{
#ifdef __linux__
    const ElfW(Ehdr) *header = (const ElfW(Ehdr) *)base;
    const ElfW(Phdr) * program;
    const ElfW(Dyn) *dynamic = NULL;
    const ElfW(Sym) *symbols = NULL;
    const char *strings = NULL;
    const uint32_t *hash = NULL;
    uintptr_t bias = 0U;
    int have_load = 0;
    uint32_t index;
    int segment;

    if (base == 0U || name == NULL || memcmp(header->e_ident, ELFMAG, SELFMAG) != 0)
    {
        return NULL;
    }
    program = (const ElfW(Phdr) *)(base + header->e_phoff);
    for (segment = 0; segment < header->e_phnum; ++segment)
    {
        if (program[segment].p_type == PT_LOAD && !have_load)
        {
            bias =
                base + (uintptr_t)program[segment].p_offset - (uintptr_t)program[segment].p_vaddr;
            have_load = 1;
        }
        else if (program[segment].p_type == PT_DYNAMIC)
        {
            dynamic = (const ElfW(Dyn) *)(base + program[segment].p_offset);
        }
    }
    if (!have_load || dynamic == NULL)
    {
        return NULL;
    }
    for (; dynamic->d_tag != DT_NULL; ++dynamic)
    {
        switch (dynamic->d_tag)
        {
        case DT_SYMTAB:
            symbols = (const ElfW(Sym) *)(bias + dynamic->d_un.d_ptr);
            break;
        case DT_STRTAB:
            strings = (const char *)(bias + dynamic->d_un.d_ptr);
            break;
        case DT_HASH:
            hash = (const uint32_t *)(bias + dynamic->d_un.d_ptr);
            break;
        default:
            break;
        }
    }
    if (symbols == NULL || strings == NULL || hash == NULL)
    {
        return NULL;
    }
    for (index = 0U; index < hash[1]; ++index)
    {
        const ElfW(Sym) *symbol = &symbols[index];

        if (ELF64_ST_TYPE(symbol->st_info) == STT_FUNC && symbol->st_shndx != SHN_UNDEF &&
            strcmp(strings + symbol->st_name, name) == 0)
        {
            return (void *)(bias + symbol->st_value);
        }
    }
#else
    (void)base;
    (void)name;
#endif
    return NULL;
}

/** @brief The vDSO clock, found once per process; NULL when unavailable. */
static chaos_clock_vdso_fn g_chaos_clock_vdso = NULL;

/** @brief Guards the one lookup. */
static chaos_once_t g_chaos_clock_once = CHAOS_ONCE_INIT;

/** @brief Finds the vDSO clock; run once through chaos_once(). */
static void chaos_clock_find_vdso(void)
{
#ifdef __linux__
    void *found =
        chaos_clock_vdso_lookup((uintptr_t)getauxval(AT_SYSINFO_EHDR), CHAOS_CLOCK_VDSO_SYMBOL);

    (void)memcpy(&g_chaos_clock_vdso, &found, sizeof(found));
#endif
}

/**
 * @brief CLOCK_MONOTONIC in nanoseconds from the vDSO; 0 when there is no vDSO clock.
 */
static inline uint64_t chaos_clock_now_ns(void)
{
    struct timespec now;

    chaos_once(&g_chaos_clock_once, chaos_clock_find_vdso);
    if (g_chaos_clock_vdso == NULL || g_chaos_clock_vdso(CLOCK_MONOTONIC, &now) != 0)
    {
        return 0U;
    }
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

/**
 * @brief CLOCK_REALTIME in milliseconds since the epoch, without libchaos-time.
 *
 * @details Rule windows (`@from=`, `@until=`) are wall-clock times so that every
 * process of a container agrees on them. The time is read from the vDSO, or with
 * a raw system call where there is no vDSO clock: never through the interposed
 * clock_gettime, so a time OFFSET rule does not move another rule's window.
 */
static inline int64_t chaos_clock_realtime_ms(void)
{
    struct timespec now;

    chaos_once(&g_chaos_clock_once, chaos_clock_find_vdso);
    if (g_chaos_clock_vdso == NULL || g_chaos_clock_vdso(CLOCK_REALTIME, &now) != 0)
    {
#ifdef __linux__
        if (syscall(SYS_clock_gettime, CLOCK_REALTIME, &now) != 0)
#else
        if (clock_gettime(CLOCK_REALTIME, &now) != 0)
#endif
        {
            return 0;
        }
    }
    return (int64_t)now.tv_sec * 1000 + (int64_t)(now.tv_nsec / 1000000L);
}

/** @brief Longest a library goes without looking at its rule file. */
#define CHAOS_CHECK_INTERVAL_NS UINT64_C(1000000)

/**
 * @brief Whether the rule file was looked at less than @p interval_ns ago.
 *
 * @param last         Time of the last look, updated when this returns 0.
 * @param interval_ns  Throttle interval; 0 disables the throttle.
 * @return 1 to skip the look this time, 0 to look now.
 */
static inline int chaos_clock_checked_recently(volatile uint64_t *last, uint64_t interval_ns)
{
    uint64_t now;

    if (interval_ns == 0U)
    {
        return 0;
    }
    now = chaos_clock_now_ns();
    if (now == 0U)
    {
        return 0;
    }
    if (now - *last < interval_ns)
    {
        return 1;
    }
    *last = now;
    return 0;
}

#endif
