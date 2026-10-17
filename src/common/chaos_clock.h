/**
 * @file chaos_clock.h
 * @brief Clocks that bypass libc (vDSO, raw system call), the rule-file check throttle and
 *        the "racily clean" mtime test.
 *
 * @details
 * Every wrapper asks whether the rule file changed. A `stat()` per call made that check
 * the largest part of a wrapper's cost, so the libraries look at the file at most every
 * CHAOS_CHECK_INTERVAL_NS (1 ms). The throttle needs a clock that is cheap and is not libc
 * `clock_gettime()`: libchaos-time interposes that, and a time rule would then change how
 * often the other libraries see their rules.
 *
 * The kernel maps a vDSO into every process and exports its clock_gettime from there; libc
 * calls the same code. This header locates that symbol once through `AT_SYSINFO_EHDR` and
 * calls it directly: no system call, no PLT, no interposition. Supported: x86_64
 * (`__vdso_clock_gettime`) and aarch64 (`__kernel_clock_gettime`). Without a vDSO, or on
 * another architecture, chaos_clock_now_ns() returns 0 and callers disable the throttle
 * (check on every call); chaos_clock_realtime_ms() falls back to a raw system call.
 *
 * @par Per translation unit
 * The lookup state is `static`, so each translation unit that includes this header does
 * its own one-time lookup; no symbol is shared between libraries.
 *
 * @par Thread and signal safety
 * The lookup never blocks: a caller that meets it in progress (another thread, or a
 * signal handler interrupting the owner) gets NULL and uses the fallback once. After the
 * lookup every read is a plain load plus the vDSO call, which is async-signal-safe.
 *
 * @par Test seams
 * CHAOS_CLOCK_RAW_GETTIME and CHAOS_RACY_WINDOW_MS may be predefined by unit tests.
 */

#ifndef CHAOS_CLOCK_H
#define CHAOS_CLOCK_H

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

/**
 * @brief clock_gettime as a raw system call, bypassing the interposable libc symbol;
 *        returns 0 or -1 with errno. Unit tests may predefine it.
 */
#ifndef CHAOS_CLOCK_RAW_GETTIME
#ifdef __linux__
#define CHAOS_CLOCK_RAW_GETTIME(clock, now) syscall(SYS_clock_gettime, (clock), (now))
#else
#define CHAOS_CLOCK_RAW_GETTIME(clock, now) clock_gettime((clock), (now))
#endif
#endif

/** @brief Signature of the vDSO clock_gettime (same as the libc function). */
typedef int (*chaos_clock_vdso_fn)(clockid_t, struct timespec *);

/** @brief vDSO symbol of clock_gettime on this architecture; NULL disables the vDSO path. */
#if defined(__x86_64__)
#define CHAOS_CLOCK_VDSO_SYMBOL "__vdso_clock_gettime"
#elif defined(__aarch64__)
#define CHAOS_CLOCK_VDSO_SYMBOL "__kernel_clock_gettime"
#else
#define CHAOS_CLOCK_VDSO_SYMBOL NULL
#endif

/**
 * @brief Resolves function symbol @p name in the vDSO image mapped at @p base.
 *
 * @details Minimal ELF walk with no libc involvement: the first PT_LOAD gives the load
 * bias, PT_DYNAMIC the symbol, string and hash tables; the symbol count is DT_HASH's
 * nchain. A vDSO without
 * DT_HASH (GNU hash only) is not searched and yields NULL, which only disables the vDSO
 * path. Symbol versions are ignored; the first defined STT_FUNC with the name wins.
 *
 * @param base  Address of the vDSO ELF header (`getauxval(AT_SYSINFO_EHDR)`); 0 allowed.
 * @param name  Symbol name; NULL allowed.
 * @return The function's address, or NULL when @p base, @p name or the symbol is absent
 *         or the image is not ELF. Always NULL on non-Linux builds.
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

/** @brief The vDSO clock_gettime once looked up; NULL when unavailable or not yet known. */
static chaos_clock_vdso_fn g_chaos_clock_vdso = NULL;

/** @brief Lookup state: 0 not started, 1 in progress, 2 done (g_chaos_clock_vdso is final). */
static volatile int g_chaos_clock_state = 0;

/** @brief Pid that claimed the lookup; lets a forked child spot an orphaned claim. */
static volatile long g_chaos_clock_owner = 0;

/**
 * @brief Performs the lookup and stores the result; run by the caller that claimed state 1.
 *
 * @details memcpy instead of a cast assignment: ISO C has no conversion between object
 * and function pointers, and the copy avoids the pedantic warning.
 */
static void chaos_clock_find_vdso(void)
{
#ifdef __linux__
    void *found =
        chaos_clock_vdso_lookup((uintptr_t)getauxval(AT_SYSINFO_EHDR), CHAOS_CLOCK_VDSO_SYMBOL);

    (void)memcpy(&g_chaos_clock_vdso, &found, sizeof(found));
#endif
}

/**
 * @brief Returns the vDSO clock_gettime, performing the one-time lookup on first use;
 *        NULL while the lookup is in progress elsewhere or when no vDSO clock exists.
 *
 * @details Never waits. A caller that finds the lookup in progress (another thread, or a
 * signal handler interrupting the owner) gets NULL and uses the fallback for this call.
 * A child forked mid-lookup inherits state 1 with an owner pid that is not its own; no
 * thread will finish that lookup in the child, so it resets the claim and takes over.
 *
 * The owner pid is stored after the claim CAS, so another thread of the same process can
 * briefly see a foreign pid and also take over; both then run the same idempotent lookup
 * and store the same pointer, so the race is harmless. The full barrier before state 2
 * publishes g_chaos_clock_vdso to readers that see state 2.
 */
static inline chaos_clock_vdso_fn chaos_clock_vdso(void)
{
    if (g_chaos_clock_state != 2)
    {
        if (g_chaos_clock_state == 1 && g_chaos_clock_owner != (long)getpid())
        {
            (void)__sync_bool_compare_and_swap(&g_chaos_clock_state, 1, 0);
        }
        if (!__sync_bool_compare_and_swap(&g_chaos_clock_state, 0, 1))
        {
            return NULL;
        }
        g_chaos_clock_owner = (long)getpid();
        chaos_clock_find_vdso();
        __sync_synchronize();
        g_chaos_clock_state = 2;
    }
    return g_chaos_clock_vdso;
}

/**
 * @brief CLOCK_MONOTONIC in ns from the vDSO; 0 when no vDSO clock is available (yet).
 *
 * @details No system-call fallback on purpose: callers use 0 to mean "no cheap clock" and
 * then skip the throttle rather than pay a system call per wrapper.
 */
static inline uint64_t chaos_clock_now_ns(void)
{
    struct timespec now;
    const chaos_clock_vdso_fn vdso = chaos_clock_vdso();

    if (vdso == NULL || vdso(CLOCK_MONOTONIC, &now) != 0)
    {
        return 0U;
    }
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

/**
 * @brief CLOCK_REALTIME in ms since the Unix epoch, never through libchaos-time; 0 when no
 *        clock can be read.
 *
 * @details Rule windows (`@from`, `@until`) are wall-clock times so that every process
 * agrees on them. Read from the vDSO, else with a raw system call; never through the
 * interposed clock_gettime, so a time OFFSET rule does not move another rule's window.
 */
static inline int64_t chaos_clock_realtime_ms(void)
{
    struct timespec now;
    const chaos_clock_vdso_fn vdso = chaos_clock_vdso();

    if (vdso == NULL || vdso(CLOCK_REALTIME, &now) != 0)
    {
        if (CHAOS_CLOCK_RAW_GETTIME(CLOCK_REALTIME, &now) != 0)
        {
            return 0;
        }
    }
    return (int64_t)now.tv_sec * 1000 + (int64_t)(now.tv_nsec / 1000000L);
}

/**
 * @brief Window in ms after a rule file's mtime during which a same-size rewrite may go
 *        unseen; unit tests widen it so that a slow machine does not close it under them.
 */
#ifndef CHAOS_RACY_WINDOW_MS
#define CHAOS_RACY_WINDOW_MS 20
#endif

/**
 * @brief Non-zero when mtime @p sec / @p nsec is within CHAOS_RACY_WINDOW_MS of now, so
 *        the file may still change without its change stamp changing.
 *
 * @details File systems take mtime from a coarse clock tick (a few ms). An in-place
 * rewrite with the same size within one tick leaves mtime, size, inode and device
 * unchanged, and the change stamp misses it. A load of a file this recent is therefore
 * provisional: the file is read again on every check until its mtime leaves the window,
 * as git treats "racily clean" index entries. A stamp more than the window in the future
 * (a writer with a skewed clock) is not treated as recent, so it cannot pin the library
 * in re-reading. Returns 0 when the wall clock cannot be read.
 */
static inline int chaos_clock_stamp_is_recent(int64_t sec, long nsec)
{
    const int64_t now = chaos_clock_realtime_ms();
    const int64_t stamp = sec * 1000 + (int64_t)(nsec / 1000000L);

    return now != 0 && now - stamp < CHAOS_RACY_WINDOW_MS && stamp - now < CHAOS_RACY_WINDOW_MS;
}

/** @brief Throttle interval in ns between two rule-file checks of one library (1 ms). */
#define CHAOS_CHECK_INTERVAL_NS UINT64_C(1000000)

/**
 * @brief Throttle test: non-zero when the rule file was checked less than @p interval_ns
 *        ago, so the caller skips the check.
 *
 * @details Unsynchronised by design: concurrent callers may each read a stale @p last
 * and check the file once more than necessary, which is harmless. Without a vDSO clock
 * it always returns 0 (check every time).
 *
 * @param last         Monotonic ns of the last check; set to now when this returns 0.
 * @param interval_ns  Throttle interval in ns; 0 disables the throttle.
 * @return 1 to skip the check, 0 to check now.
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
