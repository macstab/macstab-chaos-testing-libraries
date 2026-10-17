/**
 * @file test_memory_runtime.c
 * @brief Proves the libchaos-memory constructor: symbol resolution, seeding and start-up load.
 *
 * @details
 * Unit under test: `src/memory/chaos_memory.c`, compiled into this binary by `#include` with
 * `dlsym`, `dlerror`, `abort` and (Linux) `syscall` redefined to local stubs, so the constructor
 * runs without LD_PRELOAD and every outcome is observable.
 *
 * Seams:
 * - `dlsym` maps mmap, munmap, mprotect, madvise and posix_madvise to local stubs and returns
 *   NULL for any other name; `dlerror` returns a configurable string and counts calls.
 * - `syscall` serves the raw openat/read/close used to read `/dev/urandom`, returns the seed
 *   0x1122334455667788, and can fail the open or return a 7-byte short read.
 * - `abort` longjmps back into the test when an abort is expected and fails an assertion
 *   otherwise, so the fatal path is testable in-process.
 * - chaos_memory_config_init() and chaos_memory_config_prepare() are counting stubs.
 *
 * `CHAOS_MEMORY_CONSTRUCTOR` is left at its default, so chaos_memory_init() already ran once
 * against these stubs before main(). Each test therefore resets the counters, and the
 * constructor test also resets the run-once state of symbol resolution.
 *
 * Not covered here: the wrappers (test_chaos_memory.c) and rule loading (test_memory_config.c).
 */

#include "../support/test_memory_support.h"

#include "../../src/memory/chaos_memory_config.h"

#include <setjmp.h>
#include <stdarg.h>

/** @brief Calls of the chaos_memory_config_init() stub since the last reset. */
static int g_config_init_calls = 0;

/** @brief Calls of the chaos_memory_config_prepare() stub since the last reset. */
static int g_config_prepare_calls = 0;
/** @brief Calls of the `dlerror` stub; the resolver clears dlerror once per lookup. */
static int g_dlerror_calls = 0;
/** @brief What the `dlerror` stub returns; non-NULL makes a failed lookup fatal. */
static const char *g_dlerror_text = NULL;
/** @brief Where the `abort` stub returns to when an abort is expected. */
static jmp_buf g_abort_env;
/** @brief Non-zero while an abort is expected; any other abort fails the test. */
static int g_expect_abort = 0;
#ifdef __linux__
/** @brief Raw SYS_openat calls. */
static int g_syscall_open_calls = 0;
/** @brief Raw SYS_read calls. */
static int g_syscall_read_calls = 0;
/** @brief Raw SYS_close calls. */
static int g_syscall_close_calls = 0;
/** @brief Non-zero: SYS_openat fails with -1, as without `/dev/urandom`. */
static int g_force_open_fail = 0;
/** @brief Non-zero: SYS_read returns 7 of the 8 seed bytes. */
static int g_force_short_read = 0;
#endif

/** @brief Clears every counter and failure switch and the memory runtime globals. */
static void reset_test_state(void)
{
    chaos_memory_test_reset_runtime();
    g_config_init_calls = 0;
    g_config_prepare_calls = 0;
    g_dlerror_calls = 0;
    g_dlerror_text = NULL;
    g_expect_abort = 0;
#ifdef __linux__
    g_syscall_open_calls = 0;
    g_syscall_read_calls = 0;
    g_syscall_close_calls = 0;
    g_force_open_fail = 0;
    g_force_short_read = 0;
#endif
}

/* -------------------------------------------------------------------------
 * Real-function stubs: dlsym hands these out so the test can compare pointers
 * --------------------------------------------------------------------- */

/** @brief mmap stub: a page-aligned address that is neither NULL nor MAP_FAILED. */
static void *
stub_mmap(void *address, size_t length, int protection, int flags, int fd, off_t offset)
{
    (void)address;
    (void)length;
    (void)protection;
    (void)flags;
    (void)fd;
    (void)offset;
    return (void *)(uintptr_t)0x12345000U;
}

/** @brief munmap stub: succeeds. */
static int stub_munmap(void *address, size_t length)
{
    (void)address;
    (void)length;
    return 0;
}

/** @brief mprotect stub: succeeds. */
static int stub_mprotect(void *address, size_t length, int protection)
{
    (void)address;
    (void)length;
    (void)protection;
    return 0;
}

/** @brief posix_madvise stub: succeeds. */
static int stub_posix_madvise(void *address, size_t length, int advice)
{
    (void)address;
    (void)length;
    (void)advice;
    return 0;
}

/** @brief madvise stub: succeeds. */
static int stub_madvise(void *address, size_t length, int advice)
{
    (void)address;
    (void)length;
    (void)advice;
    return 0;
}

/** @brief Replaces the config subsystem's init so the constructor's call can be counted. */
void chaos_memory_config_init(void)
{
    ++g_config_init_calls;
}

/** @brief Replaces the rule load so the constructor's start-up load can be counted. */
int chaos_memory_config_prepare(void)
{
    ++g_config_prepare_calls;
    return 0;
}

/**
 * @brief `dlerror` seam: returns `g_dlerror_text` and counts calls.
 *
 * @details The resolver calls dlerror once to clear it before dlsym, and a second time only when
 * dlsym returned NULL, so the count shows whether a lookup happened and whether it failed.
 */
static char *chaos_memory_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

/**
 * @brief `dlsym` seam: resolves the five wrapped names to the stubs above, anything else to NULL.
 */
static void *chaos_memory_test_dlsym(void *handle, const char *symbol)
{
    (void)handle;

    if (strcmp(symbol, "mmap") == 0)
        return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_mmap_fn, stub_mmap);
    if (strcmp(symbol, "munmap") == 0)
        return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_munmap_fn, stub_munmap);
    if (strcmp(symbol, "mprotect") == 0)
        return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_mprotect_fn, stub_mprotect);
    if (strcmp(symbol, "madvise") == 0)
        return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_madvise_fn, stub_madvise);
    if (strcmp(symbol, "posix_madvise") == 0)
        return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_posix_madvise_fn, stub_posix_madvise);
    return NULL;
}

#ifdef __linux__
/**
 * @brief `syscall` seam for the raw `/dev/urandom` read.
 *
 * @details openat returns fd 9 (or -1 under `g_force_open_fail`). read asserts it receives fd 9
 * and an 8-byte buffer, fills it with 0x1122334455667788 and returns 8 (or 7 under
 * `g_force_short_read`). close succeeds. Any other number fails with -1.
 */
static long chaos_memory_test_syscall(long number, ...)
{
    if (number == SYS_openat)
    {
        ++g_syscall_open_calls;
        if (g_force_open_fail != 0)
        {
            return -1;
        }
        return 9;
    }
    if (number == SYS_read)
    {
        va_list args;
        int fd;
        void *buffer;
        size_t size;
        uint64_t seed = UINT64_C(0x1122334455667788);

        ++g_syscall_read_calls;
        va_start(args, number);
        fd = va_arg(args, int);
        buffer = va_arg(args, void *);
        size = va_arg(args, size_t);
        va_end(args);
        assert(fd == 9);
        assert(size == sizeof(seed));
        (void)memcpy(buffer, &seed, sizeof(seed));
        if (g_force_short_read != 0)
        {
            return (long)(sizeof(seed) - 1U);
        }
        return (long)sizeof(seed);
    }
    if (number == SYS_close)
    {
        ++g_syscall_close_calls;
        return 0;
    }

    return -1;
}
#endif

/**
 * @brief `abort` seam: longjmps to `g_abort_env` when expected, otherwise fails an assertion.
 */
static void chaos_memory_test_abort(void)
{
    if (g_expect_abort != 0)
    {
        longjmp(g_abort_env, 1);
    }
    assert(!"unexpected abort");
}

/* -------------------------------------------------------------------------
 * The redefinitions apply only to the included unit and are undone right after it
 * --------------------------------------------------------------------- */

#define dlsym chaos_memory_test_dlsym
#define dlerror chaos_memory_test_dlerror
#define abort chaos_memory_test_abort
#ifdef __linux__
#define syscall chaos_memory_test_syscall
#endif
#include "../../src/memory/chaos_memory.c"
#ifdef __linux__
#undef syscall
#endif
#undef abort
#undef dlerror
#undef dlsym

/* -------------------------------------------------------------------------
 * Tests
 * --------------------------------------------------------------------- */

/**
 * @brief Proves resolution fills an empty slot once and never replaces a wired one, and that the
 *        seed comes from `/dev/urandom`.
 *
 * @details
 * - An empty slot gets the dlsym result after exactly one dlerror call (the clear).
 * - A wired slot is returned before any lookup, even for a name dlsym cannot resolve: dlerror
 *   stays at 1. This is what lets a harness pre-wire pointers.
 * - Linux: the seed is the 8 bytes read through one raw openat, read and close; libc I/O is
 *   avoided because it can allocate through mmap during the constructor. Elsewhere only a
 *   non-zero seed is required.
 */
static void test_resolve_symbol_and_seed_helpers(void)
{
    chaos_memory_mmap_fn mmap_fn = NULL;

    reset_test_state();
    chaos_memory_resolve_symbol(&mmap_fn, "mmap");
    assert(mmap_fn == stub_mmap);
    assert(g_dlerror_calls == 1);

    chaos_memory_resolve_symbol(&mmap_fn, "missing-symbol");
    assert(mmap_fn == stub_mmap);
    assert(g_dlerror_calls == 1);

#ifdef __linux__
    assert(chaos_memory_read_seed_material() == UINT64_C(0x1122334455667788));
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
#else
    assert(chaos_memory_read_seed_material() != 0U);
#endif
}

/**
 * @brief Proves a symbol that dlsym cannot resolve, with dlerror reporting an error, aborts.
 *
 * @details The library fails closed: running without a real mmap would crash later and less
 * legibly. The assertion after the call is reached only if the resolver returns instead.
 */
static void test_resolve_symbol_abort_path(void)
{
    chaos_memory_mmap_fn mmap_fn = NULL;

    reset_test_state();
    g_dlerror_text = "missing";
    g_expect_abort = 1;
    if (setjmp(g_abort_env) == 0)
    {
        chaos_memory_resolve_symbol(&mmap_fn, "missing-symbol");
        assert(0 && "expected abort path");
    }
    g_expect_abort = 0;
}

#ifdef __linux__
/**
 * @brief Proves both `/dev/urandom` failures fall back to `0x6a09e667f3bcc909 ^ getpid()`.
 *
 * @details A failed open issues no read and no close. A short read still closes the fd, so the
 * fallback leaks no descriptor, and the partial bytes are discarded rather than used.
 */
static void test_seed_fallback_paths(void)
{
    uint64_t fallback = UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();

    reset_test_state();
    g_force_open_fail = 1;
    assert(chaos_memory_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 0);
    assert(g_syscall_close_calls == 0);

    reset_test_state();
    g_force_short_read = 1;
    assert(chaos_memory_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
}
#endif

/**
 * @brief Proves the constructor wires all five real functions, seeds the process and the calling
 *        thread, initialises the config subsystem and loads the rules once.
 *
 * @details The run-once state is reset because the constructor already ran before main(); without
 * that, chaos_memory_ensure_symbols() would skip resolution and the NULLed pointers would stay
 * NULL. The start-up load exists so a bad rule file is reported when the process starts, not on
 * its first mmap.
 */
static void test_constructor_init(void)
{
    int config_calls_before;
    int prepare_calls_before;

    reset_test_state();
    config_calls_before = g_config_init_calls;
    prepare_calls_before = g_config_prepare_calls;
    g_chaos_memory_symbols_once = CHAOS_ONCE_INIT;
    chaos_memory_init();
    assert(g_chaos_memory_real_mmap == stub_mmap);
    assert(g_chaos_memory_real_munmap == stub_munmap);
    assert(g_chaos_memory_real_mprotect == stub_mprotect);
    assert(g_chaos_memory_real_madvise == stub_madvise);
    assert(g_chaos_memory_real_posix_madvise == stub_posix_madvise);
    assert(g_config_init_calls == config_calls_before + 1);
    assert(g_config_prepare_calls == prepare_calls_before + 1);
    assert(g_chaos_memory_process_seed != 0U);
    assert(g_chaos_memory_tls_prng_state != 0U);
}

int main(void)
{
    test_resolve_symbol_and_seed_helpers();
    test_resolve_symbol_abort_path();
#ifdef __linux__
    test_seed_fallback_paths();
#endif
    test_constructor_init();
    return 0;
}
