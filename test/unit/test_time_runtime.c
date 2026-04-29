#include "../support/test_time_support.h"

#include "../../src/time/chaos_time_config.h"

#include <setjmp.h>
#include <stdarg.h>

static int g_config_init_calls = 0;
static int g_dlerror_calls = 0;
static const char *g_dlerror_text = NULL;
static jmp_buf g_abort_env;
static int g_expect_abort = 0;
#ifdef __linux__
static int g_syscall_open_calls = 0;
static int g_syscall_read_calls = 0;
static int g_syscall_close_calls = 0;
static int g_force_open_fail = 0;
static int g_force_short_read = 0;
#endif

static void reset_test_state(void)
{
    chaos_time_test_reset_runtime();
    g_config_init_calls = 0;
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

static int stub_clock_gettime(clockid_t clock_id, struct timespec *value)
{
    (void)clock_id;
    (void)value;
    return 0;
}

static int stub_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    (void)request;
    (void)remaining;
    return 0;
}

static int stub_usleep(useconds_t usec)
{
    (void)usec;
    return 0;
}

void chaos_time_config_init(void)
{
    ++g_config_init_calls;
}

static char *chaos_time_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

static void *chaos_time_test_dlsym(void *handle, const char *symbol)
{
    (void)handle;

    if (strcmp(symbol, "clock_gettime") == 0)
        return CHAOS_TIME_TEST_DLSYM_RESULT(chaos_time_clock_gettime_fn, stub_clock_gettime);
    if (strcmp(symbol, "nanosleep") == 0)
        return CHAOS_TIME_TEST_DLSYM_RESULT(chaos_time_nanosleep_fn, stub_nanosleep);
    if (strcmp(symbol, "usleep") == 0)
        return CHAOS_TIME_TEST_DLSYM_RESULT(chaos_time_usleep_fn, stub_usleep);
    return NULL;
}

#ifdef __linux__
static long chaos_time_test_syscall(long number, ...)
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

static void chaos_time_test_abort(void)
{
    if (g_expect_abort != 0)
    {
        longjmp(g_abort_env, 1);
    }
    assert(!"unexpected abort");
}

#define dlsym chaos_time_test_dlsym
#define dlerror chaos_time_test_dlerror
#define abort chaos_time_test_abort
#ifdef __linux__
#define syscall chaos_time_test_syscall
#endif
#include "../../src/time/chaos_time.c"
#ifdef __linux__
#undef syscall
#endif
#undef abort
#undef dlerror
#undef dlsym

static void test_resolve_symbol_and_seed_helpers(void)
{
    chaos_time_clock_gettime_fn clock_gettime_fn = NULL;

    reset_test_state();
    chaos_time_resolve_symbol(&clock_gettime_fn, "clock_gettime");
    assert(clock_gettime_fn == stub_clock_gettime);
    assert(g_dlerror_calls == 1);

#ifdef __linux__
    assert(chaos_time_read_seed_material() == UINT64_C(0x1122334455667788));
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
#else
    assert(chaos_time_read_seed_material() != 0U);
#endif
}

static void test_resolve_symbol_abort_path(void)
{
    chaos_time_clock_gettime_fn clock_gettime_fn = NULL;

    reset_test_state();
    g_dlerror_text = "missing";
    g_expect_abort = 1;
    if (setjmp(g_abort_env) == 0)
    {
        chaos_time_resolve_symbol(&clock_gettime_fn, "missing-symbol");
        assert(0 && "expected abort path");
    }
    g_expect_abort = 0;
}

#ifdef __linux__
static void test_seed_fallback_paths(void)
{
    uint64_t fallback = UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();

    reset_test_state();
    g_force_open_fail = 1;
    assert(chaos_time_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 0);
    assert(g_syscall_close_calls == 0);

    reset_test_state();
    g_force_short_read = 1;
    assert(chaos_time_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
}
#endif

static void test_constructor_init(void)
{
    int config_calls_before;

    reset_test_state();
    config_calls_before = g_config_init_calls;
    chaos_time_init();
    assert(g_chaos_time_real_clock_gettime == stub_clock_gettime);
    assert(g_chaos_time_real_nanosleep == stub_nanosleep);
    assert(g_chaos_time_real_usleep == stub_usleep);
    assert(g_config_init_calls == config_calls_before + 1);
    assert(g_chaos_time_process_seed != 0U);
    assert(g_chaos_time_tls_prng_state != 0U);
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
