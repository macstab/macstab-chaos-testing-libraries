#include "../support/test_dns_support.h"

#include "../../src/dns/chaos_dns_config.h"

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
    chaos_dns_test_reset_runtime();
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

static int stub_getaddrinfo(
    const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result
)
{
    (void)node;
    (void)service;
    (void)hints;
    (void)result;
    return 0;
}

static int stub_getnameinfo(
    const struct sockaddr *address,
    socklen_t address_len,
    char *host,
    socklen_t host_len,
    char *service,
    socklen_t service_len,
    int flags
)
{
    (void)address;
    (void)address_len;
    (void)host;
    (void)host_len;
    (void)service;
    (void)service_len;
    (void)flags;
    return 0;
}

static void stub_freeaddrinfo(struct addrinfo *result)
{
    (void)result;
}

void chaos_dns_config_init(void)
{
    ++g_config_init_calls;
}

static char *chaos_dns_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

static void *chaos_dns_test_dlsym(void *handle, const char *symbol)
{
    (void)handle;

    if (strcmp(symbol, "getaddrinfo") == 0)
        return CHAOS_DNS_TEST_DLSYM_RESULT(chaos_dns_getaddrinfo_fn, stub_getaddrinfo);
    if (strcmp(symbol, "getnameinfo") == 0)
        return CHAOS_DNS_TEST_DLSYM_RESULT(chaos_dns_getnameinfo_fn, stub_getnameinfo);
    if (strcmp(symbol, "freeaddrinfo") == 0)
        return CHAOS_DNS_TEST_DLSYM_RESULT(chaos_dns_freeaddrinfo_fn, stub_freeaddrinfo);
    return NULL;
}

#ifdef __linux__
static long chaos_dns_test_syscall(long number, ...)
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

static void chaos_dns_test_abort(void)
{
    if (g_expect_abort != 0)
    {
        longjmp(g_abort_env, 1);
    }
    assert(!"unexpected abort");
}

#define dlsym chaos_dns_test_dlsym
#define dlerror chaos_dns_test_dlerror
#define abort chaos_dns_test_abort
#ifdef __linux__
#define syscall chaos_dns_test_syscall
#endif
#include "../../src/dns/chaos_dns.c"
#ifdef __linux__
#undef syscall
#endif
#undef abort
#undef dlerror
#undef dlsym

static void test_resolve_symbol_and_seed_helpers(void)
{
    chaos_dns_getaddrinfo_fn getaddrinfo_fn = NULL;

    reset_test_state();
    chaos_dns_resolve_symbol(&getaddrinfo_fn, "getaddrinfo");
    assert(getaddrinfo_fn == stub_getaddrinfo);
    assert(g_dlerror_calls == 1);

#ifdef __linux__
    assert(chaos_dns_read_seed_material() == UINT64_C(0x1122334455667788));
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
#else
    assert(chaos_dns_read_seed_material() != 0U);
#endif
}

static void test_resolve_symbol_abort_path(void)
{
    chaos_dns_getaddrinfo_fn getaddrinfo_fn = NULL;

    reset_test_state();
    g_dlerror_text = "missing";
    g_expect_abort = 1;
    if (setjmp(g_abort_env) == 0)
    {
        chaos_dns_resolve_symbol(&getaddrinfo_fn, "missing-symbol");
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
    assert(chaos_dns_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 0);
    assert(g_syscall_close_calls == 0);

    reset_test_state();
    g_force_short_read = 1;
    assert(chaos_dns_read_seed_material() == fallback);
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
    chaos_dns_init();
    assert(g_chaos_dns_real_getaddrinfo == stub_getaddrinfo);
    assert(g_chaos_dns_real_getnameinfo == stub_getnameinfo);
    assert(g_chaos_dns_real_freeaddrinfo == stub_freeaddrinfo);
    assert(g_config_init_calls == config_calls_before + 1);
    assert(g_chaos_dns_process_seed != 0U);
    assert(g_chaos_dns_tls_prng_state != 0U);
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
