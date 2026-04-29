#ifndef CHAOS_DNS_INTERNAL_H
#define CHAOS_DNS_INTERNAL_H

#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#define CHAOS_DNS_CONFIG_PATH "/tmp/.chaos-dns.conf"
#define CHAOS_DNS_MAX_RULES 256U
#define CHAOS_DNS_MAX_LINE_LENGTH 1024U
#define CHAOS_DNS_MAX_CONFIG_BYTES (CHAOS_DNS_MAX_RULES * CHAOS_DNS_MAX_LINE_LENGTH)
#define CHAOS_DNS_MAX_TEXT 256U
#define CHAOS_DNS_MAX_VALUE 512U

#define CHAOS_DNS_EXPORT __attribute__((visibility("default")))

#define CHAOS_DNS_MTIME_MISSING UINT64_C(0)
#define CHAOS_DNS_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)
#define CHAOS_DNS_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

typedef int (*chaos_dns_getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef int (*chaos_dns_getnameinfo_fn)(
    const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int
);
typedef void (*chaos_dns_freeaddrinfo_fn)(struct addrinfo *);

extern chaos_dns_getaddrinfo_fn g_chaos_dns_real_getaddrinfo;
extern chaos_dns_getnameinfo_fn g_chaos_dns_real_getnameinfo;
extern chaos_dns_freeaddrinfo_fn g_chaos_dns_real_freeaddrinfo;

extern __thread int g_chaos_dns_tls_guard;
extern __thread uint64_t g_chaos_dns_tls_prng_state;
extern uint64_t g_chaos_dns_process_seed;

static inline int chaos_dns_in_internal(void)
{
    return g_chaos_dns_tls_guard != 0;
}

static inline int chaos_dns_enter_internal(void)
{
    int previous = g_chaos_dns_tls_guard;
    g_chaos_dns_tls_guard = 1;
    return previous;
}

static inline void chaos_dns_leave_internal(int previous)
{
    g_chaos_dns_tls_guard = previous;
}

static inline uint64_t chaos_dns_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

static inline int
chaos_dns_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

static inline uint64_t chaos_dns_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

static inline uint64_t chaos_dns_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static inline void chaos_dns_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_dns_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_dns_process_seed;
    seed ^= chaos_dns_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_dns_tls_prng_state = chaos_dns_prng_mix(seed);
    if (g_chaos_dns_tls_prng_state == 0U)
    {
        g_chaos_dns_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

static inline void chaos_dns_prng_seed_thread(uint64_t seed)
{
    g_chaos_dns_tls_prng_state = chaos_dns_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

static inline uint32_t chaos_dns_prng_next_u32(void)
{
    uint64_t state;

    chaos_dns_prng_ensure_seeded();
    state = g_chaos_dns_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_dns_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

#endif
