/**
 * @file dns_probe.c
 * @brief Runtime validation probe for libchaos-dns under LD_PRELOAD.
 *
 * @details
 * Standalone C program compiled inside a Docker container and executed under
 * `LD_PRELOAD=libchaos-dns.so`. Validates end-to-end fault injection for the
 * DNS library's interposed symbols: `getaddrinfo` and `getnameinfo`.
 *
 * Each subtest writes a config rule with a future-mtime timestamp to
 * `/tmp/.chaos-dns.conf`, then exercises the interposed symbol and asserts the
 * expected behavior. The future-mtime pattern guarantees a config reload cycle
 * on the first post-write invocation, ensuring the new rule is active.
 *
 * Subtests cover:
 * - `EAI_AGAIN` injection on `getaddrinfo` (synthetic transient failure)
 * - `LATENCY` injection on `getaddrinfo` (≥ 150 ms added sleep)
 * - `REWRITE` on `getaddrinfo` (hostname substitution: example.invalid → localhost)
 * - `SERVICE` rewrite on `getaddrinfo` (port override: 80 → 8081)
 * - `OVERRIDE` + `FILTER_FAMILY` + `LIMIT` pipeline (synthetic address list,
 *   IPv4-only, single result)
 * - `EAI_AGAIN` injection on `getnameinfo` (synthetic transient failure)
 * - `LATENCY` injection on `getnameinfo` (≥ 150 ms added sleep)
 * - `REWRITE` + `SERVICE` on `getnameinfo` (PTR hostname and service name override)
 * - the same rules on `gethostbyname`, `gethostbyname2`, their `_r` forms, `gethostbyaddr`
 *   and `gethostbyaddr_r`, which glibc and musl resolve without getaddrinfo/getnameinfo
 *
 * The `OVERRIDE` subtest exercises the full FILTER→SHUFFLE→LIMIT transform
 * pipeline in a single call: the injected address list [127.0.0.1, ::1] is
 * filtered to IPv4-only by `FILTER_FAMILY:inet4`, then trimmed to one result
 * by `LIMIT:1`. All three rules are written as a multi-line config block.
 *
 * Returns 0 on success; returns a non-zero numbered exit code identifying
 * the failing subtest.
 */
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static time_t g_config_stamp = 5000;

static void set_ipv4_address(struct sockaddr_in *address, const char *host, unsigned short port)
{
    (void)memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if (inet_pton(AF_INET, host, &address->sin_addr) != 1)
    {
        abort();
    }
}

static long long elapsed_ms(const struct timespec *start, const struct timespec *end)
{
    long long seconds = (long long)(end->tv_sec - start->tv_sec);
    long long nanos = (long long)(end->tv_nsec - start->tv_nsec);

    return seconds * 1000LL + nanos / 1000000LL;
}

/**
 * @brief Waits until the library is due to look at its rule file again.
 *
 * Once rules are loaded the libraries look at the rule file at most every
 * millisecond, so a change takes effect within that time, not on the very next
 * call. The sleep is a raw system call: libchaos-time may be faulting nanosleep.
 */
static void wait_for_rule_check(void)
{
    struct timespec delay = {0, 2000000L};

    while (syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &delay, &delay) != 0 && errno == EINTR)
    {
    }
}

static int write_config_now(const char *text)
{
    struct timespec times[2];
    FILE *config = fopen("/tmp/.chaos-dns.conf", "w");

    if (config == NULL)
    {
        return 200;
    }
    if (fprintf(config, "%s\n", text) < 0)
    {
        fclose(config);
        return 201;
    }
    if (fflush(config) != 0)
    {
        fclose(config);
        return 202;
    }

    times[0].tv_sec = g_config_stamp++;
    times[0].tv_nsec = 0L;
    times[1] = times[0];
    if (futimens(fileno(config), times) != 0)
    {
        fclose(config);
        return 203;
    }
    if (fclose(config) != 0)
    {
        return 204;
    }

    return 0;
}

/** @brief Writes the rules, then waits until the library looks at them. */
static int write_config(const char *text)
{
    const int rc = write_config_now(text);

    wait_for_rule_check();
    return rc;
}

static int probe_gai_error(void)
{
    int rc = write_config("dns://localhost:EAI_AGAIN:1.0");

    if (rc != 0)
    {
        return rc;
    }
    return getaddrinfo("localhost", NULL, NULL, NULL) == EAI_AGAIN ? 0 : 10;
}

static int probe_latency(void)
{
    struct timespec start;
    struct timespec end;
    struct addrinfo *result = NULL;
    long long duration_ms;
    int rc = write_config("dns://localhost:LATENCY:200");

    if (rc != 0)
    {
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        return 20;
    }
    rc = getaddrinfo("localhost", NULL, NULL, &result);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        if (result != NULL)
        {
            freeaddrinfo(result);
        }
        return 21;
    }
    if (result != NULL)
    {
        freeaddrinfo(result);
    }
    if (rc != 0)
    {
        return 22;
    }
    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 150LL ? 0 : 23;
}

static int probe_rewrite(void)
{
    struct addrinfo *result = NULL;
    int rc = write_config("dns://example.invalid:REWRITE:localhost");

    if (rc != 0)
    {
        return rc;
    }
    rc = getaddrinfo("example.invalid", NULL, NULL, &result);
    if (result != NULL)
    {
        freeaddrinfo(result);
    }
    return rc == 0 ? 0 : 30;
}

static int probe_service_rewrite(void)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int rc = write_config("dns://localhost:SERVICE:8081");

    if (rc != 0)
    {
        return rc;
    }

    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo("localhost", "80", &hints, &result);
    if (rc != 0)
    {
        return 40;
    }
    if (result == NULL || result->ai_addr == NULL || result->ai_family != AF_INET)
    {
        if (result != NULL)
        {
            freeaddrinfo(result);
        }
        return 41;
    }
    if (ntohs(((struct sockaddr_in *)result->ai_addr)->sin_port) != 8081U)
    {
        freeaddrinfo(result);
        return 42;
    }
    freeaddrinfo(result);
    return 0;
}

static int probe_override_filter_limit(void)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int rc = write_config("dns://override.test:OVERRIDE:127.0.0.1,[::1]\n"
                          "dns://override.test:FILTER_FAMILY:inet4\n"
                          "dns://override.test:LIMIT:1");

    if (rc != 0)
    {
        return rc;
    }

    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo("override.test", "8080", &hints, &result);
    if (rc != 0)
    {
        return 50;
    }
    if (result == NULL || result->ai_next != NULL || result->ai_family != AF_INET)
    {
        if (result != NULL)
        {
            freeaddrinfo(result);
        }
        return 51;
    }
    if (ntohs(((struct sockaddr_in *)result->ai_addr)->sin_port) != 8080U)
    {
        freeaddrinfo(result);
        return 52;
    }
    freeaddrinfo(result);
    return 0;
}

/** @brief Resident set size of this process in pages. */
static long resident_pages(void)
{
    long size = 0L;
    long resident = -1L;
    FILE *statm = fopen("/proc/self/statm", "r");

    if (statm != NULL && fscanf(statm, "%ld %ld", &size, &resident) != 2)
    {
        resident = -1L;
    }
    if (statm != NULL)
    {
        (void)fclose(statm);
    }
    return resident;
}

/**
 * @brief OVERRIDE with several literals, shuffled and cut, many times over.
 *
 * musl allocates each getaddrinfo() result as one reference-counted block; a list
 * spliced from several of them leaked on every lookup and, once SHUFFLE and LIMIT
 * reordered and cut it, freed a block still in use. The list is one of the
 * library's own now: the loop must neither crash nor grow. The canonical name
 * is the queried name, on the head, after every shuffle.
 */
static int probe_override_many(void)
{
    struct addrinfo hints;
    long before;
    long after;
    int index;
    int rc = write_config("dns://many.test:OVERRIDE:127.0.0.1,127.0.0.2,[::1]\n"
                          "dns://many.test:SHUFFLE:1.0\n"
                          "dns://many.test:LIMIT:2");

    if (rc != 0)
    {
        return rc;
    }
    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    before = resident_pages();
    for (index = 0; index < 20000; ++index)
    {
        struct addrinfo *result = NULL;

        if (getaddrinfo("many.test", "80", &hints, &result) != 0 || result == NULL ||
            result->ai_next == NULL || result->ai_next->ai_next != NULL ||
            result->ai_canonname == NULL || strcmp(result->ai_canonname, "many.test") != 0)
        {
            return 60;
        }
        freeaddrinfo(result);
    }
    after = resident_pages();
    /* A leak of even one small block per lookup would grow by megabytes. */
    return before > 0L && after - before < 256L ? 0 : 61;
}

static int probe_reverse_gai_error(void)
{
    struct sockaddr_in address;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    int rc = write_config("rdns://127.0.0.1:EAI_AGAIN:1.0");

    if (rc != 0)
    {
        return rc;
    }
    set_ipv4_address(&address, "127.0.0.1", 80U);
    return getnameinfo(
               (const struct sockaddr *)&address,
               (socklen_t)sizeof(address),
               host,
               (socklen_t)sizeof(host),
               service,
               (socklen_t)sizeof(service),
               0
           ) == EAI_AGAIN
               ? 0
               : 60;
}

static int probe_reverse_latency(void)
{
    struct sockaddr_in address;
    struct timespec start;
    struct timespec end;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    long long duration_ms;
    int rc = write_config("rdns://127.0.0.1:LATENCY:200");

    if (rc != 0)
    {
        return rc;
    }
    set_ipv4_address(&address, "127.0.0.1", 80U);
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        return 61;
    }
    rc = getnameinfo(
        (const struct sockaddr *)&address,
        (socklen_t)sizeof(address),
        host,
        (socklen_t)sizeof(host),
        service,
        (socklen_t)sizeof(service),
        0
    );
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        return 62;
    }
    if (rc != 0)
    {
        return 63;
    }
    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 150LL ? 0 : 64;
}

static int probe_reverse_rewrite_service(void)
{
    struct sockaddr_in address;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    int rc = write_config("rdns://127.0.0.1:REWRITE:ptr.example\n"
                          "rdns://127.0.0.1:SERVICE:redis");

    if (rc != 0)
    {
        return rc;
    }
    set_ipv4_address(&address, "127.0.0.1", 80U);
    rc = getnameinfo(
        (const struct sockaddr *)&address,
        (socklen_t)sizeof(address),
        host,
        (socklen_t)sizeof(host),
        service,
        (socklen_t)sizeof(service),
        0
    );
    if (rc != 0)
    {
        return 65;
    }
    if (strcmp(host, "ptr.example") != 0)
    {
        return 66;
    }
    if (strcmp(service, "redis") != 0)
    {
        return 67;
    }
    return 0;
}

/*
 * The legacy hostent resolvers follow the same dns:// and rdns:// rules as
 * getaddrinfo() and getnameinfo(): a GAI error becomes h_errno, OVERRIDE supplies
 * the addresses, REWRITE replaces the reverse name.
 */
static int probe_hostent_resolvers(void)
{
    struct hostent entry;
    struct hostent *result;
    struct in_addr loopback;
    char buffer[1024];
    char text[INET_ADDRSTRLEN];
    int h_error = 0;
    int rc = write_config("dns://localhost:EAI_NONAME:1.0");

    if (rc != 0)
    {
        return rc;
    }
    if (gethostbyname("localhost") != NULL || h_errno != HOST_NOT_FOUND)
    {
        return 400;
    }
    if (gethostbyname_r("localhost", &entry, buffer, sizeof(buffer), &result, &h_error) != 0 ||
        result != NULL || h_error != HOST_NOT_FOUND)
    {
        return 401;
    }

    rc = write_config("dns://override.test:OVERRIDE:10.20.30.40");
    if (rc != 0)
    {
        return rc;
    }
    result = gethostbyname2("override.test", AF_INET);
    if (result == NULL || result->h_addrtype != AF_INET || result->h_addr_list[0] == NULL ||
        inet_ntop(AF_INET, result->h_addr_list[0], text, sizeof(text)) == NULL ||
        strcmp(text, "10.20.30.40") != 0 || result->h_addr_list[1] != NULL)
    {
        return 402;
    }
    if (gethostbyname2_r(
            "override.test", AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error
        ) != 0 ||
        result == NULL || inet_ntop(AF_INET, result->h_addr_list[0], text, sizeof(text)) == NULL ||
        strcmp(text, "10.20.30.40") != 0)
    {
        return 403;
    }

    rc = write_config("rdns://127.0.0.1:REWRITE:ptr.example");
    if (rc != 0)
    {
        return rc;
    }
    loopback.s_addr = htonl(INADDR_LOOPBACK);
    result = gethostbyaddr(&loopback, sizeof(loopback), AF_INET);
    if (result == NULL || strcmp(result->h_name, "ptr.example") != 0)
    {
        return 404;
    }
    if (gethostbyaddr_r(
            &loopback, sizeof(loopback), AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error
        ) != 0 ||
        result == NULL || strcmp(result->h_name, "ptr.example") != 0)
    {
        return 405;
    }

    rc = write_config("# clear");
    if (rc != 0)
    {
        return rc;
    }
    result = gethostbyname("localhost");
    return result != NULL && result->h_addrtype == AF_INET ? 0 : 406;
}

int main(void)
{
    int rc;

    rc = probe_gai_error();
    if (rc != 0)
        return rc;
    rc = probe_latency();
    if (rc != 0)
        return rc;
    rc = probe_rewrite();
    if (rc != 0)
        return rc;
    rc = probe_service_rewrite();
    if (rc != 0)
        return rc;
    rc = probe_override_filter_limit();
    if (rc != 0)
        return rc;
    rc = probe_override_many();
    if (rc != 0)
        return rc;
    rc = probe_reverse_gai_error();
    if (rc != 0)
        return rc;
    rc = probe_reverse_latency();
    if (rc != 0)
        return rc;
    rc = probe_reverse_rewrite_service();
    if (rc != 0)
        return rc;
    rc = probe_hostent_resolvers();
    if (rc != 0)
        return rc;
    return 0;
}
