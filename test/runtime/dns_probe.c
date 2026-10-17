/**
 * @file dns_probe.c
 * @brief End-to-end probe for libchaos-dns in LD_PRELOAD mode on glibc and musl.
 *
 * @details
 * Proves that `dns://<host>` and `rdns://<address>` rules in the rule file
 * `/tmp/.chaos-dns.conf` reach forward and reverse resolution, including the legacy hostent
 * API. No network is needed: every name is localhost, a literal or an OVERRIDE. Exit code of
 * each check, its rule, and the behaviour proven:
 *
 * - 10      dns://localhost GAI EAI_AGAIN; getaddrinfo returns EAI_AGAIN.
 * - 20-23   dns://localhost LATENCY:200; getaddrinfo succeeds and takes >= 150 ms.
 * - 30      dns://example.invalid REWRITE:localhost; an unresolvable name resolves.
 * - 40-42   dns://localhost SERVICE:8081; service "80" comes back as port 8081.
 * - 50-52   OVERRIDE 127.0.0.1,[::1] + FILTER_FAMILY:inet4 + LIMIT:1 on one name; exactly one
 *           AF_INET result carrying the requested port 8080. Proves the effects compose in
 *           one lookup.
 * - 60-61   OVERRIDE (3 literals) + SHUFFLE:1.0 + LIMIT:2, 20000 lookups with AI_CANONNAME;
 *           always 2 results, canonical name "many.test" on the head, RSS growth < 256 pages.
 * - 60      rdns://127.0.0.1 GAI EAI_AGAIN; getnameinfo returns EAI_AGAIN.
 * - 61-64   rdns://127.0.0.1 LATENCY:200; getnameinfo succeeds and takes >= 150 ms.
 * - 65-67   rdns://127.0.0.1 REWRITE:ptr.example + SERVICE:redis; host and service replaced.
 * - 400-406 the same rules on gethostbyname(_r), gethostbyname2(_r), gethostbyaddr(_r): a GAI
 *           error becomes h_errno HOST_NOT_FOUND, OVERRIDE supplies the address list, REWRITE
 *           the reverse name; with the rules cleared, localhost resolves again.
 * - 200-204 the rule file could not be written.
 *
 * Codes 60 and 61 are reused by consecutive checks; main()'s order disambiguates. The hostent
 * functions are separate checks because glibc and musl resolve them without calling the
 * public getaddrinfo/getnameinfo, so each needs its own wrapper.
 *
 * Run by test_dns_glibc.sh (gcc:bookworm) and test_dns_alpine.sh (alpine:3.20), which build the
 * library, compile this file in the container and run it with `LD_PRELOAD=/tmp/libchaos-dns.so`.
 * Checks stop at the first failure.
 *
 * Exit: 0 when every check passes; otherwise the code of the first failing check above. The
 * rule file is left in place (cleared by the last check). The probe never skips.
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

/** @brief Fills @p address with @p host:@p port; aborts on an unparsable literal. */
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
 * @brief Sleeps 2 ms so the next intercepted call re-checks the rule file.
 *
 * With rules loaded, a library stats its rule file at most once per CHAOS_CHECK_INTERVAL_NS
 * (1 ms); a rewrite is seen by the first call after that, not necessarily the next call. The
 * sleep is a raw clock_nanosleep system call, restarted on EINTR, so no wrapper (libchaos-time
 * faults nanosleep) can fail or stretch it.
 */
static void wait_for_rule_check(void)
{
    struct timespec delay = {0, 2000000L};

    while (syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &delay, &delay) != 0 && errno == EINTR)
    {
    }
}

/**
 * @brief Replaces the rule file `/tmp/.chaos-dns.conf` with @p text plus a newline and stamps a
 *        fresh mtime.
 *
 * The mtime is set explicitly to 5000, 5001, ... seconds since the epoch, so each write
 * changes the reload change stamp even when two writes land within one filesystem timestamp
 * tick.
 *
 * @return 0, or 200 (fopen), 201 (fprintf), 202 (fflush), 203 (futimens), 204 (fclose).
 */
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

/** @brief write_config_now(), then wait_for_rule_check(); returns write_config_now()'s code. */
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

/** @brief Resident set size in pages from /proc/self/statm; -1 when unavailable. */
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
 * @brief Regression check: OVERRIDE with several literals, shuffled and cut, 20000 times,
 *        must neither crash nor leak (exit 60-61).
 *
 * musl allocates each getaddrinfo() result as one reference-counted block. A result list
 * spliced from several such blocks leaked on every lookup and, once SHUFFLE and LIMIT
 * reordered and cut it, freed a block still in use. libchaos-dns now builds the whole list in
 * its own allocation. Each result must have exactly 2 entries with the canonical name
 * "many.test" on the head after every shuffle; RSS must grow by < 256 pages (1 MiB at 4 KiB
 * pages). Fails when /proc/self/statm is unreadable.
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
    /* 256 pages (1 MiB at 4 KiB) over 20000 lookups allows ~52 bytes per lookup: less than
     * any leaked addrinfo block. */
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
 * The legacy hostent resolvers follow the same dns:// and rdns:// rules as getaddrinfo() and
 * getnameinfo() (exit 400-406): EAI_NONAME becomes h_errno HOST_NOT_FOUND (and the _r forms'
 * *h_errnop), OVERRIDE supplies a one-entry address list, REWRITE replaces h_name. The last
 * step proves an empty rule set restores real resolution.
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
