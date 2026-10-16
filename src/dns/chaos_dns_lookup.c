/**
 * @file chaos_dns_lookup.c
 * @brief Interposed getaddrinfo(3) and getnameinfo(3) entry points.
 *
 * @details
 * This translation unit contains the two exported symbols that LD_PRELOAD
 * causes the dynamic linker to resolve before their libc counterparts:
 *   - getaddrinfo(3)  — forward name-to-address lookup
 *   - getnameinfo(3)  — reverse address-to-name lookup
 *
 * Both functions follow the same structural pattern:
 *   1. **Reentrancy guard check** — if the call originates from within the
 *      library (e.g., from the OVERRIDE path calling the real getaddrinfo),
 *      delegate directly to the real implementation and return.
 *   2. **Pre-call effects** — check for LATENCY (sleep) and GAI (synthetic
 *      error) rules.  The GAI path returns early without calling the real
 *      resolver.
 *   3. **Input substitution** — check for REWRITE (hostname) and SERVICE
 *      (port) rules, replacing the relevant pointer before the real call.
 *   4. **Real call / OVERRIDE** — either call the real resolver with the
 *      (possibly substituted) inputs, or build a synthetic result list from
 *      literal IP addresses (OVERRIDE).
 *   5. **Post-call transforms** — apply FILTER_FAMILY, SHUFFLE, and LIMIT
 *      in that fixed order.  See chaos_dns_actions.h for why order matters.
 *
 * ### addrinfo list ownership and freeaddrinfo interception
 *
 * After a successful getaddrinfo call (real or OVERRIDE), `*result` points to
 * a list of addrinfo nodes that were allocated by the real getaddrinfo.
 * Ownership is returned to the calling application.
 *
 * When post-call transforms run:
 *   - FILTER_FAMILY and LIMIT may free individual nodes or sub-lists via
 *     g_chaos_dns_real_freeaddrinfo (see chaos_dns_actions.c).  Those nodes
 *     are gone; the application never sees them.
 *   - SHUFFLE only relinks nodes; no allocation or freeing occurs.
 *
 * The surviving list is still a valid "real getaddrinfo" list: every node in
 * it was allocated by the real getaddrinfo and must be freed by the real
 * freeaddrinfo.  There is therefore no special freeaddrinfo interception
 * needed: the application calls freeaddrinfo normally, which (if interposed)
 * passes through to the real freeaddrinfo because the reentrancy guard is not
 * set from application code.
 *
 * The OVERRIDE path calls the real getaddrinfo for each IP literal with
 * AI_NUMERICHOST, then concatenates the resulting sub-lists.  The combined
 * list is identical in structure to a real resolver result: all nodes were
 * allocated by the real getaddrinfo, so the application's freeaddrinfo call
 * works correctly without any special ownership tracking.
 *
 * ### getnameinfo does not return an addrinfo list
 *
 * getnameinfo writes into caller-supplied character buffers; there is no heap
 * allocation involved in the chaos path.  REWRITE and SERVICE effects on the
 * getnameinfo path directly overwrite the output buffers in place.
 *
 * ### Fail-open principle
 *
 * If any internal operation fails (config parse error, allocation failure in
 * SHUFFLE, etc.) the library either passes through to the real implementation
 * unchanged or returns the result as-is.  It never silently drops a result
 * that would otherwise have been returned.  The only exceptions are FILTER_FAMILY
 * and LIMIT producing an empty list, which both return EAI_NONAME — the same
 * error a real resolver would return for a genuinely empty result set.
 *
 * @module  libchaos-dns entry points
 * @stability  Public API (interposed symbols); internal implementation is private.
 */

#include "chaos_dns_actions.h"
#include "chaos_dns_config.h"
#include "chaos_dns_internal.h"
#include "chaos_dns_owned.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Internal call wrappers
 * These set the reentrancy guard so that recursive calls from within the
 * real resolver (which may itself call getaddrinfo or getnameinfo) are
 * passed straight through without chaos injection.
 * ------------------------------------------------------------------------- */

/**
 * @brief Call the real getaddrinfo under the reentrancy guard.
 *
 * @details All internal callers that need the real getaddrinfo must use this
 * wrapper rather than calling g_chaos_dns_real_getaddrinfo directly.  Setting
 * the guard ensures that any call the real resolver makes back into
 * getaddrinfo (e.g., on systems where the resolver uses getaddrinfo
 * internally) is not re-intercepted.
 *
 * @param node     Hostname or address string (may be NULL).
 * @param service  Service name or port string (may be NULL).
 * @param hints    Optional resolver hints (may be NULL).
 * @param result   Output pointer for the result list.
 * @return  0 on success; an EAI_* code on failure.
 */
static int chaos_dns_call_real_getaddrinfo(
    const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result
)
{
    int previous;
    int rc;

    previous = chaos_dns_enter_internal();
    rc = g_chaos_dns_real_getaddrinfo(node, service, hints, result);
    chaos_dns_leave_internal(previous);
    return rc;
}

/**
 * @brief Call the real getnameinfo under the reentrancy guard.
 *
 * @details Same guard rationale as chaos_dns_call_real_getaddrinfo.
 *
 * @param address      Socket address to look up.
 * @param address_len  Size of @p address in bytes.
 * @param host         Output buffer for the hostname (may be NULL).
 * @param host_len     Size of @p host.
 * @param service      Output buffer for the service name (may be NULL).
 * @param service_len  Size of @p service.
 * @param flags        Flags (NI_NUMERICHOST, NI_NAMEREQD, etc.).
 * @return  0 on success; an EAI_* code on failure.
 */
static int chaos_dns_call_real_getnameinfo(
    const struct sockaddr *address,
    socklen_t address_len,
    char *host,
    socklen_t host_len,
    char *service,
    socklen_t service_len,
    int flags
)
{
    int previous;
    int rc;

    previous = chaos_dns_enter_internal();
    rc = g_chaos_dns_real_getnameinfo(
        address, address_len, host, host_len, service, service_len, flags
    );
    chaos_dns_leave_internal(previous);
    return rc;
}

/* -------------------------------------------------------------------------
 * Text helpers
 * ------------------------------------------------------------------------- */

/**
 * @brief Copy @p text into a caller-supplied output buffer of size @p target_size.
 *
 * @details Used to overwrite getnameinfo output buffers for REWRITE and SERVICE
 * effects.  Fails if the replacement text is too long — the caller then returns
 * EAI_OVERFLOW to the application, matching POSIX semantics for a too-short
 * output buffer.
 *
 * @param text         NUL-terminated replacement string.
 * @param target       Output buffer.
 * @param target_size  Size of @p target in bytes (cast from socklen_t at call site).
 * @return  0 on success; -1 if @p text (+ NUL) is too long for @p target.
 */
static int chaos_dns_copy_output_text(const char *text, char *target, size_t target_size)
{
    size_t len;

    if (text == NULL || target == NULL || target_size == 0U)
    {
        return -1;
    }

    len = strlen(text);
    if (len >= target_size)
    {
        return -1;
    }

    (void)memcpy(target, text, len + 1U);
    return 0;
}

/**
 * @brief Extract a printable IP address string from a struct sockaddr.
 *
 * @details Used by the getnameinfo interposer to build the reverse-lookup
 * key for rule matching.  Handles AF_INET and AF_INET6; returns 0 for any
 * other address family (the interposer then passes through unchanged).
 *
 * The address family is checked first so that the struct cast to the narrower
 * sockaddr_in / sockaddr_in6 type is always safe.  address_len is validated
 * against the minimum required structure size as an additional safeguard
 * against caller bugs.
 *
 * The output string format matches the canonical form produced by inet_ntop(3),
 * which is the same format used when storing reverse-selector text in
 * chaos_dns_parse_reverse_selector_body() — ensuring exact-match comparisons
 * work correctly without normalisation at lookup time.
 *
 * @param address      Pointer to the socket address structure.
 * @param address_len  Byte length of the structure pointed to by @p address.
 * @param buffer       Output buffer for the printable address.
 * @param buffer_size  Size of @p buffer; INET6_ADDRSTRLEN (46) is sufficient.
 * @return  Non-zero on success; zero if the address family is unsupported or
 *          address_len is too small.
 */
static int chaos_dns_reverse_query_from_sockaddr(
    const struct sockaddr *address, socklen_t address_len, char *buffer, size_t buffer_size
)
{
    if (address == NULL || buffer == NULL || buffer_size == 0U ||
        address_len < (socklen_t)sizeof(sa_family_t))
    {
        return 0;
    }
    if (address->sa_family == AF_INET)
    {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;

        if (address_len < (socklen_t)sizeof(*ipv4))
        {
            return 0;
        }
        return inet_ntop(AF_INET, &ipv4->sin_addr, buffer, buffer_size) != NULL;
    }
    if (address->sa_family == AF_INET6)
    {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;

        if (address_len < (socklen_t)sizeof(*ipv6))
        {
            return 0;
        }
        return inet_ntop(AF_INET6, &ipv6->sin6_addr, buffer, buffer_size) != NULL;
    }

    return 0;
}

/**
 * @brief Strip IPv6 square-bracket notation from an address token.
 *
 * @details OVERRIDE rule text stores IPv6 addresses as `[::1]` so that the
 * comma-delimited list is unambiguous.  This function strips the brackets
 * before passing the address to getaddrinfo.  IPv4 addresses and bare IPv6
 * addresses (without brackets) are copied verbatim.
 *
 * @param token      Source token (e.g., `"[::1]"` or `"192.168.1.1"`).
 * @param host       Output buffer for the stripped address string.
 * @param host_size  Size of @p host.
 * @return  0 on success; -1 if @p token is empty, malformed, or too long.
 */
static int chaos_dns_strip_ipv6_brackets(const char *token, char *host, size_t host_size)
{
    size_t len;

    if (token == NULL || host == NULL || host_size == 0U)
    {
        return -1;
    }

    len = strlen(token);
    if (len == 0U)
    {
        return -1;
    }
    if (token[0] == '[' && len > 2U && token[len - 1U] == ']')
    {
        if (len - 2U >= host_size)
        {
            return -1;
        }
        (void)memcpy(host, token + 1, len - 2U);
        host[len - 2U] = '\0';
        return 0;
    }
    if (len >= host_size)
    {
        return -1;
    }

    (void)memcpy(host, token, len + 1U);
    return 0;
}

/* -------------------------------------------------------------------------
 * OVERRIDE implementation
 * ------------------------------------------------------------------------- */

/**
 * @brief The address family of IP literal @p host; 0 when it is neither.
 */
static int chaos_dns_literal_family(const char *host)
{
    unsigned char address[sizeof(struct in6_addr)];

    if (inet_pton(AF_INET, host, address) == 1)
    {
        return AF_INET;
    }
    return inet_pton(AF_INET6, host, address) == 1 ? AF_INET6 : 0;
}

/** @brief Most literals one OVERRIDE rule may list. */
#define CHAOS_DNS_MAX_OVERRIDE 32U

/**
 * @brief Resolve the comma-separated IP literals of an OVERRIDE rule.
 *
 * @details Each literal is resolved by the real getaddrinfo with AI_NUMERICHOST
 * (so @p service and the hints' socket type expand as usual, without a DNS
 * query); literals of a family the hints exclude are skipped. The nodes are
 * copied into one list of our own (chaos_dns_owned.h) and the real results are
 * released at once, so no list ever spans several of the C library's
 * allocations. With AI_CANONNAME the queried @p name is the canonical name.
 *
 * @param rule     Matched OVERRIDE rule; `rule->text` is the IP literal list.
 * @param name     The name looked up.
 * @param service  Service/port string to pass to each real getaddrinfo call.
 * @param hints    Hints from the original getaddrinfo call; may be NULL.
 * @param result   Output; set to the list on success.
 * @return 0; EAI_NONAME when no literal fits the hints; EAI_MEMORY when the list
 *         cannot be allocated; EAI_FAIL for a malformed rule; or the error of a
 *         literal the real getaddrinfo rejects.
 */
static int chaos_dns_apply_override(
    const chaos_dns_rule_t *rule,
    const char *name,
    const char *service,
    const struct addrinfo *hints,
    struct addrinfo **result
)
{
    char override_text[CHAOS_DNS_MAX_VALUE];
    struct addrinfo *partials[CHAOS_DNS_MAX_OVERRIDE];
    struct addrinfo hints_copy;
    size_t count = 0U;
    size_t index;
    char *cursor;
    int rc = 0;

    if (rule == NULL || result == NULL || strlen(rule->text) >= sizeof(override_text))
    {
        return EAI_FAIL;
    }
    (void)memcpy(override_text, rule->text, strlen(rule->text) + 1U);
    if (hints != NULL)
    {
        hints_copy = *hints;
    }
    else
    {
        (void)memset(&hints_copy, 0, sizeof(hints_copy));
    }
    hints_copy.ai_flags |= AI_NUMERICHOST;

    cursor = override_text;
    while (*cursor != '\0' && rc == 0)
    {
        char *token = cursor;
        char *separator = strchr(cursor, ',');
        char host[CHAOS_DNS_MAX_TEXT];
        int family;

        if (separator != NULL)
        {
            *separator++ = '\0';
            cursor = separator;
        }
        else
        {
            cursor += strlen(cursor);
        }
        token = token + strspn(token, " \t\r\n");
        if (chaos_dns_strip_ipv6_brackets(token, host, sizeof(host)) != 0 ||
            count == CHAOS_DNS_MAX_OVERRIDE)
        {
            rc = EAI_FAIL;
            break;
        }
        family = chaos_dns_literal_family(host);
        if (hints_copy.ai_family != AF_UNSPEC && family != 0 && family != hints_copy.ai_family)
        {
            continue; /* the caller asked for the other family */
        }
        partials[count] = NULL;
        rc = chaos_dns_call_real_getaddrinfo(host, service, &hints_copy, &partials[count]);
        if (rc == 0)
        {
            ++count;
        }
    }

    if (rc == 0 && count == 0U)
    {
        rc = EAI_NONAME;
    }
    if (rc == 0)
    {
        *result = chaos_dns_owned_copy(
            partials, count, (hints_copy.ai_flags & AI_CANONNAME) != 0 ? name : NULL
        );
        rc = *result != NULL ? 0 : EAI_MEMORY;
    }
    for (index = 0U; index < count; ++index)
    {
        g_chaos_dns_real_freeaddrinfo(partials[index]);
    }
    return rc;
}

/* =========================================================================
 * Interposed entry points
 * ========================================================================= */

/**
 * @brief Steps 4-10 of getaddrinfo(): REWRITE, SERVICE, OVERRIDE or the real
 *        resolver, then FILTER_FAMILY, SHUFFLE and LIMIT.
 *
 * @details Runs after LATENCY and GAI. Shared with the gethostbyname family, so a
 * rule shapes a name's answer identically whichever API resolves it.
 *
 * @return  0 on success; an EAI_* error code on failure.
 */
static int chaos_dns_resolve_with_rules(
    const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result
)
{
    chaos_dns_rule_t rewrite_rule;
    chaos_dns_rule_t service_rule;
    chaos_dns_rule_t override_rule;
    chaos_dns_rule_t filter_rule;
    chaos_dns_rule_t shuffle_rule;
    chaos_dns_rule_t limit_rule;
    const char *effective_node = node;
    const char *effective_service = service;
    const struct addrinfo *owned = NULL;
    int rc;

    /* 4. NULL result pointer: pass through (real API semantics unchanged). */
    if (result == NULL)
    {
        return chaos_dns_call_real_getaddrinfo(node, service, hints, result);
    }

    /* 5. REWRITE: substitute the lookup hostname. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_REWRITE, node, &rewrite_rule) &&
        chaos_dns_rule_should_trigger(&rewrite_rule))
    {
        /* The rule copy lives until the call returns. */
        effective_node = rewrite_rule.text;
    }

    /* 6. SERVICE: substitute the service/port string. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_SERVICE, node, &service_rule) &&
        chaos_dns_rule_should_trigger(&service_rule))
    {
        effective_service = service_rule.text;
    }

    /* 7. OVERRIDE or real call.
     * Both paths produce a list of nodes allocated by the real getaddrinfo.
     * Ownership of *result is held by this interposer and ultimately by the
     * application. */
    *result = NULL;
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_OVERRIDE, node, &override_rule) &&
        chaos_dns_rule_should_trigger(&override_rule))
    {
        rc = chaos_dns_apply_override(&override_rule, node, effective_service, hints, result);
        owned = rc == 0 ? *result : NULL;
    }
    else
    {
        rc = chaos_dns_call_real_getaddrinfo(effective_node, effective_service, hints, result);
    }
    if (rc != 0)
    {
        return rc;
    }

    /* 8. FILTER_FAMILY (first transform): drop nodes of the wrong family.
     * Must run before SHUFFLE and LIMIT so that those transforms see only
     * the set of nodes that will actually be returned. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_FILTER_FAMILY, node, &filter_rule) &&
        filter_rule.family != CHAOS_DNS_FAMILY_ANY && chaos_dns_rule_should_trigger(&filter_rule) &&
        !chaos_dns_filter_result_list(result, filter_rule.family))
    {
        /* All nodes were filtered out; the real resolver found nothing matching.
         * A list of ours is freed as a whole (its nodes were only unlinked). */
        (void)chaos_dns_owned_free(owned);
        return EAI_NONAME;
    }

    /* 9. SHUFFLE (second transform): randomise the surviving node order.
     * Must run before LIMIT so that the limit selects from the random order,
     * not the OS-determined order. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_SHUFFLE, node, &shuffle_rule) &&
        chaos_dns_rule_should_trigger(&shuffle_rule))
    {
        chaos_dns_shuffle_result_list(result);
    }

    /* 10. LIMIT (third transform): truncate to at most N nodes. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_LIMIT, node, &limit_rule) &&
        chaos_dns_rule_should_trigger(&limit_rule))
    {
        chaos_dns_limit_result_list(result, limit_rule.limit);
        if (*result == NULL)
        {
            (void)chaos_dns_owned_free(owned);
            return EAI_NONAME;
        }
    }

    return 0;
}

/**
 * @brief Interposed getaddrinfo(3) — forward name-to-address lookup.
 *
 * @details This is a drop-in replacement for the POSIX getaddrinfo(3) function.
 * It is resolved before the libc version because it is marked
 * CHAOS_DNS_EXPORT and libchaos-dns is loaded via LD_PRELOAD.
 *
 * **Execution order and rationale**
 *
 * 1. **Reentrancy guard** — if the current thread is already inside the
 *    library, bypass chaos entirely.  This prevents infinite recursion when
 *    the real resolver calls getaddrinfo internally.
 *
 * 2. **NULL / empty node** — bypass chaos.  The real getaddrinfo defines the
 *    semantics of a NULL node (means the local host); we don't chaos-inject
 *    that case.
 *
 * 3. **LATENCY** — look up a LATENCY rule for @p node; if it fires, sleep
 *    before continuing.  Sleep happens regardless of whether the GAI or
 *    OVERRIDE paths subsequently apply, because LATENCY models network delay
 *    that occurs regardless of outcome.
 *
 * 4. **GAI (synthetic failure)** — look up a GAI rule; if it fires, return
 *    the configured EAI_* code immediately, no real resolver call.
 *
 * 5. **NULL result pointer** — if the caller passed result == NULL, bypass
 *    chaos (the real getaddrinfo defines the semantics in this case).
 *
 * 6. **REWRITE / SERVICE** — substitute hostname and/or service before the
 *    real call.  `effective_node` and `effective_service` are updated to
 *    point into stack buffers if substitution applies.
 *
 * 7. **OVERRIDE vs real call** — if an OVERRIDE rule fires, call
 *    chaos_dns_apply_override() instead of the real resolver.  Both paths
 *    produce a `*result` list owned by this interposer (ultimately owned by
 *    the application).
 *
 * 8. **FILTER_FAMILY** — drop nodes of the wrong family; return EAI_NONAME
 *    if the list becomes empty.
 *
 * 9. **SHUFFLE** — randomise node order.
 *
 * 10. **LIMIT** — truncate to N nodes; return EAI_NONAME if limit == 0.
 *
 * **addrinfo ownership**
 *
 * `*result` on successful return points to a list allocated by the real
 * getaddrinfo, or, after OVERRIDE, to one allocation of our own
 * (chaos_dns_owned.h). The application frees either with freeaddrinfo, which
 * this library interposes to tell them apart.
 *
 * @param node     Hostname or address string (may be NULL).
 * @param service  Service name or port number string (may be NULL).
 * @param hints    Optional resolver hints (may be NULL).
 * @param result   Output pointer for the result addrinfo list.
 * @return  0 on success; an EAI_* error code on failure.
 *
 * @threadsafety  Safe — all shared state access is either read-only (active
 *               config snapshot) or TLS (PRNG, reentrancy guard).
 */
CHAOS_DNS_EXPORT int getaddrinfo(
    const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result
)
{
    chaos_dns_rule_t latency_rule;
    chaos_dns_rule_t gai_rule;
    int gai_error;

    chaos_dns_ensure_symbols();

    /* 1. Reentrancy guard: bypass if already inside the library. */
    if (chaos_dns_in_internal() || node == NULL || *node == '\0')
    {
        return chaos_dns_call_real_getaddrinfo(node, service, hints, result);
    }

    /* 2. LATENCY: inject delay before resolver, regardless of what follows. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_LATENCY, node, &latency_rule) &&
        chaos_dns_rule_should_trigger(&latency_rule))
    {
        chaos_dns_rule_apply_latency(&latency_rule);
    }

    /* 3. GAI: return a synthetic EAI_* error; skip the real resolver. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_GAI, node, &gai_rule) &&
        chaos_dns_rule_apply_gai(&gai_rule, &gai_error))
    {
        if (gai_error == EAI_SYSTEM)
        {
            errno = EIO; /* EAI_SYSTEM means "see errno": give it a system error */
        }
        return gai_error;
    }

    /* 4.-10. Result-shaping rules, shared with the gethostbyname family. */
    return chaos_dns_resolve_with_rules(node, service, hints, result);
}

/**
 * @brief Interposed freeaddrinfo(3): frees a list of ours (OVERRIDE), else the real one.
 *
 * @details Any node of a list of ours frees it: SHUFFLE may have made any of them
 * the head the application holds.
 */
CHAOS_DNS_EXPORT void freeaddrinfo(struct addrinfo *result)
{
    chaos_dns_ensure_symbols();
    if (chaos_dns_owned_free(result) || g_chaos_dns_real_freeaddrinfo == NULL)
    {
        return;
    }
    g_chaos_dns_real_freeaddrinfo(result);
}

/**
 * @brief Interposed getnameinfo(3) — reverse address-to-name lookup.
 *
 * @details This is a drop-in replacement for the POSIX getnameinfo(3) function.
 *
 * **Execution order**
 *
 * 1. **Reentrancy guard / NULL address** — bypass chaos entirely.
 *
 * 2. **Reverse query key extraction** — convert the struct sockaddr to a
 *    normalised IP string using chaos_dns_reverse_query_from_sockaddr().
 *    If the address family is unsupported, bypass chaos.
 *
 * 3. **LATENCY** — inject delay before the real call.
 *
 * 4. **GAI** — return a synthetic EAI_* error before the real call.
 *
 * 5. **Real call** — call getnameinfo with the original, unmodified arguments.
 *    If the real call fails, return the error immediately.
 *
 * 6. **REWRITE** — if the rule fires and the replacement hostname fits in the
 *    output buffer, overwrite `host` in place.  If it doesn't fit, return
 *    EAI_OVERFLOW (matching POSIX semantics for a too-short host buffer).
 *
 * 7. **SERVICE** — same as REWRITE but for the `service` output buffer.
 *
 * **No addrinfo list** — getnameinfo writes into caller-supplied character
 * buffers; there is no heap allocation in the chaos path and therefore no
 * ownership transfer to reason about.
 *
 * @param address      Socket address to resolve.
 * @param address_len  Byte size of @p address.
 * @param host         Output buffer for the resolved hostname (may be NULL).
 * @param host_len     Size of @p host in bytes.
 * @param service      Output buffer for the resolved service name (may be NULL).
 * @param service_len  Size of @p service in bytes.
 * @param flags        Resolver flags (NI_NUMERICHOST, NI_NAMEREQD, etc.).
 * @return  0 on success; an EAI_* error code on failure (including EAI_OVERFLOW
 *          if REWRITE or SERVICE text is too long for the output buffer).
 *
 * @threadsafety  Safe — see getaddrinfo for general thread-safety notes.
 */
CHAOS_DNS_EXPORT int getnameinfo(
    const struct sockaddr *address,
    socklen_t address_len,
    char *host,
    socklen_t host_len,
    char *service,
    socklen_t service_len,
    int flags
)
{
    chaos_dns_rule_t latency_rule;
    chaos_dns_rule_t gai_rule;
    chaos_dns_rule_t rewrite_rule;
    chaos_dns_rule_t service_rule;
    char query[CHAOS_DNS_MAX_TEXT];
    int rc;
    int gai_error;

    chaos_dns_ensure_symbols();

    /* 1. Reentrancy guard / NULL address. */
    if (chaos_dns_in_internal() || address == NULL)
    {
        return chaos_dns_call_real_getnameinfo(
            address, address_len, host, host_len, service, service_len, flags
        );
    }

    /* 2. Extract the reverse-lookup key (normalised IP string).
     * If the address family is unsupported, bypass chaos entirely. */
    if (!chaos_dns_reverse_query_from_sockaddr(address, address_len, query, sizeof(query)))
    {
        return chaos_dns_call_real_getnameinfo(
            address, address_len, host, host_len, service, service_len, flags
        );
    }

    /* 3. LATENCY: inject delay before the real resolver call. */
    if (chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_LATENCY, query, &latency_rule) &&
        chaos_dns_rule_should_trigger(&latency_rule))
    {
        chaos_dns_rule_apply_latency(&latency_rule);
    }

    /* 4. GAI: return a synthetic EAI_* error; skip the real resolver. */
    if (chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_GAI, query, &gai_rule) &&
        chaos_dns_rule_apply_gai(&gai_rule, &gai_error))
    {
        return gai_error;
    }

    /* 5. Real call: perform the actual reverse lookup. */
    rc = chaos_dns_call_real_getnameinfo(
        address, address_len, host, host_len, service, service_len, flags
    );
    if (rc != 0)
    {
        return rc;
    }

    /* 6. REWRITE: overwrite the hostname in the caller's output buffer.
     * If the replacement text is too long, return EAI_OVERFLOW so the caller
     * knows the buffer was too small — same semantics as the real getnameinfo. */
    if (host != NULL && host_len > 0U &&
        chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_REWRITE, query, &rewrite_rule) &&
        chaos_dns_rule_should_trigger(&rewrite_rule) &&
        chaos_dns_copy_output_text(rewrite_rule.text, host, (size_t)host_len) != 0)
    {
        return EAI_OVERFLOW;
    }

    /* 7. SERVICE: overwrite the service name in the caller's output buffer. */
    if (service != NULL && service_len > 0U &&
        chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_SERVICE, query, &service_rule) &&
        chaos_dns_rule_should_trigger(&service_rule) &&
        chaos_dns_copy_output_text(service_rule.text, service, (size_t)service_len) != 0)
    {
        return EAI_OVERFLOW;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * The legacy hostent resolvers: gethostbyname, gethostbyname2, their _r forms,
 * gethostbyaddr and gethostbyaddr_r
 *
 * glibc and musl resolve these through their internal lookup code, never through
 * getaddrinfo() or getnameinfo(), so dns:// and rdns:// rules would not reach
 * them. Forward lookups follow the dns:// rules of the name, reverse lookups the
 * rdns:// rules of the address. LATENCY and GAI apply first; GAI's EAI_* code is
 * reported as the matching h_errno. When only those rules match, the real
 * resolver answers, unchanged. When a rule shapes the answer (REWRITE, OVERRIDE,
 * FILTER_FAMILY, SHUFFLE, LIMIT), the answer comes from the same pipeline as
 * getaddrinfo() and is converted to a hostent, so both APIs see the same result.
 * Reverse lookups support REWRITE of the returned name.
 * ------------------------------------------------------------------------- */

#ifndef NETDB_INTERNAL
#define NETDB_INTERNAL (-1)
#endif

/** Storage behind the non-reentrant forms, which by contract return static data. */
static struct hostent g_chaos_dns_hostent;
static char g_chaos_dns_hostent_buffer[2048];

/**
 * @brief Maps a getaddrinfo EAI_* code to the h_errno a hostent resolver reports.
 */
static int chaos_dns_h_errno_for(int eai_error)
{
    switch (eai_error)
    {
    case EAI_NONAME:
        return HOST_NOT_FOUND;
    case EAI_AGAIN:
        return TRY_AGAIN;
#ifdef EAI_NODATA
    case EAI_NODATA:
        return NO_DATA;
#endif
#ifdef EAI_ADDRFAMILY
    case EAI_ADDRFAMILY:
        return NO_DATA;
#endif
    default:
        return NO_RECOVERY;
    }
}

/**
 * @brief Applies LATENCY, then GAI, for a hostent lookup of @p query.
 *
 * @param query    Forward host name or reverse IP text.
 * @param reverse  Non-zero to use the rdns:// rules.
 * @param h_error  Receives the h_errno when GAI fires.
 * @return Non-zero when GAI fired and the lookup must fail.
 */
static int chaos_dns_hostent_prelude(const char *query, int reverse, int *h_error)
{
    chaos_dns_rule_t latency_rule;
    chaos_dns_rule_t gai_rule;
    int gai_error;
    int matched;

    matched = reverse
                  ? chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_LATENCY, query, &latency_rule)
                  : chaos_dns_config_match(CHAOS_DNS_EFFECT_LATENCY, query, &latency_rule);
    if (matched && chaos_dns_rule_should_trigger(&latency_rule))
    {
        chaos_dns_rule_apply_latency(&latency_rule);
    }
    matched = reverse ? chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_GAI, query, &gai_rule)
                      : chaos_dns_config_match(CHAOS_DNS_EFFECT_GAI, query, &gai_rule);
    if (matched && chaos_dns_rule_apply_gai(&gai_rule, &gai_error))
    {
        *h_error = chaos_dns_h_errno_for(gai_error);
        return 1;
    }
    return 0;
}

/** @brief Non-zero when any rule that shapes a forward answer matches @p name. */
static int chaos_dns_has_result_rule(const char *name)
{
    chaos_dns_rule_t rule;

    return chaos_dns_config_match(CHAOS_DNS_EFFECT_REWRITE, name, &rule) ||
           chaos_dns_config_match(CHAOS_DNS_EFFECT_OVERRIDE, name, &rule) ||
           chaos_dns_config_match(CHAOS_DNS_EFFECT_FILTER_FAMILY, name, &rule) ||
           chaos_dns_config_match(CHAOS_DNS_EFFECT_SHUFFLE, name, &rule) ||
           chaos_dns_config_match(CHAOS_DNS_EFFECT_LIMIT, name, &rule);
}

/**
 * @brief Lays out a hostent for the @p family addresses of @p list inside @p buffer.
 *
 * @details Layout: alias list (empty), address list, addresses, name. The name is
 * the canonical name of the first node, or @p name.
 *
 * @return 0 on success; ERANGE when @p buffer is too small; ENOENT when @p list
 *         holds no address of @p family.
 */
static int chaos_dns_fill_hostent(
    const char *name,
    int family,
    const struct addrinfo *list,
    struct hostent *entry,
    char *buffer,
    size_t buffer_size
)
{
    const size_t address_size =
        family == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
    const struct addrinfo *node;
    const char *host_name = name;
    size_t count = 0U;
    size_t name_size;
    size_t pointers_size;
    size_t offset;
    size_t index = 0U;
    char **pointers;
    char *addresses;

    for (node = list; node != NULL; node = node->ai_next)
    {
        if (node->ai_family == family && node->ai_addr != NULL)
        {
            ++count;
        }
    }
    if (count == 0U)
    {
        return ENOENT;
    }
    if (list->ai_canonname != NULL)
    {
        host_name = list->ai_canonname;
    }
    name_size = strlen(host_name) + 1U;

    /* Pointers first, aligned for char *; then addresses; then the name. */
    offset = (size_t)((uintptr_t)buffer % sizeof(char *));
    offset = offset == 0U ? 0U : sizeof(char *) - offset;
    pointers_size = (count + 2U) * sizeof(char *);
    if (buffer_size < offset ||
        buffer_size - offset < pointers_size + count * address_size + name_size)
    {
        return ERANGE;
    }
    pointers = (char **)(void *)(buffer + offset);
    addresses = buffer + offset + pointers_size;

    for (node = list; node != NULL; node = node->ai_next)
    {
        if (node->ai_family != family || node->ai_addr == NULL)
        {
            continue;
        }
        if (family == AF_INET6)
        {
            (void)memcpy(
                addresses + index * address_size,
                &((const struct sockaddr_in6 *)(const void *)node->ai_addr)->sin6_addr,
                address_size
            );
        }
        else
        {
            (void)memcpy(
                addresses + index * address_size,
                &((const struct sockaddr_in *)(const void *)node->ai_addr)->sin_addr,
                address_size
            );
        }
        pointers[1U + index] = addresses + index * address_size;
        ++index;
    }
    pointers[0] = NULL;          /* empty alias list */
    pointers[1U + count] = NULL; /* end of the address list */
    (void)memcpy(addresses + count * address_size, host_name, name_size);

    entry->h_name = addresses + count * address_size;
    entry->h_aliases = pointers;
    entry->h_addrtype = family;
    entry->h_length = (int)address_size;
    entry->h_addr_list = pointers + 1;
    return 0;
}

/**
 * @brief Resolves @p name through the getaddrinfo rule pipeline into a hostent.
 *
 * @return 0, or ERANGE when @p buffer is too small; *result is NULL on failure
 *         and *h_error then says why.
 */
static int chaos_dns_hostent_from_rules(
    const char *name,
    int family,
    struct hostent *entry,
    char *buffer,
    size_t buffer_size,
    struct hostent **result,
    int *h_error
)
{
    struct addrinfo hints;
    struct addrinfo *list = NULL;
    int previous;
    int rc;

    *result = NULL;
    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    rc = chaos_dns_resolve_with_rules(name, NULL, &hints, &list);
    if (rc != 0)
    {
        *h_error = chaos_dns_h_errno_for(rc);
        return 0;
    }
    rc = chaos_dns_fill_hostent(name, family, list, entry, buffer, buffer_size);
    if (!chaos_dns_owned_free(list))
    {
        previous = chaos_dns_enter_internal();
        g_chaos_dns_real_freeaddrinfo(list);
        chaos_dns_leave_internal(previous);
    }
    if (rc == ERANGE)
    {
        *h_error = NETDB_INTERNAL;
        errno = ERANGE;
        return ERANGE;
    }
    if (rc != 0)
    {
        *h_error = NO_DATA;
        return 0;
    }
    *result = entry;
    return 0;
}

/** @brief Calls the real gethostbyname2_r under the reentrancy guard. */
static int chaos_dns_call_real_gethostbyname2_r(
    const char *name,
    int family,
    struct hostent *entry,
    char *buffer,
    size_t buffer_size,
    struct hostent **result,
    int *h_error
)
{
    int previous;
    int rc;

    previous = chaos_dns_enter_internal();
    rc = g_chaos_dns_real_gethostbyname2_r(
        name, family, entry, buffer, buffer_size, result, h_error
    );
    chaos_dns_leave_internal(previous);
    return rc;
}

/** @brief Calls the real gethostbyname2 under the reentrancy guard. */
static struct hostent *chaos_dns_call_real_gethostbyname2(const char *name, int family)
{
    struct hostent *entry;
    int previous;

    previous = chaos_dns_enter_internal();
    entry = g_chaos_dns_real_gethostbyname2(name, family);
    chaos_dns_leave_internal(previous);
    return entry;
}

/**
 * @brief Interposed gethostbyname2_r(3): the dns:// rules of @p name.
 *
 * @return 0, with *result NULL and *h_error set when the lookup failed; ERANGE
 *         when @p buffer is too small.
 */
CHAOS_DNS_EXPORT int gethostbyname2_r(
    const char *name,
    int family,
    struct hostent *entry,
    char *buffer,
    size_t buffer_size,
    struct hostent **result,
    int *h_error
)
{
    int injected;

    chaos_dns_ensure_symbols();
    if (chaos_dns_in_internal() || name == NULL || *name == '\0' || result == NULL ||
        h_error == NULL)
    {
        return chaos_dns_call_real_gethostbyname2_r(
            name, family, entry, buffer, buffer_size, result, h_error
        );
    }
    if (chaos_dns_hostent_prelude(name, 0, &injected))
    {
        *result = NULL;
        *h_error = injected;
        return 0;
    }
    if (chaos_dns_has_result_rule(name))
    {
        return chaos_dns_hostent_from_rules(
            name, family, entry, buffer, buffer_size, result, h_error
        );
    }
    return chaos_dns_call_real_gethostbyname2_r(
        name, family, entry, buffer, buffer_size, result, h_error
    );
}

/** @brief Interposed gethostbyname_r(3): gethostbyname2_r() for AF_INET. */
CHAOS_DNS_EXPORT int gethostbyname_r(
    const char *name,
    struct hostent *entry,
    char *buffer,
    size_t buffer_size,
    struct hostent **result,
    int *h_error
)
{
    return gethostbyname2_r(name, AF_INET, entry, buffer, buffer_size, result, h_error);
}

/**
 * @brief Interposed gethostbyname2(3): the dns:// rules of @p name.
 *
 * @return The (static) entry, or NULL with h_errno set.
 */
CHAOS_DNS_EXPORT struct hostent *gethostbyname2(const char *name, int family)
{
    struct hostent *result;
    int injected;

    chaos_dns_ensure_symbols();
    if (chaos_dns_in_internal() || name == NULL || *name == '\0')
    {
        return chaos_dns_call_real_gethostbyname2(name, family);
    }
    if (chaos_dns_hostent_prelude(name, 0, &injected))
    {
        h_errno = injected;
        return NULL;
    }
    if (chaos_dns_has_result_rule(name))
    {
        (void)chaos_dns_hostent_from_rules(
            name,
            family,
            &g_chaos_dns_hostent,
            g_chaos_dns_hostent_buffer,
            sizeof(g_chaos_dns_hostent_buffer),
            &result,
            &injected
        );
        if (result == NULL)
        {
            h_errno = injected;
        }
        return result;
    }
    return chaos_dns_call_real_gethostbyname2(name, family);
}

/** @brief Interposed gethostbyname(3): gethostbyname2() for AF_INET. */
CHAOS_DNS_EXPORT struct hostent *gethostbyname(const char *name)
{
    return gethostbyname2(name, AF_INET);
}

/** @brief Renders a binary address as the rdns:// lookup key; 0 when unsupported. */
static int chaos_dns_reverse_query_from_address(
    const void *address, socklen_t length, int family, char *buffer, size_t buffer_size
)
{
    if (address == NULL || (family == AF_INET && length < (socklen_t)sizeof(struct in_addr)) ||
        (family == AF_INET6 && length < (socklen_t)sizeof(struct in6_addr)) ||
        (family != AF_INET && family != AF_INET6))
    {
        return 0;
    }
    return inet_ntop(family, address, buffer, (socklen_t)buffer_size) != NULL;
}

/** @brief The REWRITE text for reverse key @p query, or NULL when none fires. */
static const char *chaos_dns_reverse_rewrite(const char *query, chaos_dns_rule_t *rule)
{
    if (chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_REWRITE, query, rule) &&
        chaos_dns_rule_should_trigger(rule))
    {
        return rule->text;
    }
    return NULL;
}

/**
 * @brief Interposed gethostbyaddr_r(3): the rdns:// rules of the address.
 *
 * @details A REWRITE replaces h_name; the new name is stored at the end of
 * @p buffer, and the real resolver gets the rest.
 */
CHAOS_DNS_EXPORT int gethostbyaddr_r(
    const void *address,
    socklen_t length,
    int family,
    struct hostent *entry,
    char *buffer,
    size_t buffer_size,
    struct hostent **result,
    int *h_error
)
{
    chaos_dns_rule_t rewrite_rule;
    char query[CHAOS_DNS_MAX_TEXT];
    const char *rewrite = NULL;
    size_t reserved = 0U;
    int injected;
    int previous;
    int rc;

    chaos_dns_ensure_symbols();
    if (!chaos_dns_in_internal() && result != NULL && h_error != NULL &&
        chaos_dns_reverse_query_from_address(address, length, family, query, sizeof(query)))
    {
        if (chaos_dns_hostent_prelude(query, 1, &injected))
        {
            *result = NULL;
            *h_error = injected;
            return 0;
        }
        rewrite = chaos_dns_reverse_rewrite(query, &rewrite_rule);
        if (rewrite != NULL)
        {
            reserved = strlen(rewrite) + 1U;
            if (reserved > buffer_size)
            {
                *result = NULL;
                *h_error = NETDB_INTERNAL;
                errno = ERANGE;
                return ERANGE;
            }
        }
    }

    previous = chaos_dns_enter_internal();
    rc = g_chaos_dns_real_gethostbyaddr_r(
        address, length, family, entry, buffer, buffer_size - reserved, result, h_error
    );
    chaos_dns_leave_internal(previous);
    if (rc == 0 && rewrite != NULL && *result != NULL)
    {
        (void)memcpy(buffer + buffer_size - reserved, rewrite, reserved);
        (*result)->h_name = buffer + buffer_size - reserved;
    }
    return rc;
}

/** @brief Interposed gethostbyaddr(3): the rdns:// rules of the address. */
CHAOS_DNS_EXPORT struct hostent *gethostbyaddr(const void *address, socklen_t length, int family)
{
    static char rewritten_name[CHAOS_DNS_MAX_VALUE];
    chaos_dns_rule_t rewrite_rule;
    char query[CHAOS_DNS_MAX_TEXT];
    const char *rewrite = NULL;
    struct hostent *entry;
    int injected;
    int previous;

    chaos_dns_ensure_symbols();
    if (!chaos_dns_in_internal() &&
        chaos_dns_reverse_query_from_address(address, length, family, query, sizeof(query)))
    {
        if (chaos_dns_hostent_prelude(query, 1, &injected))
        {
            h_errno = injected;
            return NULL;
        }
        rewrite = chaos_dns_reverse_rewrite(query, &rewrite_rule);
    }

    previous = chaos_dns_enter_internal();
    entry = g_chaos_dns_real_gethostbyaddr(address, length, family);
    chaos_dns_leave_internal(previous);
    if (entry != NULL && rewrite != NULL &&
        chaos_dns_copy_output_text(rewrite, rewritten_name, sizeof(rewritten_name)) == 0)
    {
        entry->h_name = rewritten_name;
    }
    return entry;
}
