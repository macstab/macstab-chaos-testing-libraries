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

#include <arpa/inet.h>
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
    rc       = g_chaos_dns_real_getaddrinfo(node, service, hints, result);
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
    socklen_t              address_len,
    char                  *host,
    socklen_t              host_len,
    char                  *service,
    socklen_t              service_len,
    int                    flags
)
{
    int previous;
    int rc;

    previous = chaos_dns_enter_internal();
    rc       = g_chaos_dns_real_getnameinfo(
        address, address_len, host, host_len, service, service_len, flags
    );
    chaos_dns_leave_internal(previous);
    return rc;
}

/* -------------------------------------------------------------------------
 * Text helpers
 * ------------------------------------------------------------------------- */

/**
 * @brief Copy @p text into @p buffer and set *target to point into @p buffer,
 *        or set *target = NULL if @p text is NULL.
 *
 * @details Used to substitute hostname and service inputs before the real
 * resolver call.  The caller passes a stack-allocated buffer; this function
 * either copies the text into it (so the pointer's lifetime is the caller's
 * stack frame) or leaves *target as NULL when no substitution is needed.
 *
 * @param text         Source string; NULL means "no substitution".
 * @param buffer       Writable buffer to copy into if @p text is non-NULL.
 * @param buffer_size  Size of @p buffer.
 * @param target       Output: receives either a pointer into @p buffer or NULL.
 * @return  0 on success; -1 if @p text is non-NULL but too long for @p buffer.
 */
static int
chaos_dns_copy_text_or_null(const char *text, char *buffer, size_t buffer_size, const char **target)
{
    size_t len;

    if (target == NULL)
    {
        return -1;
    }
    if (text == NULL)
    {
        *target = NULL;
        return 0;
    }

    len = strlen(text);
    if (len >= buffer_size)
    {
        return -1;
    }

    (void)memcpy(buffer, text, len + 1U);
    *target = buffer;
    return 0;
}

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
 * @brief Append all nodes of @p next to the end of the list at @p head.
 *
 * @details Used by chaos_dns_apply_override() to concatenate per-IP-literal
 * result lists from the real getaddrinfo into a single combined list.
 *
 * Ownership of @p next is transferred to @p head: after the call, the nodes
 * from @p next are reachable via the chain starting at *head.  The caller
 * must not free @p next independently.
 *
 * @param head  Pointer to the head of the target list; set to @p next if empty.
 * @param next  Head of the list to append; no-op if NULL.
 */
static void chaos_dns_append_result_list(struct addrinfo **head, struct addrinfo *next)
{
    struct addrinfo *tail;

    if (head == NULL || next == NULL)
    {
        return;
    }
    if (*head == NULL)
    {
        *head = next;
        return;
    }

    tail = *head;
    while (tail->ai_next != NULL)
    {
        tail = tail->ai_next;
    }
    tail->ai_next = next;
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
 * @brief Build a synthetic addrinfo result list from a comma-separated list of IP literals.
 *
 * @details For each IP literal in `rule->text`:
 *   1. Strip IPv6 brackets if present.
 *   2. Call the real getaddrinfo with AI_NUMERICHOST | caller's hints flags
 *      so that no DNS resolution is performed — only address parsing.
 *   3. Append the partial result to the `combined` list.
 *
 * If any token fails (bracket stripping or getaddrinfo), the entire combined
 * list built so far is freed via g_chaos_dns_real_freeaddrinfo and the
 * function returns an error.  This is an all-or-nothing contract: either all
 * IP literals produce valid result nodes, or the call fails cleanly.
 *
 * ### Ownership of the returned list
 *
 * Every node in `*result` on success was allocated by the real getaddrinfo
 * via the real-call path.  The caller (getaddrinfo interposer) owns the
 * list and must ensure it is eventually freed by the real freeaddrinfo.
 * Because the nodes were created by real getaddrinfo, post-call transforms
 * (FILTER_FAMILY, LIMIT) can safely call chaos_dns_call_real_freeaddrinfo
 * on individual nodes from this list.
 *
 * @param rule     Matched OVERRIDE rule; `rule->text` is the IP literal list.
 * @param service  Service/port string to pass to each real getaddrinfo call.
 * @param hints    Hints from the original getaddrinfo call; AI_NUMERICHOST is
 *                 added internally.  May be NULL.
 * @param result   Output; set to the combined list on success.
 * @return  0 on success with at least one node; EAI_NONAME if the combined
 *          list is unexpectedly empty; EAI_FAIL on any internal error.
 */
static int chaos_dns_apply_override(
    const chaos_dns_rule_t *rule,
    const char             *service,
    const struct addrinfo  *hints,
    struct addrinfo       **result
)
{
    char                 override_text[CHAOS_DNS_MAX_VALUE];
    char                *cursor;
    struct addrinfo      hints_copy;
    const struct addrinfo *lookup_hints;
    struct addrinfo     *combined = NULL;

    if (rule == NULL || result == NULL)
    {
        return EAI_FAIL;
    }
    if (strlen(rule->text) >= sizeof(override_text))
    {
        return EAI_FAIL;
    }

    /* Work on a local copy of rule->text so we can tokenise with NUL writes. */
    (void)memcpy(override_text, rule->text, strlen(rule->text) + 1U);

    /* Build a hints copy that forces numeric-host resolution so that the real
     * getaddrinfo does not perform another DNS lookup for what must be a
     * literal IP address. */
    if (hints != NULL)
    {
        hints_copy = *hints;
    }
    else
    {
        (void)memset(&hints_copy, 0, sizeof(hints_copy));
    }
    hints_copy.ai_flags |= AI_NUMERICHOST;
    lookup_hints = &hints_copy;

    cursor = override_text;
    while (*cursor != '\0')
    {
        char            *token     = cursor;
        char            *separator = strchr(cursor, ',');
        char             host[CHAOS_DNS_MAX_TEXT];
        struct addrinfo *partial   = NULL;
        int              rc;

        if (separator != NULL)
        {
            *separator++ = '\0';
            cursor = separator;
        }
        else
        {
            cursor += strlen(cursor);
        }

        /* Skip leading whitespace in the token. */
        token = token + strspn(token, " \t\r\n");
        if (chaos_dns_strip_ipv6_brackets(token, host, sizeof(host)) != 0)
        {
            /* Bracket stripping failed: free whatever we accumulated and bail. */
            if (combined != NULL)
            {
                g_chaos_dns_real_freeaddrinfo(combined);
            }
            return EAI_FAIL;
        }

        rc = chaos_dns_call_real_getaddrinfo(host, service, lookup_hints, &partial);
        if (rc != 0)
        {
            /* Real call failed for this token: free accumulated list and return
             * the error so the interposer can surface it to the application. */
            if (combined != NULL)
            {
                g_chaos_dns_real_freeaddrinfo(combined);
            }
            return rc;
        }
        /* Ownership of 'partial' is transferred to 'combined'. */
        chaos_dns_append_result_list(&combined, partial);
    }

    *result = combined;
    return combined != NULL ? 0 : EAI_NONAME;
}

/* =========================================================================
 * Interposed entry points
 * ========================================================================= */

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
 * `*result` on successful return points to a list of nodes all allocated by
 * the real getaddrinfo.  The application is responsible for calling
 * freeaddrinfo on this list.  The interposed freeaddrinfo (if present in the
 * library) delegates to the real freeaddrinfo; there is no special ownership
 * state that differs from what a non-interposed call would produce.
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
    chaos_dns_rule_t rewrite_rule;
    chaos_dns_rule_t service_rule;
    chaos_dns_rule_t override_rule;
    chaos_dns_rule_t filter_rule;
    chaos_dns_rule_t shuffle_rule;
    chaos_dns_rule_t limit_rule;
    char             node_buffer[CHAOS_DNS_MAX_VALUE];
    char             service_buffer[CHAOS_DNS_MAX_VALUE];
    const char      *effective_node    = node;
    const char      *effective_service = service;
    int              rc;
    int              gai_error;

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
        return gai_error;
    }

    /* 4. NULL result pointer: pass through (real API semantics unchanged). */
    if (result == NULL)
    {
        return chaos_dns_call_real_getaddrinfo(node, service, hints, result);
    }

    /* 5. REWRITE: substitute the lookup hostname. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_REWRITE, node, &rewrite_rule) &&
        chaos_dns_rule_should_trigger(&rewrite_rule))
    {
        if (chaos_dns_copy_text_or_null(
                rewrite_rule.text, node_buffer, sizeof(node_buffer), &effective_node
            ) != 0)
        {
            return EAI_FAIL;
        }
    }

    /* 6. SERVICE: substitute the service/port string. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_SERVICE, node, &service_rule) &&
        chaos_dns_rule_should_trigger(&service_rule))
    {
        if (chaos_dns_copy_text_or_null(
                service_rule.text, service_buffer, sizeof(service_buffer), &effective_service
            ) != 0)
        {
            return EAI_FAIL;
        }
    }

    /* 7. OVERRIDE or real call.
     * Both paths produce a list of nodes allocated by the real getaddrinfo.
     * Ownership of *result is held by this interposer and ultimately by the
     * application. */
    *result = NULL;
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_OVERRIDE, node, &override_rule) &&
        chaos_dns_rule_should_trigger(&override_rule))
    {
        rc = chaos_dns_apply_override(&override_rule, effective_service, hints, result);
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
        chaos_dns_rule_should_trigger(&filter_rule) &&
        !chaos_dns_filter_result_list(result, filter_rule.family))
    {
        /* All nodes were filtered out; the real resolver found nothing matching. */
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
            return EAI_NONAME;
        }
    }

    return 0;
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
    socklen_t              address_len,
    char                  *host,
    socklen_t              host_len,
    char                  *service,
    socklen_t              service_len,
    int                    flags
)
{
    chaos_dns_rule_t latency_rule;
    chaos_dns_rule_t gai_rule;
    chaos_dns_rule_t rewrite_rule;
    chaos_dns_rule_t service_rule;
    char             query[CHAOS_DNS_MAX_TEXT];
    int              rc;
    int              gai_error;

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
