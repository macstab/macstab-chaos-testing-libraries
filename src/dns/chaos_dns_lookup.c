/**
 * @file chaos_dns_lookup.c
 * @brief Wrappers for the resolver entry points: getaddrinfo, freeaddrinfo, getnameinfo,
 *        and the gethostbyname / gethostbyaddr family.
 *
 * @details
 * ### getaddrinfo pipeline
 * Rules are matched on the queried name as the caller passed it, one effect at a time:
 *   1. **Guard / NULL or empty node** -- forwarded untouched (a NULL node means the
 *      local host or a service-only lookup; it names nothing a rule could select).
 *   2. **LATENCY** -- sleep, whatever follows.
 *   3. **GAI** -- return the EAI_* code without resolving (EAI_SYSTEM with errno EIO).
 *   4. **REWRITE / SERVICE** -- resolve another name and/or service.
 *   5. **OVERRIDE or the real resolver** -- OVERRIDE answers with its IP literals, copied
 *      into one block of its own (chaos_dns_owned.h).
 *   6. **FILTER_FAMILY, SHUFFLE, LIMIT**, in that order (rationale in
 *      chaos_dns_actions.h). An empty result is EAI_NONAME.
 * Steps 4 to 6 (chaos_dns_resolve_with_rules()) also serve the gethostbyname family, so
 * a name's answer is shaped identically whichever API resolves it.
 *
 * ### Result ownership and freeaddrinfo
 * `*result` is either a list from the real getaddrinfo (possibly with nodes released by
 * FILTER_FAMILY or LIMIT and reordered by SHUFFLE) or an OVERRIDE block. musl frees a
 * real result as one reference-counted block charged to its last node, so lists from
 * several real calls must never be spliced: OVERRIDE copies its per-literal results and
 * releases them at once. The freeaddrinfo wrapper frees an OVERRIDE block when given any
 * of its nodes, and hands everything else to the real freeaddrinfo.
 *
 * ### getnameinfo
 * Matched on the address in inet_ntop form (rdns:// rules). LATENCY and GAI before the
 * real call; REWRITE and SERVICE overwrite the caller's host and service buffers after
 * it, returning EAI_OVERFLOW when the replacement does not fit. No allocation.
 *
 * ### Failure behaviour (fail-open)
 * Internal failures (rule file problems, SHUFFLE's allocation) leave the call to the
 * real resolver or the result as it was. Results shrink only by FILTER_FAMILY and LIMIT;
 * an empty list becomes EAI_NONAME, what a resolver reports for a name without the
 * wanted addresses. Before the real functions are resolved, the wrappers fail with
 * EAI_SYSTEM / ENOSYS (hostent forms: NETDB_INTERNAL / ENOSYS): no system call can stand
 * in for a resolver.
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
 * Calls to the real functions, with the guard set so that a resolver calling
 * getaddrinfo or getnameinfo internally reaches the real function unmatched.
 * ------------------------------------------------------------------------- */

/**
 * @brief Calls the real getaddrinfo with the guard set.
 *
 * @details The only way the library calls getaddrinfo (OVERRIDE's literals, REWRITE,
 * the hostent pipeline): the guard keeps a resolver that calls getaddrinfo internally
 * from being matched again. Before resolution: EAI_SYSTEM with errno ENOSYS.
 *
 * @param node     Host name or address string; may be NULL.
 * @param service  Service name or port string; may be NULL.
 * @param hints    Optional hints; may be NULL.
 * @param result   Output list.
 * @return  0 on success; an EAI_* code on failure.
 */
static int chaos_dns_call_real_getaddrinfo(
    const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result
)
{
    int previous;
    int rc;

    if (g_chaos_dns_real_getaddrinfo == NULL)
    {
        /* Not resolved yet (a call from inside the symbol lookup): there is no system
         * call to fall back to, so fail the way getaddrinfo reports system errors. */
        errno = ENOSYS;
        return EAI_SYSTEM;
    }
    previous = chaos_dns_enter_internal();
    rc = g_chaos_dns_real_getaddrinfo(node, service, hints, result);
    chaos_dns_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real getnameinfo with the guard set; EAI_SYSTEM / ENOSYS before
 *        resolution.
 *
 * @param address      Socket address to look up.
 * @param address_len  Size of @p address in bytes.
 * @param host         Output buffer for the host name; may be NULL.
 * @param host_len     Size of @p host.
 * @param service      Output buffer for the service name; may be NULL.
 * @param service_len  Size of @p service.
 * @param flags        NI_* flags.
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

    if (g_chaos_dns_real_getnameinfo == NULL)
    {
        errno = ENOSYS;
        return EAI_SYSTEM;
    }
    previous = chaos_dns_enter_internal();
    rc = g_chaos_dns_real_getnameinfo(
        address, address_len, host, host_len, service, service_len, flags
    );
    chaos_dns_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real freeaddrinfo with the guard set.
 *
 * @details Before resolution the list is leaked: no system call frees it, and leaking is
 * the only safe choice.
 *
 * @param result  List from the real getaddrinfo (never an OVERRIDE block).
 */
static void chaos_dns_call_real_freeaddrinfo(struct addrinfo *result)
{
    int previous;

    if (g_chaos_dns_real_freeaddrinfo == NULL)
    {
        return;
    }
    previous = chaos_dns_enter_internal();
    g_chaos_dns_real_freeaddrinfo(result);
    chaos_dns_leave_internal(previous);
}

/* -------------------------------------------------------------------------
 * Text helpers
 * ------------------------------------------------------------------------- */

/**
 * @brief Copies @p text into a caller's output buffer of @p target_size bytes.
 *
 * @details For getnameinfo/gethostbyaddr REWRITE and SERVICE. A replacement that does
 * not fit with its NUL fails, and getnameinfo then returns EAI_OVERFLOW, as the real
 * function does for a short buffer; the buffer is left as the real call wrote it.
 *
 * @param text         NUL-terminated replacement.
 * @param target       Output buffer.
 * @param target_size  Size of @p target in bytes.
 * @return  0 on success; -1 if it does not fit or an argument is NULL/0.
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
 * @brief The rdns:// lookup key of a socket address: its inet_ntop text.
 *
 * @details AF_INET and AF_INET6 only; any other family, or an @p address_len shorter
 * than the family's sockaddr, yields 0 and getnameinfo forwards untouched. The family is
 * checked before the cast. inet_ntop is also how rdns:// selectors are stored, so the
 * comparison is an exact string match.
 *
 * @param address      Socket address.
 * @param address_len  Bytes valid at @p address.
 * @param buffer       Output for the text.
 * @param buffer_size  Size of @p buffer; INET6_ADDRSTRLEN (46) suffices.
 * @return  Non-zero on success; zero otherwise.
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
 * @brief Strips the brackets of an IPv6 OVERRIDE literal (`[::1]` -> `::1`).
 *
 * @details Other tokens are copied as they are. getaddrinfo with AI_NUMERICHOST does not
 * accept brackets.
 *
 * @param token      Token, e.g. `[::1]` or `192.168.1.1`.
 * @param host       Output buffer.
 * @param host_size  Size of @p host.
 * @return  0 on success; -1 if @p token is empty or does not fit.
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
 * OVERRIDE
 * ------------------------------------------------------------------------- */

/**
 * @brief Family of IP literal @p host: AF_INET, AF_INET6, or 0 for neither.
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

/** @brief Most literals one OVERRIDE rule may list; more fail the lookup with EAI_FAIL. */
#define CHAOS_DNS_MAX_OVERRIDE 32U

/**
 * @brief Builds the answer of an OVERRIDE rule from its comma-separated IP literals.
 *
 * @details Each literal is resolved by the real getaddrinfo with AI_NUMERICHOST added to
 * the caller's hints, so @p service and the socket type expand as usual without a DNS
 * query; a literal of a family the hints exclude is skipped. The nodes are copied into
 * one block of our own (chaos_dns_owned_copy()) and the real results are released at
 * once, so no returned list spans several C library allocations (see the file header).
 * With AI_CANONNAME the queried @p name becomes the canonical name.
 *
 * @param rule     Matched OVERRIDE rule; `rule->text` holds the literals.
 * @param name     The name looked up.
 * @param service  Service string for each real getaddrinfo call (after SERVICE rules).
 * @param hints    The caller's hints; may be NULL.
 * @param result   Output: the list on success.
 * @return 0; EAI_NONAME when no literal fits the hints; EAI_MEMORY when the block cannot
 *         be allocated or 256 blocks are alive; EAI_FAIL for a malformed rule or more
 *         than 32 literals; or the error of a literal the real getaddrinfo rejects.
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
        chaos_dns_call_real_freeaddrinfo(partials[index]);
    }
    return rc;
}

/* =========================================================================
 * Wrappers
 * ========================================================================= */

/**
 * @brief The result-shaping half of getaddrinfo: REWRITE, SERVICE, OVERRIDE or the real
 *        resolver, then FILTER_FAMILY, SHUFFLE and LIMIT.
 *
 * @details Runs after LATENCY and GAI. Shared with the gethostbyname family. Every rule
 * is matched on the original @p node, not on a REWRITE target. When FILTER_FAMILY or
 * LIMIT empties an OVERRIDE list, its block is freed here and EAI_NONAME returned;
 * an emptied real list has already been released node by node.
 *
 * @return  0 on success; an EAI_* code on failure.
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

    /* NULL result pointer: forward; the real function defines that case. */
    if (result == NULL)
    {
        return chaos_dns_call_real_getaddrinfo(node, service, hints, result);
    }

    /* REWRITE: resolve another name. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_REWRITE, node, &rewrite_rule) &&
        chaos_dns_rule_should_trigger(&rewrite_rule))
    {
        /* Points into the rule copy, which lives until this function returns. */
        effective_node = rewrite_rule.text;
    }

    /* SERVICE: use another service string (matched on the queried name). */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_SERVICE, node, &service_rule) &&
        chaos_dns_rule_should_trigger(&service_rule))
    {
        effective_service = service_rule.text;
    }

    /* OVERRIDE or the real resolver. *result is either a real list or an OVERRIDE
     * block (chaos_dns_owned.h); `owned` remembers the block so an emptied list can
     * still be freed. */
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

    /* FILTER_FAMILY first: SHUFFLE and LIMIT then see only the addresses that will be
     * returned. A rule with family ANY is skipped without counting a hit. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_FILTER_FAMILY, node, &filter_rule) &&
        filter_rule.family != CHAOS_DNS_FAMILY_ANY && chaos_dns_rule_should_trigger(&filter_rule) &&
        !chaos_dns_filter_result_list(result, filter_rule.family))
    {
        /* Nothing left. Dropped real nodes are released already; an OVERRIDE block is
         * freed as a whole (its nodes were only unlinked). */
        (void)chaos_dns_owned_free(owned);
        return EAI_NONAME;
    }

    /* SHUFFLE before LIMIT: LIMIT then keeps a random subset, not the resolver's first
     * entries. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_SHUFFLE, node, &shuffle_rule) &&
        chaos_dns_rule_should_trigger(&shuffle_rule))
    {
        chaos_dns_shuffle_result_list(result);
    }

    /* LIMIT last. The parser guarantees limit >= 1; the NULL check covers limit 0. */
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
 * @brief getaddrinfo(3) wrapper: dns:// rules of @p node.
 *
 * @details Order:
 *   1. Guard set, or NULL/empty @p node: forwarded untouched.
 *   2. **LATENCY** -- sleep before anything else, whether GAI or OVERRIDE follows: it
 *      models resolver delay, which precedes any outcome.
 *   3. **GAI** -- return the EAI_* code without resolving. EAI_SYSTEM sets errno to EIO,
 *      since EAI_SYSTEM tells the caller to read errno.
 *   4. chaos_dns_resolve_with_rules(): NULL @p result is forwarded; REWRITE, SERVICE,
 *      OVERRIDE or the real call; FILTER_FAMILY, SHUFFLE, LIMIT.
 *
 * On success `*result` is a list from the real getaddrinfo or an OVERRIDE block; the
 * application frees either with freeaddrinfo, whose wrapper tells them apart.
 *
 * @param node     Host name or address string; may be NULL.
 * @param service  Service name or port string; may be NULL.
 * @param hints    Optional hints; may be NULL.
 * @param result   Output list.
 * @return  0 on success; an EAI_* code on failure.
 *
 * @threadsafety  Any thread: rules are copied out of the active snapshot; PRNG and guard
 *               are thread-local.
 */
CHAOS_DNS_EXPORT int getaddrinfo(
    const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result
)
{
    chaos_dns_rule_t latency_rule;
    chaos_dns_rule_t gai_rule;
    int gai_error;

    chaos_dns_ensure_symbols();

    /* Guard set, or no name to select on: forward. */
    if (chaos_dns_in_internal() || node == NULL || *node == '\0')
    {
        return chaos_dns_call_real_getaddrinfo(node, service, hints, result);
    }

    /* LATENCY: delay before the resolver, whatever follows. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_LATENCY, node, &latency_rule) &&
        chaos_dns_rule_should_trigger(&latency_rule))
    {
        chaos_dns_rule_apply_latency(&latency_rule);
    }

    /* GAI: a synthetic EAI_* error; the resolver is not called. */
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_GAI, node, &gai_rule) &&
        chaos_dns_rule_apply_gai(&gai_rule, &gai_error))
    {
        if (gai_error == EAI_SYSTEM)
        {
            errno = EIO; /* EAI_SYSTEM means "see errno": give it a system error */
        }
        return gai_error;
    }

    /* REWRITE, SERVICE, OVERRIDE and the transforms, shared with the hostent family. */
    return chaos_dns_resolve_with_rules(node, service, hints, result);
}

/**
 * @brief freeaddrinfo(3) wrapper: frees an OVERRIDE block, else calls the real one.
 *
 * @details Any node of an OVERRIDE block frees the whole block: SHUFFLE may have made any
 * of them the head the application holds. NULL goes to the real freeaddrinfo.
 */
CHAOS_DNS_EXPORT void freeaddrinfo(struct addrinfo *result)
{
    chaos_dns_ensure_symbols();
    if (!chaos_dns_owned_free(result))
    {
        chaos_dns_call_real_freeaddrinfo(result);
    }
}

/**
 * @brief getnameinfo(3) wrapper: rdns:// rules of the address.
 *
 * @details Order:
 *   1. Guard set, NULL @p address, or a family other than AF_INET/AF_INET6: forwarded
 *      untouched.
 *   2. **LATENCY**, then **GAI** (returned as is; unlike getaddrinfo, errno is not set
 *      for EAI_SYSTEM).
 *   3. The real call with the original arguments; its failure is returned.
 *   4. **REWRITE** overwrites @p host, **SERVICE** @p service, each only when the caller
 *      passed that buffer; a replacement that does not fit returns EAI_OVERFLOW.
 *
 * @param address      Socket address to look up.
 * @param address_len  Size of @p address in bytes.
 * @param host         Output buffer for the host name; may be NULL.
 * @param host_len     Size of @p host in bytes.
 * @param service      Output buffer for the service name; may be NULL.
 * @param service_len  Size of @p service in bytes.
 * @param flags        NI_* flags.
 * @return  0 on success; an EAI_* code on failure, including EAI_OVERFLOW.
 *
 * @threadsafety  Any thread; see getaddrinfo().
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

    /* Guard set, or no address: forward. */
    if (chaos_dns_in_internal() || address == NULL)
    {
        return chaos_dns_call_real_getnameinfo(
            address, address_len, host, host_len, service, service_len, flags
        );
    }

    /* The rdns:// key is the inet_ntop text; any other family is forwarded untouched. */
    if (!chaos_dns_reverse_query_from_sockaddr(address, address_len, query, sizeof(query)))
    {
        return chaos_dns_call_real_getnameinfo(
            address, address_len, host, host_len, service, service_len, flags
        );
    }

    /* LATENCY: delay before the real call. */
    if (chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_LATENCY, query, &latency_rule) &&
        chaos_dns_rule_should_trigger(&latency_rule))
    {
        chaos_dns_rule_apply_latency(&latency_rule);
    }

    /* GAI: a synthetic EAI_* error; the resolver is not called. */
    if (chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_GAI, query, &gai_rule) &&
        chaos_dns_rule_apply_gai(&gai_rule, &gai_error))
    {
        return gai_error;
    }

    /* The real reverse lookup, with the caller's arguments. */
    rc = chaos_dns_call_real_getnameinfo(
        address, address_len, host, host_len, service, service_len, flags
    );
    if (rc != 0)
    {
        return rc;
    }

    /* REWRITE: overwrite the host name the real call wrote. A replacement that does not
     * fit returns EAI_OVERFLOW, as the real getnameinfo does for a short buffer. */
    if (host != NULL && host_len > 0U &&
        chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_REWRITE, query, &rewrite_rule) &&
        chaos_dns_rule_should_trigger(&rewrite_rule) &&
        chaos_dns_copy_output_text(rewrite_rule.text, host, (size_t)host_len) != 0)
    {
        return EAI_OVERFLOW;
    }

    /* SERVICE: overwrite the service name the same way. */
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
 * The hostent resolvers: gethostbyname, gethostbyname2, their _r forms,
 * gethostbyaddr and gethostbyaddr_r
 *
 * glibc and musl resolve these through internal lookup code, never through
 * getaddrinfo() or getnameinfo(), so they need wrappers of their own. Forward lookups
 * follow the dns:// rules of the name, reverse lookups the rdns:// rules of the
 * address (inet_ntop text). LATENCY and GAI apply first; GAI's EAI_* code becomes the
 * matching h_errno. When no result-shaping rule (REWRITE, OVERRIDE, FILTER_FAMILY,
 * SHUFFLE, LIMIT) matches the name, the real resolver answers unchanged; otherwise the
 * answer comes from chaos_dns_resolve_with_rules() and is converted to a hostent, so
 * both APIs see the same result. Reverse lookups support REWRITE of h_name only.
 * The non-reentrant forms return static data, as their contract allows; they are not
 * thread-safe, exactly like the libc originals.
 * ------------------------------------------------------------------------- */

#ifndef NETDB_INTERNAL
#define NETDB_INTERNAL (-1)
#endif

/** Storage of the non-reentrant forms (2048-byte buffer); returned as static data. */
static struct hostent g_chaos_dns_hostent;
static char g_chaos_dns_hostent_buffer[2048];

/**
 * @brief The h_errno for an EAI_* code: NONAME -> HOST_NOT_FOUND, AGAIN -> TRY_AGAIN,
 *        NODATA/ADDRFAMILY -> NO_DATA, anything else -> NO_RECOVERY.
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
 * @brief LATENCY, then GAI, for a hostent lookup of @p query.
 *
 * @param query    Host name (forward) or inet_ntop text (reverse).
 * @param reverse  Non-zero for the rdns:// rules.
 * @param h_error  Output: the h_errno when GAI fires.
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

/**
 * @brief Whether a result-shaping rule (REWRITE, OVERRIDE, FILTER_FAMILY, SHUFFLE, LIMIT)
 *        matches @p name; only matching, no firing decision and no hit.
 */
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
 * @details Layout: padding to pointer alignment, the alias list (empty) and the address
 * pointer list, the addresses, the name. The name is the first node's canonical name if
 * it has one, else @p name. Nodes of the other family are skipped.
 *
 * @return 0 on success; ERANGE when @p buffer is too small; ENOENT when @p list holds no
 *         address of @p family.
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

    /* Pointers first (aligned for char *), then the addresses, then the name. */
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
 * @details Hints: @p family, SOCK_STREAM (one node per address), AI_CANONNAME. The list
 * is freed (OVERRIDE block or real list) before returning.
 *
 * @return 0, or ERANGE (h_errno NETDB_INTERNAL, errno ERANGE) when @p buffer is too
 *         small; on any failure *result is NULL and *h_error says why (EAI_* mapped, or
 *         NO_DATA when no address of @p family remains).
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
        chaos_dns_call_real_freeaddrinfo(list);
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

/**
 * @brief Failure of a reentrant hostent wrapper before the real function is resolved.
 *
 * @details No system call resolves a name: fail as these functions report a system
 * error, NETDB_INTERNAL with errno ENOSYS.
 *
 * @return ENOSYS.
 */
static int chaos_dns_hostent_r_unresolved(struct hostent **result, int *h_error)
{
    if (result != NULL)
    {
        *result = NULL;
    }
    if (h_error != NULL)
    {
        *h_error = NETDB_INTERNAL;
    }
    errno = ENOSYS;
    return ENOSYS;
}

/**
 * @brief Failure of a non-reentrant hostent wrapper before the real function is resolved.
 *
 * @return NULL, with h_errno NETDB_INTERNAL and errno ENOSYS.
 */
static struct hostent *chaos_dns_hostent_unresolved(void)
{
    h_errno = NETDB_INTERNAL;
    errno = ENOSYS;
    return NULL;
}

/** @brief Calls the real gethostbyname2_r with the guard set. */
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

    if (g_chaos_dns_real_gethostbyname2_r == NULL)
    {
        return chaos_dns_hostent_r_unresolved(result, h_error);
    }
    previous = chaos_dns_enter_internal();
    rc = g_chaos_dns_real_gethostbyname2_r(
        name, family, entry, buffer, buffer_size, result, h_error
    );
    chaos_dns_leave_internal(previous);
    return rc;
}

/** @brief Calls the real gethostbyname2 with the guard set. */
static struct hostent *chaos_dns_call_real_gethostbyname2(const char *name, int family)
{
    struct hostent *entry;
    int previous;

    if (g_chaos_dns_real_gethostbyname2 == NULL)
    {
        return chaos_dns_hostent_unresolved();
    }
    previous = chaos_dns_enter_internal();
    entry = g_chaos_dns_real_gethostbyname2(name, family);
    chaos_dns_leave_internal(previous);
    return entry;
}

/**
 * @brief gethostbyname2_r(3) wrapper: dns:// rules of @p name.
 *
 * @details Guard set, NULL/empty @p name, or NULL @p result / @p h_error: forwarded.
 *
 * @return 0, with *result NULL and *h_error set when the lookup failed; ERANGE when
 *         @p buffer is too small for a rule-shaped answer.
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

/** @brief gethostbyname_r(3) wrapper: gethostbyname2_r() for AF_INET. */
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
 * @brief gethostbyname2(3) wrapper: dns:// rules of @p name.
 *
 * @return The entry (static storage, overwritten by the next call), or NULL with
 *         h_errno set.
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

/** @brief gethostbyname(3) wrapper: gethostbyname2() for AF_INET. */
CHAOS_DNS_EXPORT struct hostent *gethostbyname(const char *name)
{
    return gethostbyname2(name, AF_INET);
}

/** @brief The rdns:// key of a binary address (inet_ntop text); 0 for an unsupported one. */
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

/** @brief The REWRITE text for reverse key @p query when a rule fires; NULL otherwise. */
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
 * @brief gethostbyaddr_r(3) wrapper: rdns:// rules of the address.
 *
 * @details A firing REWRITE reserves strlen + 1 bytes at the end of @p buffer for the new
 * h_name and gives the real resolver the rest; a buffer smaller than the name fails with
 * ERANGE (h_errno NETDB_INTERNAL). The REWRITE fires (and counts) before the real call,
 * so it is counted even when the address does not resolve.
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

    if (g_chaos_dns_real_gethostbyaddr_r == NULL)
    {
        return chaos_dns_hostent_r_unresolved(result, h_error);
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

/**
 * @brief gethostbyaddr(3) wrapper: rdns:// rules of the address.
 *
 * @details A firing REWRITE replaces h_name with a copy in function-static storage
 * (CHAOS_DNS_MAX_VALUE bytes); not thread-safe, like the libc original's static entry.
 */
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

    if (g_chaos_dns_real_gethostbyaddr == NULL)
    {
        return chaos_dns_hostent_unresolved();
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
