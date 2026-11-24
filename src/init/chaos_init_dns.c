/**
 * @file chaos_init_dns.c
 * @brief `chaos-init`: libchaos-dns rules applied to a tracee's outgoing queries.
 *
 * @details The libchaos-dns rule core is compiled in by `#include`, unchanged. What is
 * new here is finding the query: the resolver is a library function, so the only thing
 * SECCOMP mode sees of a lookup is the packet it sends.
 *
 * @par How a query is recognised
 * By its own shape, not by a port. A notified send's payload is read out of the tracee
 * and parsed as a DNS message: one question, no answer bit, an opcode of QUERY, and a
 * `QNAME` of length-prefixed labels that ends inside the payload. A query over TCP
 * carries a two-byte length in front, which is skipped when it matches the rest. Anything
 * that does not parse is not a query and is left alone.
 *
 * A port test would be weaker, not stronger: it needs the socket's peer (two `/proc`
 * reads), misses a resolver on another port, and still has to parse the name. The shape
 * is what the name is in.
 *
 * @par What it applies
 * `LATENCY` only, which delays the query and so the lookup. The other effects of the
 * library change the *answer*, which the resolver assembles from what comes back: failing
 * the send would produce some resolution error rather than the `EAI_*` the rule names.
 * Such rules, and `rdns://` selectors, are rejected at load time
 * (CHAOS_DNS_RULE_SUPPORTED) so the status file says so.
 *
 * @par Cost
 * One notification per send of a process whose rules can act on it, plus one read of up
 * to 512 bytes out of the tracee. A rule file without a LATENCY rule notifies nothing.
 */

#include "chaos_init_dns.h"

/* Parser hook, defined before the core is included: rules this mode cannot apply reject
 * their file at load time. */
struct chaos_dns_rule;
static int chaos_init_dns_supported(const struct chaos_dns_rule *rule);
#define CHAOS_DNS_RULE_SUPPORTED(rule) chaos_init_dns_supported(rule)

#include "../dns/chaos_dns_actions.c"
#include "../dns/chaos_dns_config.c"
/* The actions file frees answer lists through this; the supervisor builds none, but the
 * reference has to resolve. */
#include "../dns/chaos_dns_owned.c"
#include "chaos_init_core.h"
#include "chaos_init_proc.h"
#include "chaos_init_tracee.h"

#include <sys/random.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>

/* Symbols the rule core expects from the preload library; the seed is replaced from
 * getrandom() in chaos_init_dns_start(). The supervisor resolves nothing itself, so the
 * real-function pointers stay NULL -- nothing here reaches them. */
chaos_dns_getaddrinfo_fn g_chaos_dns_real_getaddrinfo = NULL;
chaos_dns_getnameinfo_fn g_chaos_dns_real_getnameinfo = NULL;
chaos_dns_freeaddrinfo_fn g_chaos_dns_real_freeaddrinfo = NULL;
__thread int g_chaos_dns_tls_guard = 0;
uint64_t g_chaos_dns_lineage = 0U;
uint64_t g_chaos_dns_process_seed = UINT64_C(0x510e527fade682d1);

/* CHAOS_DNS_RULE_SUPPORTED: LATENCY on a forward selector. Everything else changes the
 * answer the resolver builds, which no reply to a send can do: the lookup would fail with
 * whatever error the resolver makes of it, not with the one the rule names. A reverse
 * selector cannot be matched either -- a PTR query carries `in-addr.arpa` labels, and the
 * rule names an address. */
static int chaos_init_dns_supported(const struct chaos_dns_rule *rule)
{
    return rule->effect == CHAOS_DNS_EFFECT_LATENCY &&
           rule->selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP;
}

/** @brief Longest payload read out of a tracee: a UDP query is at most this (RFC 1035). */
#define CHAOS_INIT_DNS_MAX_PAYLOAD 512U

/** @brief Longest name a query can carry, dots included (RFC 1035 §2.3.4). */
#define CHAOS_INIT_DNS_MAX_NAME 255U

/* Per-process hit slots of the dns rules. */
CHAOS_INIT_RULES_STORAGE(g_chaos_init_dns, CHAOS_DNS_MAX_RULES);

static uint64_t g_chaos_init_dns_load = 0U;
static const chaos_dns_config_state_t *g_chaos_init_dns_seen_state = NULL;
static uint64_t g_chaos_init_dns_seen_stamp = 0U;

/* chaos_init_rules_t::snapshot for dns; reload detection as in chaos_init_io.c. */
static size_t chaos_init_dns_snapshot(const chaos_init_text_t **texts, uint64_t *generation)
{
    const chaos_dns_config_state_t *state = chaos_dns_config_active_state();

    if (g_chaos_init_dns_load == 0U || state != g_chaos_init_dns_seen_state ||
        g_chaos_dns_cached_mtime != g_chaos_init_dns_seen_stamp)
    {
        g_chaos_init_dns_seen_state = state;
        g_chaos_init_dns_seen_stamp = g_chaos_dns_cached_mtime;
        ++g_chaos_init_dns_load;
    }
    *texts = (const chaos_init_text_t *)state->text;
    *generation = g_chaos_init_dns_load;
    return state->rule_count;
}

static chaos_init_rules_t g_chaos_init_dns_rules = {
    CHAOS_DNS_HITS_PREFIX,
    CHAOS_DNS_MAX_RULES,
    chaos_init_dns_snapshot,
    NULL,
    g_chaos_init_dns_slots,
    g_chaos_init_dns_hashes,
    g_chaos_init_dns_generation,
    g_chaos_init_dns_count,
    g_chaos_init_dns_total,
    g_chaos_init_dns_pending,
    g_chaos_init_dns_buffer,
    g_chaos_init_dns_file,
};

void chaos_init_dns_start(void)
{

    chaos_dns_config_init();
    g_chaos_dns_process_seed = chaos_init_seed();
    (void)chaos_init_tracee_register(&g_chaos_init_dns_rules);
}

/**
 * @brief Reads the name out of a DNS question, or reports that there is none.
 *
 * @details The message is a header of six 16-bit fields followed by the question. The
 * tests are the ones that make a false positive impossible in practice: the answer bit
 * clear, the opcode QUERY, exactly one question, and a QNAME whose labels end with a zero
 * byte inside the payload. A compression pointer (the two high bits of a length byte) is
 * not allowed in a question and ends the parse.
 *
 * @param payload  The bytes sent.
 * @param size     How many.
 * @param out      Receives the dotted name, NUL-terminated, as sent.
 * @param capacity Bytes @p out holds; CHAOS_INIT_DNS_MAX_NAME + 1, which is what makes
 *                 the length test the protocol's own limit.
 * @return 1 when @p out holds a name, else 0.
 */
static int
chaos_init_dns_question(const unsigned char *payload, size_t size, char *out, size_t capacity)
{
    size_t at = 12U;
    size_t length = 0U;

    /* A query over TCP is preceded by its own length. */
    if (size > 2U && ((size_t)payload[0] << 8 | payload[1]) == size - 2U)
    {
        payload += 2;
        size -= 2U;
    }
    if (size <= at || (payload[2] & 0x80U) != 0U || (payload[2] & 0x78U) != 0U ||
        ((size_t)payload[4] << 8 | payload[5]) != 1U)
    {
        return 0;
    }
    while (at < size && payload[at] != 0U)
    {
        const size_t label = payload[at];

        /* The capacity is the protocol's name limit plus the terminator, so one test
         * covers both: a name that does not fit is not a name. */
        if ((label & 0xc0U) != 0U || at + label + 1U > size || length + label + 1U >= capacity)
        {
            return 0;
        }
        if (length > 0U)
        {
            out[length++] = '.';
        }
        (void)memcpy(out + length, payload + at + 1U, label);
        length += label;
        at += label + 1U;
    }
    /* The root label has to be there, and a question is a name plus type and class. */
    if (at >= size || length == 0U || at + 5U > size)
    {
        return 0;
    }
    out[length] = '\0';
    return 1;
}

/**
 * @brief The payload of a send, as far as this decider needs it.
 *
 * @param address  Output: where the bytes are in the tracee.
 * @param size     Output: how many there are.
 * @return 1 when @p call is a send with one contiguous payload, else 0.
 */
static int chaos_init_dns_payload(const chaos_init_call_t *call, uint64_t *address, uint64_t *size)
{
    struct iovec vector;
    struct msghdr message;

    switch (call->nr)
    {
    case __NR_sendto:
    case __NR_write:
        *address = call->args[1];
        *size = call->args[2];
        return 1;
    case __NR_sendmsg:
    case __NR_sendmmsg:
        /* The first message of a batch, and its first segment: a resolver puts one query
         * in each, and the second message of a glibc batch asks for the same name. */
        if (chaos_init_read_memory(call->tid, call->args[1], &message, sizeof(message)) != 0 ||
            message.msg_iovlen == 0U || message.msg_iov == NULL ||
            chaos_init_read_memory(
                call->tid, (uint64_t)(uintptr_t)message.msg_iov, &vector, sizeof(vector)
            ) != 0)
        {
            return 0;
        }
        *address = (uint64_t)(uintptr_t)vector.iov_base;
        *size = vector.iov_len;
        return 1;
    default:
        return 0;
    }
}

int chaos_init_dns_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    const chaos_dns_config_state_t *state;
    unsigned char payload[CHAOS_INIT_DNS_MAX_PAYLOAD];
    char name[CHAOS_INIT_DNS_MAX_NAME + 1U];
    chaos_dns_rule_t rule;
    uint64_t address = 0U;
    uint64_t size = 0U;

    if (!chaos_init_dns_payload(call, &address, &size) || size == 0U || address == 0U)
    {
        return 0;
    }
    if (size > sizeof(payload))
    {
        size = sizeof(payload);
    }
    if (chaos_init_read_memory(call->tid, address, payload, (size_t)size) != 0 ||
        !chaos_init_dns_question(payload, (size_t)size, name, sizeof(name)) ||
        !chaos_dns_config_match(CHAOS_DNS_EFFECT_LATENCY, name, &rule))
    {
        return 0;
    }
    state = chaos_dns_config_active_state();
    rule.hit = chaos_init_tracee_hit(
        &g_chaos_init_dns_rules, call->tid, state->hits, state->rule_count, rule.hit
    );
    rule.hit_generation = rule.hit != NULL ? rule.hit->generation : 0U;
    if (rule.hit == NULL || !chaos_dns_rule_should_trigger(&rule))
    {
        return 0;
    }
    /* The query is held, not failed: what the resolver then sees is a slow name server,
     * which is what the rule says. */
    verdict->action = CHAOS_INIT_DELAY;
    verdict->delay_ms = rule.latency_ms;
    return 1;
}

size_t chaos_init_dns_calls(long *out, size_t capacity)
{
    static const long sends[] = {__NR_sendto, __NR_sendmsg, __NR_sendmmsg, __NR_write};
    size_t count = 0U;
    size_t index;

    if (out == NULL || !chaos_dns_config_prepare())
    {
        return 0U;
    }
    /* chaos_dns_config_prepare() above answers 1 only for a file that loaded at least one
     * rule, and any loaded rule is a LATENCY rule on a forward selector -- the parser
     * rejected everything else (chaos_init_dns_supported()). So the sends are worth
     * notifying exactly when it says so. */
    for (index = 0U; index < sizeof(sends) / sizeof(sends[0]); ++index)
    {
        if (count == capacity)
        {
            return count;
        }
        out[count++] = sends[index];
    }
    return count;
}
