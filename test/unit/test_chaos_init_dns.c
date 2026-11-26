/**
 * @file test_chaos_init_dns.c
 * @brief Proves chaos-init finds the name in a tracee's outgoing DNS query and delays the
 *        send by the rule for that name -- and that it leaves everything else alone.
 *
 * @details Unit under test: `chaos_init_dns_decide()` and `chaos_init_dns_calls()` in
 * `src/init/chaos_init_dns.c`, compiled in by `#include` together with the libchaos-dns
 * rule core it embeds, `chaos_init_proc.c` (the read out of the tracee) and
 * `chaos_init_tracee.c` (per-process hit slots).
 *
 * Isolation: no supervisor, no seccomp filter and no tracee. Each call is a
 * `chaos_init_call_t` filled the way a seccomp notification fills it, with this test
 * process as the caller (`tid = getpid()`), so the payload is read out of this process's
 * own memory through the real process_vm_readv(). Queries are built by hand, which is the
 * only way to ask what a malformed one does. The rule file is replaced by an atomic
 * rename(2), and `g_chaos_dns_check_interval_ns = 0` makes every decision re-check it.
 *
 * Properties proven:
 * - the name is read out of a `sendto`, a `write`, a `sendmsg` and the first message of a
 *   `sendmmsg` batch, and matched exactly and by suffix;
 * - a query over TCP, which carries its length in front, is read the same way;
 * - what is not a question is not treated as one: an answer, an opcode other than QUERY,
 *   a question count other than one, a label that runs past the payload, a compression
 *   pointer, a name without its root label, a name longer than a name may be, and a
 *   question without type and class;
 * - a call that carries no payload the decider can reach -- another system call, a NULL
 *   buffer, an empty one, an unreadable `msghdr`, an iovec of no segments -- returns 0, so
 *   the same send is still net's to decide;
 * - a matched query is held for the rule's latency and counts one hit; a name no rule
 *   names is not;
 * - the filter is asked for the resolver's sends only while a LATENCY rule is loaded;
 * - every other effect, and every `rdns://` selector, rejects the whole rule file: the
 *   answer is assembled inside the resolver, where no reply to a send reaches it.
 */

#include "../../src/init/chaos_init_dns.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_tracee.c"

/* The seed source lives in chaos_init_core.c, which this test does not include; the
 * declaration comes from chaos_init_core.h, so the definition may follow the include. A
 * fixed value keeps the rules' draw keys the same in every run. */
uint64_t chaos_init_seed(void)
{
    return UINT64_C(0x5eed5eed5eed5eed);
}

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

/** @brief Replaces the rule file by rename(2), so a reload never sees a partial file. */
static void write_rules(const char *rules)
{
    FILE *file = fopen("/tmp/.chaos-dns.conf.new", "w");

    assert(file != NULL && fputs(rules, file) >= 0 && fclose(file) == 0);
    assert(rename("/tmp/.chaos-dns.conf.new", "/tmp/.chaos-dns.conf") == 0);
}

/**
 * @brief Builds a query for @p name into @p out.
 *
 * @param prefixed  Non-zero for the two-byte length a query over TCP carries.
 * @return The length written.
 */
static size_t build_query(unsigned char *out, const char *name, int prefixed)
{
    size_t at = prefixed ? 14U : 12U;
    const size_t header = prefixed ? 2U : 0U;
    const char *label = name;

    (void)memset(out, 0, at);
    out[header + 0U] = 0x12;
    out[header + 1U] = 0x34;
    out[header + 5U] = 1U; /* one question */
    while (*label != '\0')
    {
        const char *dot = strchr(label, '.');
        const size_t length = dot != NULL ? (size_t)(dot - label) : strlen(label);

        out[at++] = (unsigned char)length;
        (void)memcpy(out + at, label, length);
        at += length;
        label = dot != NULL ? dot + 1 : label + length;
    }
    out[at++] = 0U; /* the root label */
    out[at++] = 0U;
    out[at++] = 1U; /* QTYPE A */
    out[at++] = 0U;
    out[at++] = 1U; /* QCLASS IN */
    if (prefixed)
    {
        out[0] = (unsigned char)((at - 2U) >> 8);
        out[1] = (unsigned char)((at - 2U) & 0xffU);
    }
    return at;
}

/** @brief Address of @p pointer as a call argument. */
#define P(pointer) ((uint64_t)(uintptr_t)(pointer))

/** @brief Decides a send of @p size bytes at @p payload made by this process. */
static chaos_init_verdict_t decide(int nr, const void *payload, size_t size, int *owned)
{
    chaos_init_call_t call;
    chaos_init_verdict_t verdict;

    memset(&call, 0, sizeof(call));
    memset(&verdict, 0, sizeof(verdict));
    call.tid = getpid();
    call.nr = nr;
    call.args[0] = 7U;
    call.args[1] = P(payload);
    call.args[2] = size;
    verdict.action = CHAOS_INIT_PASS;
    *owned = chaos_init_dns_decide(&call, &verdict);
    return verdict;
}

/** @brief Whether the query for @p name is held for @p delay_ms. */
static int delays(const char *name, unsigned delay_ms)
{
    unsigned char query[512];
    const size_t length = build_query(query, name, 0);
    chaos_init_verdict_t verdict;
    int owned = 0;

    verdict = decide(__NR_sendto, query, length, &owned);
    return owned && verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == delay_ms;
}

int main(void)
{
    unsigned char query[512];
    unsigned char broken[512];
    chaos_init_call_t call;
    chaos_init_verdict_t verdict;
    size_t length;
    long calls[8];
    char hits[256];
    char path[64];
    FILE *file;
    int owned = 0;

    (void)unlink("/tmp/.chaos-dns.conf");
    chaos_init_dns_start();
    g_chaos_dns_check_interval_ns = 0U;

    /* No rule file: a query is nobody's business here, and the filter stays empty. */
    length = build_query(query, "slow.example.com", 0);
    (void)decide(__NR_sendto, query, length, &owned);
    assert(owned == 0);
    assert(chaos_init_dns_calls(calls, sizeof(calls) / sizeof(calls[0])) == 0U);

    /* The name in the query decides, and only that name. */
    write_rules("dns://slow.example.com:LATENCY:300\n");
    assert(delays("slow.example.com", 300U));
    assert(!delays("fast.example.com", 300U));
    assert(!delays("example.com", 300U));
    /* A suffix rule reaches every name below it, not the suffix itself. */
    write_rules("dns://*.example.com:LATENCY:120\n");
    assert(delays("any.example.com", 120U));
    assert(delays("deep.any.example.com", 120U));
    assert(!delays("example.com", 120U));

    /* A rule that matches and does not fire leaves the send alone: a probability of zero
     * never draws a delay, and the call is still net's to decide. */
    write_rules("dns://slow.example.com:LATENCY:300@0\n");
    length = build_query(query, "slow.example.com", 0);
    (void)decide(__NR_sendto, query, length, &owned);
    assert(owned == 0);

    /* Every send a resolver uses carries the query the same way. */
    write_rules("dns://slow.example.com:LATENCY:40\n");
    length = build_query(query, "slow.example.com", 0);
    assert(decide(__NR_write, query, length, &owned).delay_ms == 40U && owned);
    {
        struct iovec vector;
        struct msghdr message;
        struct mmsghdr batch[2];

        vector.iov_base = query;
        vector.iov_len = length;
        memset(&message, 0, sizeof(message));
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        assert(decide(__NR_sendmsg, &message, sizeof(message), &owned).delay_ms == 40U && owned);
        memset(batch, 0, sizeof(batch));
        batch[0].msg_hdr = message;
        batch[1].msg_hdr = message;
        assert(decide(__NR_sendmmsg, batch, sizeof(batch), &owned).delay_ms == 40U && owned);
        /* A message without segments, and a header that cannot be read, carry nothing. */
        message.msg_iovlen = 0;
        (void)decide(__NR_sendmsg, &message, sizeof(message), &owned);
        assert(owned == 0);
        message.msg_iovlen = 1;
        message.msg_iov = NULL;
        (void)decide(__NR_sendmsg, &message, sizeof(message), &owned);
        assert(owned == 0);
        memset(&call, 0, sizeof(call));
        call.tid = getpid();
        call.nr = __NR_sendmsg;
        call.args[1] = 8U; /* not a readable address */
        call.args[2] = sizeof(message);
        assert(chaos_init_dns_decide(&call, &verdict) == 0);
    }
    /* A query over TCP carries its length in front. */
    length = build_query(query, "slow.example.com", 1);
    assert(decide(__NR_write, query, length, &owned).delay_ms == 40U && owned);

    /* What is not a question is not treated as one. */
    length = build_query(broken, "slow.example.com", 0);
    {
        unsigned char keep;
        size_t index;

        keep = broken[2];
        broken[2] = 0x80U; /* an answer, not a query */
        (void)decide(__NR_sendto, broken, length, &owned);
        assert(owned == 0);
        broken[2] = 0x28U; /* an opcode other than QUERY */
        (void)decide(__NR_sendto, broken, length, &owned);
        assert(owned == 0);
        broken[2] = keep;
        broken[5] = 2U; /* two questions */
        (void)decide(__NR_sendto, broken, length, &owned);
        assert(owned == 0);
        broken[5] = 0U; /* none at all */
        (void)decide(__NR_sendto, broken, length, &owned);
        assert(owned == 0);
        broken[5] = 1U;
        broken[12] = 0xc0U; /* a compression pointer, which a question may not hold */
        (void)decide(__NR_sendto, broken, length, &owned);
        assert(owned == 0);
        /* A label whose content runs past the payload. 200 would not test this: its high
         * bits make it a compression pointer, which the clause above rejects first.
         *
         * The bound this reaches is redundancy rather than a guard, and the test says so
         * because the next reader will wonder: the capacity check caps a name at 255
         * characters and therefore `at` at about 268, so in a 512-byte payload the copy
         * can never reach the end of the buffer. Measured: removing the bound entirely
         * leaves the suite green under ASan, because a name that walks past `size` is
         * refused by the root-label check behind the loop. It stays as the cheap half of
         * the pair, so a later change to either limit cannot turn into a read. */
        broken[12] = 60U;
        (void)decide(__NR_sendto, broken, length, &owned);
        assert(owned == 0);
        /* The root label and the type and class behind it have to be there. */
        (void)build_query(broken, "slow.example.com", 0);
        (void)decide(__NR_sendto, broken, 17U, &owned);
        assert(owned == 0);
        (void)decide(__NR_sendto, broken, length - 2U, &owned);
        assert(owned == 0);
        /* A header alone is not a question either. */
        (void)decide(__NR_sendto, broken, 12U, &owned);
        assert(owned == 0);
        /* A compression pointer whose value would fit as a label is still not one. Read
         * as a length it would make the bytes behind it one label, and a label may hold
         * anything -- dots included -- so this payload would match the suffix rule and be
         * held as a query for a name nobody sent. The rule does match that name when it
         * arrives as labels, which is what makes the first answer the test. */
        write_rules("dns://*.example.com:LATENCY:70\n");
        assert(delays("a.example.com", 70U));
        (void)memset(broken, 0, sizeof(broken));
        broken[5] = 1U;
        broken[12] = 0xc0U; /* 192 read as a length, which fits in a 300-byte payload */
        (void)memset(broken + 13, 'a', 192U);
        (void)memcpy(broken + 13 + 192U - 12U, ".example.com", 12U);
        broken[13 + 192U] = 0U;
        broken[13 + 192U + 3U] = 1U;
        (void)decide(__NR_sendto, broken, 300U, &owned);
        assert(owned == 0);
        write_rules("dns://slow.example.com:LATENCY:40\n");

        /* The capacity guard, pinned from both sides. A rule that matches any name ending
         * in `.abc` is loaded first, so these assertions see whether the name was built at
         * all -- `owned == 0` alone passes for a name that parsed and matched nothing,
         * which is why the old case here proved nothing.
         *
         * 64 labels of three bytes is a name of exactly 255 characters: the longest one
         * the protocol allows, and it must parse. One more character must not, because the
         * terminator would then be written one byte past the 256-byte name. */
        write_rules("dns://*.abc:LATENCY:90\n");
        (void)memset(broken, 0, sizeof(broken));
        broken[5] = 1U;
        for (index = 0U; index < 64U; ++index)
        {
            broken[12U + index * 4U] = 3U;
            (void)memcpy(broken + 13U + index * 4U, "abc", 3U);
        }
        assert(decide(__NR_sendto, broken, 12U + 64U * 4U + 6U, &owned).delay_ms == 90U);
        assert(owned);
        /* 63 labels of three plus one of four: 256 characters, one too many. */
        (void)memset(broken, 0, sizeof(broken));
        broken[5] = 1U;
        for (index = 0U; index < 63U; ++index)
        {
            broken[12U + index * 4U] = 3U;
            (void)memcpy(broken + 13U + index * 4U, "abc", 3U);
        }
        broken[12U + 63U * 4U] = 4U;
        (void)memcpy(broken + 13U + 63U * 4U, "wabc", 4U);
        (void)decide(__NR_sendto, broken, 12U + 63U * 4U + 5U + 6U, &owned);
        assert(owned == 0);
        write_rules("dns://slow.example.com:LATENCY:40\n");
    }

    /* Calls and payloads the decider leaves alone: another system call, no buffer, no
     * bytes, and a buffer it cannot read. */
    length = build_query(query, "slow.example.com", 0);
    (void)decide(__NR_getpid, query, length, &owned);
    assert(owned == 0);
    (void)decide(__NR_sendto, NULL, length, &owned);
    assert(owned == 0);
    (void)decide(__NR_sendto, query, 0U, &owned);
    assert(owned == 0);
    memset(&call, 0, sizeof(call));
    call.tid = getpid();
    call.nr = __NR_sendto;
    call.args[1] = 8U;
    call.args[2] = 32U;
    assert(chaos_init_dns_decide(&call, &verdict) == 0);
    /* More than a query can be: only the first 512 bytes are read, which still hold the
     * question. */
    assert(decide(__NR_sendto, query, 4096U, &owned).delay_ms == 40U && owned);

    /* The filter is asked for the resolver's sends, and only while a rule can act on
     * one. Neither list writes past its capacity, and neither needs a buffer at all. */
    assert(chaos_init_dns_calls(calls, sizeof(calls) / sizeof(calls[0])) == 4U);
    assert(calls[0] == __NR_sendto && calls[3] == __NR_write);
    assert(chaos_init_dns_calls(calls, 2U) == 2U);
    assert(chaos_init_dns_calls(calls, 0U) == 0U);
    assert(chaos_init_dns_calls(NULL, 4U) == 0U);

    /* The hits file counts the queries that were held, as under LD_PRELOAD. */
    (void)snprintf(path, sizeof(path), "/tmp/.chaos-dns.hits.%ld", (long)getpid());
    file = fopen(path, "r");
    assert(file != NULL);
    hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
    (void)fclose(file);
    assert(strstr(hits, "\tdns://slow.example.com:LATENCY:40\n") != NULL);

    /* Every other effect rejects the whole file: the answer is assembled inside the
     * resolver, so a reply to the send cannot produce the one the rule names. A reverse
     * selector cannot be matched at all -- a PTR query carries in-addr.arpa labels. */
    {
        static const char *const rejected[] = {
            "dns://x.example.com:EAI_NONAME:1.0\n",
            "dns://x.example.com:REWRITE:other.example.com\n",
            "dns://x.example.com:OVERRIDE:10.0.0.1\n",
            "dns://x.example.com:SERVICE:81\n",
            "dns://x.example.com:FILTER_FAMILY:inet6\n",
            "dns://x.example.com:SHUFFLE:1.0\n",
            "dns://x.example.com:LIMIT:1\n",
            "rdns://1.2.3.4:LATENCY:100\n",
            "dns://slow.example.com:LATENCY:40\nrdns://*:LATENCY:10\n"
        };
        size_t index;

        for (index = 0U; index < sizeof(rejected) / sizeof(rejected[0]); ++index)
        {
            write_rules(rejected[index]);
            assert(!delays("slow.example.com", 40U));
            file = fopen("/tmp/.chaos-dns.status", "r");
            assert(file != NULL);
            hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
            (void)fclose(file);
            assert(strstr(hits, "reason=unsupported in seccomp mode\n") != NULL);
            assert(chaos_init_dns_calls(calls, sizeof(calls) / sizeof(calls[0])) == 0U);
        }
    }

    (void)unlink("/tmp/.chaos-dns.conf");
    (void)unlink(path);
    /* A reload without a call: what the inotify watch of chaos_init.c asks for when a
     * rule file is put in place, so that the status file reports the rules before anything
     * has called into them. Two rules, because every file loaded above has one or none: a
     * status that said anything else would mean the reload did nothing. */
    write_rules("dns://a.example.com:LATENCY:5\ndns://b.example.com:LATENCY:5\n");
    chaos_init_dns_reload();
    {
        FILE *reloaded = fopen("/tmp/.chaos-dns.status", "r");
        char text[256] = {0};

        assert(reloaded != NULL);
        text[fread(text, 1U, sizeof(text) - 1U, reloaded)] = '\0';
        (void)fclose(reloaded);
        assert(strncmp(text, "state=ok\nrules=2\n", strlen("state=ok\nrules=2\n")) == 0);
    }

    return 0;
}
