/**
 * @file test_config_proptest.c
 * @brief Property tests for the libchaos-io rule line parser: valid lines round-trip into
 *        the rule struct, blank and comment lines yield no rule, malformed lines are
 *        rejected, and arbitrary bytes never break it.
 *
 * @details Unit under test: `chaos_io_config_parse_line()` in
 * `src/config/chaos_io_config.c`, compiled in by `#include`. Grammar of a rule line:
 * `<path_prefix>:<operation>:<effect>:<param>`, where `<effect>` is an accepted errno name
 * (ERRNO effect) or LATENCY, TORN, CORRUPT, and `<param>` is a probability in [0, 1]
 * (milliseconds for LATENCY). The parser is pure string processing on a mutable buffer,
 * so no rule file and no wrapper is involved.
 *
 * Properties:
 * 1. Round-trip: every field of a known-valid line lands in the rule (operation, effect,
 *    errnum, probability, latency, path prefix and its length), for all four effects.
 * 2. No-rule lines: empty, whitespace-only and `#` comment lines return 0, not 1 or -1,
 *    so they neither add a rule nor reject the file.
 * 3. Robustness: 2000 strings of 0..510 random bytes from a fixed-seed xorshift64 always
 *    return -1, 0 or 1; a returned rule satisfies the struct invariants. Out-of-bounds
 *    access is caught only when this test runs under the ASan/UBSan builds.
 * 4. Rejection: NULL, too few fields, unknown operation or effect, an errno name outside
 *    the accepted list (EINVAL), probability > 1, TORN on a read, CORRUPT on a write.
 *
 * Scope: libchaos-io only. The other libraries' rule grammars differ in field count and
 * semantics and have their own config suites.
 */

#include "../support/test_support.h"

CHAOS_IO_DEFINE_TEST_GLOBALS();

/* parse_line touches no file and calls no real function; the globals only satisfy the link. */

#include "../../src/config/chaos_io_config.c"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ---- fixed-seed xorshift64: failures reproduce bit for bit ---------------- */

static uint64_t g_prng = 0xdeadbeefcafe1234ULL;

static uint64_t prng_next(void)
{
    g_prng ^= g_prng << 13;
    g_prng ^= g_prng >> 7;
    g_prng ^= g_prng << 17;
    return g_prng;
}

/* ---- Property 1: round-trip --------------------------------------------- */

/** @brief ERRNO with the `*` prefix at probability 1.0 round-trips exactly. */
static void test_roundtrip_errno_wildcard(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    snprintf(line, sizeof(line), "*:read:EIO:1.0");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_READ);
    assert(rule.effect == CHAOS_IO_EFFECT_ERRNO);
    assert(rule.errnum == EIO);
    assert(rule.probability == 1.0);
    assert(strcmp(rule.path_prefix, "*") == 0);
}

/**
 * @brief ERRNO with a path prefix records the prefix and its length; fractional
 *        probabilities are compared within +-0.001 to tolerate binary rounding.
 */
static void test_roundtrip_errno_path_with_probability(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    snprintf(line, sizeof(line), "/var/lib/postgresql:fsync:EIO:0.05");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_FSYNC);
    assert(rule.effect == CHAOS_IO_EFFECT_ERRNO);
    assert(rule.errnum == EIO);
    assert(rule.probability >= 0.049 && rule.probability <= 0.051);
    assert(strcmp(rule.path_prefix, "/var/lib/postgresql") == 0);
    assert(rule.path_len == strlen("/var/lib/postgresql"));

    snprintf(line, sizeof(line), "*:write:ENOSPC:0.2");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_WRITE);
    assert(rule.effect == CHAOS_IO_EFFECT_ERRNO);
    assert(rule.errnum == ENOSPC);
    assert(rule.probability >= 0.199 && rule.probability <= 0.201);
}

/** @brief LATENCY takes milliseconds, not a probability, in the fourth field. */
static void test_roundtrip_latency(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    snprintf(line, sizeof(line), "*:write:LATENCY:100");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_WRITE);
    assert(rule.effect == CHAOS_IO_EFFECT_LATENCY);
    assert(rule.latency_ms == 100U);

    snprintf(line, sizeof(line), "/data:pread:LATENCY:250");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.effect == CHAOS_IO_EFFECT_LATENCY);
    assert(rule.latency_ms == 250U);
    assert(rule.operation == CHAOS_IO_OP_PREAD);
}

/** @brief TORN on a write-class operation is accepted with its probability. */
static void test_roundtrip_torn(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    snprintf(line, sizeof(line), "*:write:TORN:0.1");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_WRITE);
    assert(rule.effect == CHAOS_IO_EFFECT_TORN);
    assert(rule.probability >= 0.099 && rule.probability <= 0.101);
}

/** @brief CORRUPT on a read-class operation is accepted with its probability. */
static void test_roundtrip_corrupt(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    snprintf(line, sizeof(line), "*:read:CORRUPT:0.3");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_READ);
    assert(rule.effect == CHAOS_IO_EFFECT_CORRUPT);
    assert(rule.probability >= 0.299 && rule.probability <= 0.301);
}

/** @brief Probability bounds 0 and 1 are inclusive, in decimal and integer form. */
static void test_roundtrip_probability_boundaries(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    snprintf(line, sizeof(line), "*:read:EIO:0.0");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.probability == 0.0);

    snprintf(line, sizeof(line), "*:read:EIO:1.0");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.probability == 1.0);

    /* Integer forms. */
    snprintf(line, sizeof(line), "*:read:EIO:0");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.probability == 0.0);

    snprintf(line, sizeof(line), "*:read:EIO:1");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.probability == 1.0);
}

/* ---- Property 2: blank / comment identity ------------------------------- */

/** @brief Lines without a rule return 0, including comments after leading whitespace. */
static void test_blank_comment_identity(void)
{
    chaos_io_rule_t rule;
    char line[256];

    snprintf(line, sizeof(line), "%s", "");
    assert(chaos_io_config_parse_line(line, &rule) == 0);

    snprintf(line, sizeof(line), "   ");
    assert(chaos_io_config_parse_line(line, &rule) == 0);

    snprintf(line, sizeof(line), "\t\t");
    assert(chaos_io_config_parse_line(line, &rule) == 0);

    snprintf(line, sizeof(line), "# this is a comment");
    assert(chaos_io_config_parse_line(line, &rule) == 0);

    snprintf(line, sizeof(line), "   # indented comment");
    assert(chaos_io_config_parse_line(line, &rule) == 0);
}

/* ---- Property 3: robustness against random input ------------------------ */

/**
 * @brief Arbitrary bytes (embedded NULs shorten the string, high bytes included) never
 *        produce an out-of-range return or an inconsistent rule.
 */
static void test_robustness(void)
{
    char buf[512];
    chaos_io_rule_t rule;
    int i;
    int j;
    int rc;

    for (i = 0; i < 2000; ++i)
    {
        size_t len = (size_t)(prng_next() % (sizeof(buf) - 1U));
        for (j = 0; j < (int)len; ++j)
            buf[j] = (char)(prng_next() & 0xff);
        buf[len] = '\0';

        rc = chaos_io_config_parse_line(buf, &rule);

        assert(rc >= -1 && rc <= 1);

        /* A returned rule is internally consistent. */
        if (rc == 1)
        {
            assert(rule.operation != CHAOS_IO_OP_INVALID);
            assert(rule.effect != CHAOS_IO_EFFECT_INVALID);
            assert(rule.probability >= 0.0 && rule.probability <= 1.0);
            assert(rule.path_len == strlen(rule.path_prefix));
        }
    }
}

/* ---- Property 4: invalid inputs → -1 ----------------------------------- */

/** @brief Structurally or semantically invalid lines return -1 (the file is rejected). */
static void test_invalid_inputs(void)
{
    chaos_io_rule_t rule;
    char line[256];

    assert(chaos_io_config_parse_line(NULL, &rule) == -1);

    /* Too few fields. */
    snprintf(line, sizeof(line), "*:write:EIO");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    snprintf(line, sizeof(line), "*:write");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    /* Unknown operation; unknown effect (neither an accepted errno name nor an effect). */
    snprintf(line, sizeof(line), "*:nosuchop:EIO:0.5");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    snprintf(line, sizeof(line), "*:write:BADEFFECT:0.5");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    /* A real errno outside the accepted storage-error list, and probability > 1. */
    snprintf(line, sizeof(line), "*:write:EINVAL:0.5");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    snprintf(line, sizeof(line), "*:write:EIO:1.5");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    /* TORN needs a write-class operation, CORRUPT a read-class one. */
    snprintf(line, sizeof(line), "*:read:TORN:0.1");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    snprintf(line, sizeof(line), "*:write:CORRUPT:0.1");
    assert(chaos_io_config_parse_line(line, &rule) == -1);
}

/* ---- main --------------------------------------------------------------- */

int main(void)
{
    /* Re-check the rule file on every call (no reload throttle); the throttle has its own test. */
    g_chaos_io_check_interval_ns = 0U;
    chaos_io_config_init();

    test_roundtrip_errno_wildcard();
    test_roundtrip_errno_path_with_probability();
    test_roundtrip_latency();
    test_roundtrip_torn();
    test_roundtrip_corrupt();
    test_roundtrip_probability_boundaries();
    test_blank_comment_identity();
    test_robustness();
    test_invalid_inputs();

    puts("PROPTEST: OK");
    return 0;
}
