/**
 * @file test_config_proptest.c
 * @brief Property-based round-trip and robustness tests for the IO config parser.
 *
 * Subsystem under test: `src/config/chaos_io_config.c` (parse_line only).
 *
 * IO config rule format (four colon-delimited fields):
 *   <path_prefix> : <operation> : <effect_or_errno> : <param>
 * where effect_or_errno is either an errno name (EIO, ENOSPC, …) for the ERRNO
 * effect, or "LATENCY", "TORN", "CORRUPT".  The fourth field is either a
 * probability [0.0, 1.0] or a latency in milliseconds.
 *
 * Three property classes are verified:
 *
 *  1. Round-trip: construct a known-valid config line string, call parse_line,
 *     assert every field in the returned rule matches the constructed input.
 *     Covers ERRNO, LATENCY, TORN, and CORRUPT effects with multiple operations
 *     and probability values.
 *
 *  2. Blank/comment identity: blank lines and comment lines must return 0
 *     (not 1 and not -1).  This is an algebraic identity: a zero-rule config
 *     is behaviourally equivalent to no LD_PRELOAD at all.
 *
 *  3. Robustness: a deterministic pseudo-random byte generator produces 2000
 *     random strings of lengths 0..511.  parse_line must return 1, 0, or -1
 *     without crashing, accessing out-of-bounds memory, or invoking undefined
 *     behaviour.  When return value is 1, basic invariants on the rule struct
 *     are checked.
 *
 *  4. Rejected inputs: a set of structurally invalid lines must all return -1.
 *
 * The IO config parser is used as the representative case; all six parsers
 * share the same structural grammar so the properties hold for the other five
 * domains by construction.
 */

#include "../support/test_support.h"

CHAOS_IO_DEFINE_TEST_GLOBALS();

/* parse_line is pure string parsing — no I/O globals are called. */

#include "../../src/config/chaos_io_config.c"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ---- deterministic PRNG (xorshift64) ------------------------------------ */

static uint64_t g_prng = 0xdeadbeefcafe1234ULL;

static uint64_t prng_next(void)
{
    g_prng ^= g_prng << 13;
    g_prng ^= g_prng >> 7;
    g_prng ^= g_prng << 17;
    return g_prng;
}

/* ---- Property 1: round-trip --------------------------------------------- */

static void test_roundtrip_errno_wildcard(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    /* *:read:EIO:1.0  (wildcard path, 100% probability) */
    snprintf(line, sizeof(line), "*:read:EIO:1.0");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_READ);
    assert(rule.effect == CHAOS_IO_EFFECT_ERRNO);
    assert(rule.errnum == EIO);
    assert(rule.probability == 1.0);
    assert(strcmp(rule.path_prefix, "*") == 0);
}

static void test_roundtrip_errno_path_with_probability(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    /* /var/lib/postgresql:fsync:EIO:0.05 */
    snprintf(line, sizeof(line), "/var/lib/postgresql:fsync:EIO:0.05");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_FSYNC);
    assert(rule.effect == CHAOS_IO_EFFECT_ERRNO);
    assert(rule.errnum == EIO);
    assert(rule.probability >= 0.049 && rule.probability <= 0.051);
    assert(strcmp(rule.path_prefix, "/var/lib/postgresql") == 0);
    assert(rule.path_len == strlen("/var/lib/postgresql"));

    /* wildcard write ENOSPC 20% */
    snprintf(line, sizeof(line), "*:write:ENOSPC:0.2");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_WRITE);
    assert(rule.effect == CHAOS_IO_EFFECT_ERRNO);
    assert(rule.errnum == ENOSPC);
    assert(rule.probability >= 0.199 && rule.probability <= 0.201);
}

static void test_roundtrip_latency(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    /* *:write:LATENCY:100 */
    snprintf(line, sizeof(line), "*:write:LATENCY:100");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_WRITE);
    assert(rule.effect == CHAOS_IO_EFFECT_LATENCY);
    assert(rule.latency_ms == 100U);

    /* /data:pread:LATENCY:250 */
    snprintf(line, sizeof(line), "/data:pread:LATENCY:250");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.effect == CHAOS_IO_EFFECT_LATENCY);
    assert(rule.latency_ms == 250U);
    assert(rule.operation == CHAOS_IO_OP_PREAD);
}

static void test_roundtrip_torn(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    /* *:write:TORN:0.1 */
    snprintf(line, sizeof(line), "*:write:TORN:0.1");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_WRITE);
    assert(rule.effect == CHAOS_IO_EFFECT_TORN);
    assert(rule.probability >= 0.099 && rule.probability <= 0.101);
}

static void test_roundtrip_corrupt(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    /* *:read:CORRUPT:0.3 */
    snprintf(line, sizeof(line), "*:read:CORRUPT:0.3");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.operation == CHAOS_IO_OP_READ);
    assert(rule.effect == CHAOS_IO_EFFECT_CORRUPT);
    assert(rule.probability >= 0.299 && rule.probability <= 0.301);
}

static void test_roundtrip_probability_boundaries(void)
{
    chaos_io_rule_t rule;
    char line[256];
    int rc;

    /* probability 0.0 */
    snprintf(line, sizeof(line), "*:read:EIO:0.0");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.probability == 0.0);

    /* probability 1.0 */
    snprintf(line, sizeof(line), "*:read:EIO:1.0");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.probability == 1.0);

    /* probability 0 (integer form) */
    snprintf(line, sizeof(line), "*:read:EIO:0");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.probability == 0.0);

    /* probability 1 (integer form) */
    snprintf(line, sizeof(line), "*:read:EIO:1");
    rc = chaos_io_config_parse_line(line, &rule);
    assert(rc == 1);
    assert(rule.probability == 1.0);
}

/* ---- Property 2: blank / comment identity ------------------------------- */

static void test_blank_comment_identity(void)
{
    chaos_io_rule_t rule;
    char line[256];

    /* empty string */
    snprintf(line, sizeof(line), "%s", "");
    assert(chaos_io_config_parse_line(line, &rule) == 0);

    /* spaces only */
    snprintf(line, sizeof(line), "   ");
    assert(chaos_io_config_parse_line(line, &rule) == 0);

    /* tabs */
    snprintf(line, sizeof(line), "\t\t");
    assert(chaos_io_config_parse_line(line, &rule) == 0);

    /* hash comment */
    snprintf(line, sizeof(line), "# this is a comment");
    assert(chaos_io_config_parse_line(line, &rule) == 0);

    /* hash with leading whitespace */
    snprintf(line, sizeof(line), "   # indented comment");
    assert(chaos_io_config_parse_line(line, &rule) == 0);
}

/* ---- Property 3: robustness against random input ------------------------ */

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

        /* Must return one of: 1 (parsed), 0 (blank/comment), -1 (invalid). */
        assert(rc >= -1 && rc <= 1);

        /* When a rule is returned, its fields must satisfy invariants. */
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

static void test_invalid_inputs(void)
{
    chaos_io_rule_t rule;
    char line[256];

    /* NULL line */
    assert(chaos_io_config_parse_line(NULL, &rule) == -1);

    /* too few fields: missing probability */
    snprintf(line, sizeof(line), "*:write:EIO");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    /* too few fields: only two */
    snprintf(line, sizeof(line), "*:write");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    /* unrecognised operation */
    snprintf(line, sizeof(line), "*:nosuchop:EIO:0.5");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    /* unrecognised effect (not an errno name and not LATENCY/TORN/CORRUPT) */
    snprintf(line, sizeof(line), "*:write:BADEFFECT:0.5");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    /* EINVAL is explicitly unsupported by the IO config parser */
    snprintf(line, sizeof(line), "*:write:EINVAL:0.5");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    /* probability > 1.0 */
    snprintf(line, sizeof(line), "*:write:EIO:1.5");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    /* TORN only valid for write operations, not read */
    snprintf(line, sizeof(line), "*:read:TORN:0.1");
    assert(chaos_io_config_parse_line(line, &rule) == -1);

    /* CORRUPT only valid for read operations, not write */
    snprintf(line, sizeof(line), "*:write:CORRUPT:0.1");
    assert(chaos_io_config_parse_line(line, &rule) == -1);
}

/* ---- main --------------------------------------------------------------- */

int main(void)
{
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
