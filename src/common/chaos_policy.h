/**
 * @file chaos_policy.h
 * @brief Rule qualifiers shared by every library: `@first`, `@from`, `@until`, `@size`.
 *
 * @details
 * Each library has its own rule grammar, but all of them accept the same
 * qualifiers, written as separate words after the rule and before any comment:
 *
 * @code
 * tcp4://127.0.0.1:5432:connect:ECONNREFUSED:1.0 @first=3 # net
 * /data:write:EIO:1.0 @from=1760000000000 @until=1760000005000
 * tcp4://127.0.0.1:9092:send:LATENCY:200 @size>65536
 * @endcode
 *
 * - `@first=N`  the rule fires at most N times in a process, then goes inert:
 *   start-up faults that clear by themselves.
 * - `@from=T`, `@until=T`  the rule is active only while the wall clock (Unix
 *   milliseconds) is in [from, until). One rule file can hold a whole incident
 *   timeline; every process agrees on it, unlike a time relative to when each
 *   process happened to load the file.
 * - `@size>N`, `@size<N`  the rule applies only to calls that move more than (or
 *   fewer than) N bytes. Calls without a byte count never match a size-gated rule.
 *
 * An unknown or malformed qualifier rejects the line like any other invalid rule.
 */

#ifndef CHAOS_POLICY_H
#define CHAOS_POLICY_H

#include "chaos_clock.h"
#include "chaos_hits.h"

#include <stdint.h>
#include <string.h>

/** @brief Byte count of a call that has none; never satisfies a size gate. */
#define CHAOS_POLICY_NO_SIZE UINT64_MAX

/** @brief Qualifiers of one rule; all zero means none. */
typedef struct chaos_rule_policy
{
    uint64_t first;      /**< `@first=N`; 0 for no limit. */
    int64_t from_ms;     /**< `@from=T`; 0 for no lower bound. */
    int64_t until_ms;    /**< `@until=T`; 0 for no upper bound. */
    uint64_t size_above; /**< `@size>N`, valid when has_size_above. */
    uint64_t size_below; /**< `@size<N`, valid when has_size_below. */
    unsigned char has_size_above;
    unsigned char has_size_below;
} chaos_rule_policy_t;

/**
 * @brief Parses a probability as the rule grammar defines it: "0", "1", "0." and
 *        digits, or "1." and zeros; trailing blanks are allowed. -1 otherwise.
 *
 * @details Independent of the locale, unlike strtod: an application may set
 * LC_NUMERIC (the JVM calls setlocale(LC_ALL, "")), and under a German locale
 * strtod stops at the '.' of "0.5". strtod also takes nan, inf, hexadecimal and
 * exponents, none of which is a probability. The first 15 decimals are exact;
 * further digits are checked but below a double's precision.
 */
static inline int chaos_policy_parse_probability(const char *text, double *probability)
{
    uint64_t decimals = 0U;
    double scale = 1.0;
    int one;

    if (text == NULL || probability == NULL || (*text != '0' && *text != '1'))
    {
        return -1;
    }
    one = *text++ == '1';
    if (*text == '.')
    {
        ++text;
        if (*text < '0' || *text > '9')
        {
            return -1;
        }
        for (; *text >= '0' && *text <= '9'; ++text)
        {
            if (one && *text != '0')
            {
                return -1;
            }
            if (scale < 1e15)
            {
                decimals = decimals * 10U + (uint64_t)(*text - '0');
                scale *= 10.0;
            }
        }
    }
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n')
    {
        ++text;
    }
    if (*text != '\0')
    {
        return -1;
    }
    *probability = one ? 1.0 : (double)decimals / scale;
    return 0;
}

/** @brief Parses a decimal number of at most 18 digits; -1 when @p text is not one. */
static inline int chaos_policy_parse_number(const char *text, uint64_t *value)
{
    uint64_t result = 0U;
    size_t digits = 0U;

    if (*text == '\0')
    {
        return -1;
    }
    for (; *text != '\0'; ++text, ++digits)
    {
        if (*text < '0' || *text > '9' || digits >= 18U)
        {
            return -1;
        }
        result = result * 10U + (uint64_t)(*text - '0');
    }
    *value = result;
    return 0;
}

/** @brief Applies one `@...` word to @p policy; -1 when it is not a known qualifier. */
static inline int chaos_policy_parse_word(const char *word, chaos_rule_policy_t *policy)
{
    uint64_t value;

    if (strncmp(word, "@first=", 7U) == 0 && chaos_policy_parse_number(word + 7, &value) == 0 &&
        value > 0U)
    {
        policy->first = value;
        return 0;
    }
    if (strncmp(word, "@from=", 6U) == 0 && chaos_policy_parse_number(word + 6, &value) == 0)
    {
        policy->from_ms = (int64_t)value;
        return 0;
    }
    if (strncmp(word, "@until=", 7U) == 0 && chaos_policy_parse_number(word + 7, &value) == 0)
    {
        policy->until_ms = (int64_t)value;
        return 0;
    }
    if (strncmp(word, "@size>", 6U) == 0 && chaos_policy_parse_number(word + 6, &value) == 0)
    {
        policy->size_above = value;
        policy->has_size_above = 1U;
        return 0;
    }
    if (strncmp(word, "@size<", 6U) == 0 && chaos_policy_parse_number(word + 6, &value) == 0)
    {
        policy->size_below = value;
        policy->has_size_below = 1U;
        return 0;
    }
    return -1;
}

/**
 * @brief Removes the qualifiers from the end of @p line and parses them.
 *
 * @details Qualifiers are the trailing whitespace-separated words that start with
 * `@`, before any `#` comment. The line is cut before the first of them (and the
 * comment with it), so the library's own parser sees only the rule. A line with
 * no qualifiers is left as it is.
 *
 * @return 0, or -1 when a qualifier is unknown or malformed, or an `@until`
 *         precedes its `@from`.
 */
static inline int chaos_policy_extract(char *line, chaos_rule_policy_t *policy)
{
    char *comment = strchr(line, '#');
    char *end = comment != NULL ? comment : line + strlen(line);
    char *cut = NULL;

    memset(policy, 0, sizeof(*policy));
    for (;;)
    {
        char *word_end = end;
        char *word;
        char saved;

        while (word_end > line &&
               (word_end[-1] == ' ' || word_end[-1] == '\t' || word_end[-1] == '\r'))
        {
            --word_end;
        }
        word = word_end;
        while (word > line && word[-1] != ' ' && word[-1] != '\t')
        {
            --word;
        }
        if (word == word_end || *word != '@' || word == line)
        {
            break;
        }
        saved = *word_end;
        *word_end = '\0';
        if (chaos_policy_parse_word(word, policy) != 0)
        {
            *word_end = saved;
            return -1;
        }
        *word_end = saved;
        cut = word;
        end = word;
    }
    if (cut != NULL)
    {
        *cut = '\0';
    }
    if (policy->from_ms != 0 && policy->until_ms != 0 && policy->until_ms <= policy->from_ms)
    {
        return -1;
    }
    return 0;
}

/** @brief Whether @p policy carries no qualifier at all. */
static inline int chaos_policy_is_empty(const chaos_rule_policy_t *policy)
{
    return policy->first == 0U && policy->from_ms == 0 && policy->until_ms == 0 &&
           !policy->has_size_above && !policy->has_size_below;
}

/** @brief Whether the wall clock is inside the rule's `@from`/`@until` window. */
static inline int chaos_policy_window_open(const chaos_rule_policy_t *policy)
{
    int64_t now;

    if (policy->from_ms == 0 && policy->until_ms == 0)
    {
        return 1;
    }
    now = chaos_clock_realtime_ms();
    return (policy->from_ms == 0 || now >= policy->from_ms) &&
           (policy->until_ms == 0 || now < policy->until_ms);
}

/** @brief Whether a call moving @p size bytes passes the rule's `@size` gate. */
static inline int chaos_policy_size_ok(const chaos_rule_policy_t *policy, uint64_t size)
{
    if (!policy->has_size_above && !policy->has_size_below)
    {
        return 1;
    }
    if (size == CHAOS_POLICY_NO_SIZE)
    {
        return 0;
    }
    return (!policy->has_size_above || size > policy->size_above) &&
           (!policy->has_size_below || size < policy->size_below);
}

/**
 * @brief Completes a firing that passed every other check: claims an `@first`
 *        slot and counts the hit.
 *
 * @return 1 when the effect fires, 0 when the rule has used up its `@first=N`.
 */
static inline int chaos_policy_fire(const chaos_rule_policy_t *policy, chaos_hit_slot_t *slot)
{
    /* Claims are per process: each library's atfork handler clears them in a child. */
    if (policy->first != 0U && slot != NULL &&
        __sync_fetch_and_add(&slot->claimed, 1U) >= policy->first)
    {
        return 0;
    }
    chaos_hit_record(slot);
    return 1;
}

#endif
