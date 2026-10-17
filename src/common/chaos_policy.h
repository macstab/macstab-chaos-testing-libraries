/**
 * @file chaos_policy.h
 * @brief Rule qualifiers shared by every library (`@first`, `@from`, `@until`, `@size`)
 *        and the locale-independent number parsers of the rule grammars.
 *
 * @details
 * Each library has its own rule grammar; all of them accept the same qualifiers as
 * separate whitespace-delimited words after the rule and before any `#` comment:
 *
 * @code
 * tcp4://127.0.0.1:5432:connect:ECONNREFUSED:1.0 @first=3 # net
 * /data:write:EIO:1.0 @from=1760000000000 @until=1760000005000
 * tcp4://127.0.0.1:9092:send:LATENCY:200 @size>65536
 * @endcode
 *
 * | Qualifier | Meaning |
 * |-----------|---------|
 * | `@first=N` | At most N hits per process (N >= 1), then inert: a self-clearing start-up fault. |
 * | `@from=T` | Active only when the wall clock, in Unix ms, is >= T. |
 * | `@until=T` | Active only when the wall clock, in Unix ms, is < T. |
 * | `@size>N` | Applies only to calls that move more than N bytes. |
 * | `@size<N` | Applies only to calls that move fewer than N bytes. |
 *
 * Why wall-clock windows: one rule file can hold a whole incident timeline and every
 * process agrees on it, which a time relative to each process's own load would not give.
 * The clock is read without libchaos-time (chaos_clock_realtime_ms()), so a time OFFSET
 * rule does not move another rule's window.
 *
 * Grammar limits and validation:
 * - Numbers are plain decimal, 1 to 18 digits; no sign, no separators.
 * - An unknown or malformed qualifier, `@first=0`, or `@until` <= `@from` (both given)
 *   rejects the line like any other invalid rule, which rejects the whole rule file.
 * - A repeated qualifier is accepted; the leftmost occurrence wins, because words are
 *   parsed right to left.
 * - A call without a byte count (CHAOS_POLICY_NO_SIZE) never matches a size-gated rule.
 *
 * `@first` is counted per process in the rule's hit slot (chaos_hits.h); a forked child
 * starts with a fresh allowance. All functions are header-only, allocation-free and
 * locale-independent; the parsers run on the reload path only, chaos_policy_fire() on
 * every hit.
 */

#ifndef CHAOS_POLICY_H
#define CHAOS_POLICY_H

#include "chaos_clock.h"
#include "chaos_hits.h"

#include <stdint.h>
#include <string.h>

/** @brief Size passed for a call that moves no byte count (e.g. open); fails every `@size` gate. */
#define CHAOS_POLICY_NO_SIZE UINT64_MAX

/** @brief Parsed qualifiers of one rule; an all-zero value means no qualifier. */
typedef struct chaos_rule_policy
{
    uint64_t first;               /**< `@first=N` hit limit per process; 0 for none. */
    int64_t from_ms;              /**< `@from=T`, Unix ms; 0 for no lower bound. */
    int64_t until_ms;             /**< `@until=T`, Unix ms (exclusive); 0 for no upper bound. */
    uint64_t size_above;          /**< `@size>N` in bytes; meaningful when has_size_above. */
    uint64_t size_below;          /**< `@size<N` in bytes; meaningful when has_size_below. */
    unsigned char has_size_above; /**< Non-zero when `@size>N` was given (N may be 0). */
    unsigned char has_size_below; /**< Non-zero when `@size<N` was given (N may be 0). */
} chaos_rule_policy_t;

/**
 * @brief Parses a rule's probability field into [0.0, 1.0].
 *
 * @details Accepted forms: `0`, `1`, `0.` followed by one or more digits, or `1.`
 * followed by one or more zeros; trailing space, tab, CR or LF is allowed. Anything else
 * (sign, exponent, `.5`, `1.5`, `nan`, `inf`, hexadecimal) is rejected.
 *
 * Why not strtod: strtod honours LC_NUMERIC, which the application may change (the JVM
 * calls `setlocale(LC_ALL, "")`); under a German locale it stops at the '.' of "0.5". It
 * also accepts nan, inf, hexadecimal and exponents, none of which is a probability.
 *
 * Precision: the first 15 decimals are accumulated exactly; later digits are validated
 * but ignored, as they lie below a double's 53-bit precision.
 *
 * @param text         NUL-terminated field; NULL is rejected.
 * @param probability  Receives the value on success; untouched on failure. NULL is rejected.
 * @return 0 on success, -1 when @p text is not a probability.
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

/**
 * @brief Parses an unsigned decimal of 1 to 18 digits (< 10^18, so it fits int64_t too).
 *
 * @param text   NUL-terminated digits only; no sign, blanks or separators. Must not be NULL.
 * @param value  Receives the number on success; untouched on failure.
 * @return 0 on success, -1 for an empty string, a non-digit or a 19th digit.
 */
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

/**
 * @brief Applies one qualifier word, e.g. `@size>4096`, to @p policy.
 *
 * @param word    NUL-terminated word starting with `@`.
 * @param policy  Updated in place; an earlier value of the same qualifier is overwritten.
 * @return 0 on success, -1 for an unknown qualifier, a malformed number or `@first=0`.
 */
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
 * @brief Strips the trailing qualifier words from @p line and parses them into @p policy.
 *
 * @details Scans right to left from the first `#` (or the end of the line) and takes
 * every whitespace-separated word that starts with `@`; the scan stops at the first
 * word that does not. A word at the start of the line is never a qualifier, so a
 * line needs a rule before its qualifiers. When at least one qualifier was found, a NUL
 * is written where the first of them begins, dropping the qualifiers and any comment, so
 * the library's own parser sees only the rule (with trailing blanks it must tolerate).
 * A line without qualifiers is not modified.
 *
 * Words are terminated in place and restored before the next step, so on failure
 * @p line is unchanged.
 *
 * @param line    Mutable NUL-terminated rule line.
 * @param policy  Reset to all zero, then filled; partially filled on failure.
 * @return 0 on success; -1 for an unknown or malformed qualifier, or for `@until` <=
 *         `@from` when both are given.
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

/** @brief Non-zero when @p policy carries no qualifier, so the rule needs no policy checks. */
static inline int chaos_policy_is_empty(const chaos_rule_policy_t *policy)
{
    return policy->first == 0U && policy->from_ms == 0 && policy->until_ms == 0 &&
           !policy->has_size_above && !policy->has_size_below;
}

/**
 * @brief Non-zero when the wall clock lies in [`@from`, `@until`), or the rule has no window.
 *
 * @details Reads CLOCK_REALTIME only when a bound is set. When the clock cannot be read
 * at all, "now" is 0: a rule with `@from` stays closed, one with only `@until` stays open.
 */
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

/**
 * @brief Non-zero when a call moving @p size bytes passes the rule's `@size` gate.
 *
 * @param size  Byte count of the call, or CHAOS_POLICY_NO_SIZE, which fails any gate.
 */
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
 * @brief Final gate of a hit, called after selector, window, size and probability all
 *        passed: claims one `@first` allowance and counts the hit.
 *
 * @details Lock-free and safe from any thread: the claim is a CAS loop on the slot's
 * claim word, the count an atomic add. The claim word packs the claim count (low 32 bits)
 * with the low 32 bits of the generation it belongs to (high 32 bits), so one CAS proves
 * both that the allowance is not used up and that the slot still belongs to this rule
 * copy. A copy that passed the generation check while a reload handed its slot to another
 * rule therefore fails the CAS instead of consuming the new rule's allowance.
 *
 * The count saturates at 2^32 - 1 claims, so a `@first` above that limit cannot wrap into
 * the generation bits; it then behaves as `@first=4294967295`.
 *
 * @param policy      The rule's qualifiers.
 * @param slot        The rule's hit slot; NULL for a rule copy outside a snapshot (unit
 *                    tests), which fires without `@first` enforcement or counting.
 * @param generation  The slot generation captured with the rule copy.
 * @return 1 when the effect is to be applied (and the hit is counted); 0 when the rule's
 *         `@first=N` is used up or the rule left the rule file (its slot moved on, see
 *         chaos_hits.h).
 */
static inline int
chaos_policy_fire(const chaos_rule_policy_t *policy, chaos_hit_slot_t *slot, uint64_t generation)
{
    if (!chaos_hit_slot_current(slot, generation))
    {
        return 0;
    }
    /* Claims are per process: each library's atfork handler resets them in a child.
     * The claim succeeds only on a word tagged with this copy's generation, which closes
     * the window between the generation check above and the CAS. */
    if (policy->first != 0U && slot != NULL)
    {
        const uint64_t mine = chaos_hit_claims_none(generation);
        uint64_t claimed;

        do
        {
            claimed = slot->claimed;
            if ((claimed & ~UINT64_C(0xffffffff)) != mine ||
                chaos_hit_claims(claimed) >= policy->first ||
                chaos_hit_claims(claimed) == UINT64_C(0xffffffff))
            {
                return 0;
            }
        } while (!__sync_bool_compare_and_swap(&slot->claimed, claimed, claimed + 1U));
    }
    chaos_hit_record(slot);
    return 1;
}

#endif
