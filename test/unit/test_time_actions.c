/**
 * @file test_time_actions.c
 * @brief Proves the libchaos-time effect actions: the probability gate and qualifiers,
 *   LATENCY sleeping, ERRNO injection, OFFSET and REGRESS clock arithmetic, and the
 *   deadline conversion used by absolute sleeps.
 *
 * @details Unit under test: `src/time/chaos_time_actions.c`, included directly so its
 * `static` helpers (`chaos_time_add_offset_ms()`) are callable.
 *
 * Isolation: `CHAOS_TIME_DEFINE_TEST_GLOBALS()` provides the real-function pointers, all
 * NULL. Each latency case installs only the sleep stub it needs, which selects the path:
 * production prefers the real `usleep` and falls back to the real `nanosleep` only when
 * `usleep` is unresolved. The `usleep` stub records each chunk instead of sleeping; the
 * `nanosleep` stub records the request and can fail with EINTR a set number of times or with
 * any other errno. Rule structs are built in memory, so no rule file is involved. Qualifier
 * windows use wall-clock bounds far in the past (1 ms after the epoch) or future (4e12 ms,
 * around 2096), so the result does not depend on when the test runs.
 *
 * Out of scope: rule parsing and selection (test_time_config.c) and the wrappers
 * (test_chaos_time.c).
 */

#include "../support/test_time_support.h"

#include "../../src/time/chaos_time_config.h"

CHAOS_TIME_DEFINE_TEST_GLOBALS();

/** @brief `usleep` stub arguments in call order; the stub asserts if more than 8 arrive. */
static useconds_t g_sleep_chunks[8];
/** @brief Entries used in `g_sleep_chunks`. */
static size_t g_sleep_count = 0U;
/** @brief Calls to the `nanosleep` stub, including failed ones. */
static int g_nanosleep_calls = 0;
/** @brief Further `nanosleep` stub calls to fail with EINTR before any other outcome. */
static int g_nanosleep_eintr_count = 0;
/** @brief Non-zero makes the `nanosleep` stub fail with this errno once EINTRs are used up. */
static int g_nanosleep_error = 0;
/** @brief Request passed to the latest `nanosleep` stub call. */
static struct timespec g_last_nanosleep_request;

/**
 * @brief Real-`usleep` stand-in: records @p usec (microseconds) and returns 0 without sleeping.
 */
static int chaos_time_test_usleep(useconds_t usec)
{
    assert(g_sleep_count < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]));
    g_sleep_chunks[g_sleep_count++] = usec;
    return 0;
}

/**
 * @brief Real-`nanosleep` stand-in with scripted failures; never sleeps.
 *
 * Records the call and its request. While `g_nanosleep_eintr_count` is positive it fails
 * with EINTR and reports the whole request as remaining, which is what production passes
 * back on the retry. Next, a non-zero `g_nanosleep_error` fails with that errno. Otherwise
 * it succeeds with nothing remaining.
 */
static int chaos_time_test_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    ++g_nanosleep_calls;
    assert(request != NULL);
    g_last_nanosleep_request = *request;
    if (g_nanosleep_eintr_count > 0)
    {
        --g_nanosleep_eintr_count;
        if (remaining != NULL)
        {
            remaining->tv_sec = request->tv_sec;
            remaining->tv_nsec = request->tv_nsec;
        }
        errno = EINTR;
        return -1;
    }
    if (g_nanosleep_error != 0)
    {
        errno = g_nanosleep_error;
        return -1;
    }
    if (remaining != NULL)
    {
        remaining->tv_sec = 0;
        remaining->tv_nsec = 0L;
    }
    return 0;
}

#include "../../src/time/chaos_time_actions.c"

/**
 * @brief Unresolves every real function and clears the stub records and failure switches,
 *   so each case installs exactly the sleep path it tests.
 */
static void reset_action_state(void)
{
    size_t index;

    chaos_time_test_reset_runtime();
    g_sleep_count = 0U;
    g_nanosleep_calls = 0;
    g_nanosleep_eintr_count = 0;
    g_nanosleep_error = 0;
    g_last_nanosleep_request.tv_sec = 0;
    g_last_nanosleep_request.tv_nsec = 0L;
    for (index = 0U; index < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]); ++index)
    {
        g_sleep_chunks[index] = 0U;
    }
}

/**
 * @brief Proves the probability gate fires when `sample < probability * 2^32`, with 0.0 never
 *   and 1.0 always firing, and that a NULL rule never triggers.
 *
 * @details The sample is passed explicitly, so the PRNG is not involved. 0.0 with sample 0
 * and 1.0 with sample 0xffffffff are the extremes the threshold comparison alone would get
 * wrong; the guards before it must decide them.
 */
static void test_probability_helpers(void)
{
    assert(!chaos_time_probability_hit_sample(0.0, 0U));
    assert(chaos_time_probability_hit_sample(1.0, 0xffffffffU));
    assert(chaos_time_probability_hit_sample(0.5, 0U));
    assert(!chaos_time_probability_hit_sample(0.5, 0xffffffffU));
    assert(!chaos_time_rule_should_trigger(NULL));
}

/**
 * @brief Proves LATENCY sleeps the configured time through the real sleep functions, in
 *   chunks of at most 1 s, and never alters the caller's errno.
 *
 * @details Cases, each after a reset so only the named stub is resolved:
 * - `usleep` path: 2500 ms becomes three chunks of 1 000 000, 1 000 000 and 500 000 us. The
 *   1 s cap exists because POSIX guarantees `useconds_t` only up to 1 000 000.
 * - `nanosleep` fallback (no `usleep`): 1 ms becomes one request of {0 s, 1 000 000 ns}.
 * - One EINTR is retried, giving two calls, so a signal does not shorten the delay.
 * - Probability 0.0, a NULL rule and an ERRNO rule do not sleep.
 * - A non-EINTR failure (EINVAL) ends the chunk after one call; errno keeps its sentinel.
 * - With neither real sleep function resolved the delay is skipped, not a crash.
 */
static void test_latency_helper(void)
{
    chaos_time_rule_t rule;

    reset_action_state();
    g_chaos_time_real_usleep = chaos_time_test_usleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 2500U;
    chaos_time_rule_apply_latency(&rule);
    assert(g_sleep_count == 3U);
    assert(g_sleep_chunks[0] == 1000000U);
    assert(g_sleep_chunks[1] == 1000000U);
    assert(g_sleep_chunks[2] == 500000U);

    reset_action_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 1U;
    chaos_time_rule_apply_latency(&rule);
    assert(g_sleep_count == 0U);
    assert(g_nanosleep_calls == 1);
    assert(g_last_nanosleep_request.tv_sec == 0);
    assert(g_last_nanosleep_request.tv_nsec == 1000000L);

    reset_action_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_nanosleep_eintr_count = 1;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 1U;
    chaos_time_rule_apply_latency(&rule);
    assert(g_nanosleep_calls == 2);

    reset_action_state();
    g_chaos_time_real_usleep = chaos_time_test_usleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_LATENCY;
    rule.probability = 0.0;
    rule.latency_ms = 100U;
    chaos_time_rule_apply_latency(&rule);
    assert(g_sleep_count == 0U);

    /* Only a LATENCY rule sleeps. */
    rule.probability = 1.0;
    chaos_time_rule_apply_latency(NULL);
    rule.effect = CHAOS_TIME_EFFECT_ERRNO;
    chaos_time_rule_apply_latency(&rule);
    assert(g_sleep_count == 0U);

    /* Only EINTR is retried; any other failure would loop forever if retried. The delay is
     * injected, so the errno it leaves must not reach the caller. */
    reset_action_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_nanosleep_error = EINVAL;
    rule.effect = CHAOS_TIME_EFFECT_LATENCY;
    rule.latency_ms = 1U;
    errno = 4242;
    chaos_time_rule_apply_latency(&rule);
    assert(g_nanosleep_calls == 1);
    assert(errno == 4242);

    /* Neither real sleep function resolved: skip the delay rather than call NULL. */
    reset_action_state();
    errno = 4242;
    chaos_time_rule_apply_latency(&rule);
    assert(g_sleep_count == 0U);
    assert(g_nanosleep_calls == 0);
    assert(errno == 4242);
}

/**
 * @brief Proves ERRNO sets errno only when it fires, and that OFFSET shifts a timespec by a
 *   signed millisecond delta with correct carry, borrow and clamping at zero.
 *
 * @details ERRNO at probability 1.0 sets EINVAL and reports a hit; a NULL rule, probability
 * 0.0 or a LATENCY rule report none and leave errno at its sentinel. OFFSET arithmetic:
 * - +1500 ms on {10 s, 250 ms} gives {11 s, 750 ms}; -1500 ms on {2 s, 100 ms} gives
 *   {0 s, 600 ms}, borrowing across the second boundary.
 * - -500 ms on {0 s, 100 ms} clamps to {0, 0}: a negative timespec is invalid in POSIX.
 * - A zero delta and a NULL target leave the value alone; {1 s, 900 ms} + 200 ms carries to
 *   {2 s, 100 ms}.
 * - A NULL rule, a NULL value, probability 0.0 and a REGRESS rule shift nothing.
 */
static void test_errno_and_offset_helpers(void)
{
    chaos_time_rule_t rule;
    struct timespec value;

    reset_action_state();
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_ERRNO;
    rule.probability = 1.0;
    rule.errnum = EINVAL;
    errno = 0;
    assert(chaos_time_rule_apply_errno(&rule));
    assert(errno == EINVAL);
    assert(!chaos_time_rule_apply_errno(NULL));

    /* No hit, no errno change: the real call's errno must survive. */
    errno = 4242;
    rule.probability = 0.0;
    assert(!chaos_time_rule_apply_errno(&rule));
    rule.probability = 1.0;
    rule.effect = CHAOS_TIME_EFFECT_LATENCY;
    assert(!chaos_time_rule_apply_errno(&rule));
    assert(errno == 4242);

    reset_action_state();
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_OFFSET;
    rule.probability = 1.0;
    rule.offset_ms = 1500;
    value.tv_sec = 10;
    value.tv_nsec = 250000000L;
    chaos_time_rule_apply_offset(&rule, &value);
    assert(value.tv_sec == 11);
    assert(value.tv_nsec == 750000000L);

    value.tv_sec = 2;
    value.tv_nsec = 100000000L;
    rule.offset_ms = -1500;
    chaos_time_rule_apply_offset(&rule, &value);
    assert(value.tv_sec == 0);
    assert(value.tv_nsec == 600000000L);

    value.tv_sec = 0;
    value.tv_nsec = 100000000L;
    rule.offset_ms = -500;
    chaos_time_rule_apply_offset(&rule, &value);
    assert(value.tv_sec == 0);
    assert(value.tv_nsec == 0L);

    value.tv_sec = 3;
    value.tv_nsec = 400000000L;
    chaos_time_add_offset_ms(&value, 0);
    assert(value.tv_sec == 3);
    assert(value.tv_nsec == 400000000L);

    value.tv_sec = 3;
    value.tv_nsec = 400000000L;
    chaos_time_add_offset_ms(NULL, 500);
    assert(value.tv_sec == 3);
    assert(value.tv_nsec == 400000000L);

    value.tv_sec = 1;
    value.tv_nsec = 900000000L;
    chaos_time_add_offset_ms(&value, 200);
    assert(value.tv_sec == 2);
    assert(value.tv_nsec == 100000000L);

    value.tv_sec = 7;
    value.tv_nsec = 0L;
    chaos_time_rule_apply_offset(NULL, &value);
    assert(value.tv_sec == 7);
    assert(value.tv_nsec == 0L);
    chaos_time_rule_apply_offset(&rule, NULL);

    /* Only a firing OFFSET rule shifts; REGRESS has its own action. */
    rule.probability = 0.0;
    chaos_time_rule_apply_offset(&rule, &value);
    rule.probability = 1.0;
    rule.effect = CHAOS_TIME_EFFECT_REGRESS;
    chaos_time_rule_apply_offset(&rule, &value);
    assert(value.tv_sec == 7);
    assert(value.tv_nsec == 0L);
}

/**
 * @brief Proves a rule's hit slot counts exactly the decisions that fire, and that a rule
 *   without a slot still fires.
 *
 * @details The hits file reports this count, so a call the probability gate rejects must
 * not be counted. With `hit == NULL` nothing is counted and `@first` is not enforced, but the
 * rule still fires.
 */
static void test_should_trigger_counts_hits(void)
{
    chaos_time_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_TIME_EFFECT_ERRNO;
    rule.hit = &slot;
    rule.probability = 1.0;
    assert(chaos_time_rule_should_trigger(&rule) == 1);
    assert(slot.count == 1U);
    rule.probability = 0.0;
    assert(chaos_time_rule_should_trigger(&rule) == 0);
    assert(slot.count == 1U);
    rule.hit = NULL;
    rule.probability = 1.0;
    assert(chaos_time_rule_should_trigger(&rule) == 1);
}

/**
 * @brief Proves the trigger decision honours the qualifiers `@first`, `@from`, `@until` and
 *   `@size`.
 *
 * @details `@first=2` fires twice, then never, and the count stops at 2. A window that ended
 * (`@until` 1 ms after the epoch) or has not started (`@from` around 2096) does not fire; an
 * open one does. `@size>100` rejects a call that carries no size (`CHAOS_POLICY_NO_SIZE`)
 * and 100 itself, passes 101, and `@size<101` then rejects 101: both bounds are exclusive.
 */
static void test_should_trigger_honours_qualifiers(void)
{
    chaos_time_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_TIME_EFFECT_ERRNO;
    rule.hit = &slot;
    rule.probability = 1.0;
    rule.policy.first = 2U;
    assert(chaos_time_rule_should_trigger(&rule) == 1);
    assert(chaos_time_rule_should_trigger(&rule) == 1);
    assert(chaos_time_rule_should_trigger(&rule) == 0);
    assert(slot.count == 2U);

    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.until_ms = 1;
    assert(chaos_time_rule_should_trigger(&rule) == 0);
    rule.policy.until_ms = 0;
    rule.policy.from_ms = INT64_C(4000000000000);
    assert(chaos_time_rule_should_trigger(&rule) == 0);
    rule.policy.from_ms = 1;
    assert(chaos_time_rule_should_trigger(&rule) == 1);

    /* Both @size bounds are exclusive; a call without a size never passes a size gate. */
    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.has_size_above = 1U;
    rule.policy.size_above = 100U;
    rule.call_size = CHAOS_POLICY_NO_SIZE;
    assert(chaos_time_rule_should_trigger(&rule) == 0);
    rule.call_size = 100U;
    assert(chaos_time_rule_should_trigger(&rule) == 0);
    rule.call_size = 101U;
    assert(chaos_time_rule_should_trigger(&rule) == 1);
    rule.policy.has_size_below = 1U;
    rule.policy.size_below = 101U;
    assert(chaos_time_rule_should_trigger(&rule) == 0);
}

/**
 * @brief Proves REGRESS steps the clock back once and keeps it back: the first read stays
 *   real, a later read that passes the gate jumps back by `offset_ms`, and every read after
 *   that stays shifted without consulting the gate again.
 *
 * @details The state lives in the hit slot (0 unseen, 1 seen, 3 deciding, 2 jumped), so the
 * test drives it directly:
 * - Without a slot nothing happens; the first read with one only moves 0 to 1.
 * - A failed gate keeps state 1; a passing one shifts 100 s to 95 s, sets state 2 and counts
 *   one hit. Later reads at probability 0.0 stay shifted (101 s reads 96 s), uncounted.
 * - A closed `@until` window shifts nothing even after the jump.
 * - State 3 (another thread deciding) leaves this read real and the state untouched.
 * - A slot whose generation no longer matches (reassigned on reload) shifts nothing.
 * - An OFFSET rule, a NULL rule and a NULL value are ignored.
 */
static void test_regress_goes_back_once(void)
{
    chaos_time_rule_t rule;
    chaos_hit_slot_t slot;
    struct timespec value;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_TIME_EFFECT_REGRESS;
    rule.offset_ms = 5000;
    rule.probability = 1.0;

    value.tv_sec = 100;
    value.tv_nsec = 0;
    chaos_time_rule_apply_regress(&rule, &value);
    assert(value.tv_sec == 100);

    rule.hit = &slot;
    chaos_time_rule_apply_regress(&rule, &value);
    assert(value.tv_sec == 100 && slot.state == 1U);

    rule.probability = 0.0;
    chaos_time_rule_apply_regress(&rule, &value);
    assert(value.tv_sec == 100 && slot.state == 1U);

    rule.probability = 1.0;
    chaos_time_rule_apply_regress(&rule, &value);
    assert(value.tv_sec == 95 && slot.state == 2U && slot.count == 1U);

    rule.probability = 0.0;
    value.tv_sec = 101;
    chaos_time_rule_apply_regress(&rule, &value);
    assert(value.tv_sec == 96 && slot.count == 1U);

    /* The window gates every read, including those after the jump. */
    rule.policy.until_ms = 1;
    value.tv_sec = 101;
    chaos_time_rule_apply_regress(&rule, &value);
    assert(value.tv_sec == 101);
    rule.policy.until_ms = 0;

    /* State 3: another thread owns the decision, so this read is not shifted yet. */
    slot.state = 3U;
    rule.probability = 1.0;
    chaos_time_rule_apply_regress(&rule, &value);
    assert(value.tv_sec == 101 && slot.state == 3U);
    slot.state = 2U;

    /* Generation mismatch: a reload gave the slot to another rule after this copy was taken. */
    slot.generation = 1U;
    value.tv_sec = 101;
    chaos_time_rule_apply_regress(&rule, &value);
    assert(value.tv_sec == 101 && slot.state == 2U);
    slot.generation = 0U;

    rule.effect = CHAOS_TIME_EFFECT_OFFSET;
    value.tv_sec = 101;
    chaos_time_rule_apply_regress(&rule, &value);
    assert(value.tv_sec == 101);
    chaos_time_rule_apply_regress(NULL, &value);
    chaos_time_rule_apply_regress(&rule, NULL);
}

/**
 * @brief Proves an absolute sleep deadline, computed from shifted clock reads, is converted
 *   back to real time by exactly the shift every read carries.
 *
 * @details The program saw now + O under OFFSET and now - R after a REGRESS jump, so the
 * real deadline is O earlier and R later. Only a shift applied to every read is certain:
 * - OFFSET +2000 ms at probability 1.0 moves {100 s} to {98 s}. Probability 0.5, `@first`,
 *   either `@size` bound or a closed window mean some reads were real, so nothing changes.
 * - REGRESS 5000 ms adds 5 s only in state 2 (jumped), with a current slot and an open
 *   window: 98 s becomes 103 s. Both rules together add up: 103 s becomes 106 s.
 * - No rule, a REGRESS without a slot or rules of the wrong effect change nothing.
 */
static void test_unshift_deadline(void)
{
    chaos_time_rule_t offset;
    chaos_time_rule_t regress;
    chaos_hit_slot_t slot;
    struct timespec deadline;

    memset(&offset, 0, sizeof(offset));
    memset(&regress, 0, sizeof(regress));
    memset(&slot, 0, sizeof(slot));
    offset.effect = CHAOS_TIME_EFFECT_OFFSET;
    offset.offset_ms = 2000;
    offset.probability = 1.0;
    regress.effect = CHAOS_TIME_EFFECT_REGRESS;
    regress.offset_ms = 5000;
    regress.hit = &slot;

    deadline.tv_sec = 100;
    deadline.tv_nsec = 0L;
    assert(chaos_time_rule_unshift_deadline(NULL, NULL, &deadline) == 0);
    assert(chaos_time_rule_unshift_deadline(&offset, NULL, &deadline) == 1);
    assert(deadline.tv_sec == 98);

    offset.probability = 0.5;
    assert(chaos_time_rule_unshift_deadline(&offset, NULL, &deadline) == 0);
    offset.probability = 1.0;
    offset.policy.first = 1U;
    assert(chaos_time_rule_unshift_deadline(&offset, NULL, &deadline) == 0);
    offset.policy.first = 0U;
    offset.policy.has_size_above = 1U;
    assert(chaos_time_rule_unshift_deadline(&offset, NULL, &deadline) == 0);
    offset.policy.has_size_above = 0U;
    offset.policy.has_size_below = 1U;
    assert(chaos_time_rule_unshift_deadline(&offset, NULL, &deadline) == 0);
    offset.policy.has_size_below = 0U;
    offset.policy.until_ms = 1;
    assert(chaos_time_rule_unshift_deadline(&offset, NULL, &deadline) == 0);
    offset.policy.until_ms = 0;
    /* The two qualifiers this release added belong in the same list: both make the shift
     * apply to some reads and not others, and an unshifted deadline taken off a deadline
     * the program never shifted makes an absolute sleep return at once. */
    offset.policy.every = 2U;
    assert(chaos_time_rule_unshift_deadline(&offset, NULL, &deadline) == 0);
    offset.policy.every = 0U;
    offset.policy.at_ms = 60000U;
    assert(chaos_time_rule_unshift_deadline(&offset, NULL, &deadline) == 0);
    offset.policy.at_ms = 0U;
    assert(deadline.tv_sec == 98);

    slot.state = 1U;
    assert(chaos_time_rule_unshift_deadline(NULL, &regress, &deadline) == 0);
    slot.state = 2U;
    slot.generation = 1U;
    assert(chaos_time_rule_unshift_deadline(NULL, &regress, &deadline) == 0);
    slot.generation = 0U;
    regress.policy.until_ms = 1;
    assert(chaos_time_rule_unshift_deadline(NULL, &regress, &deadline) == 0);
    regress.policy.until_ms = 0;
    regress.policy.every = 3U;
    assert(chaos_time_rule_unshift_deadline(NULL, &regress, &deadline) == 0);
    regress.policy.every = 0U;
    regress.policy.at_ms = 500U;
    assert(chaos_time_rule_unshift_deadline(NULL, &regress, &deadline) == 0);
    regress.policy.at_ms = 0U;
    assert(chaos_time_rule_unshift_deadline(NULL, &regress, &deadline) == 1);
    assert(deadline.tv_sec == 103);
    assert(chaos_time_rule_unshift_deadline(&offset, &regress, &deadline) == 1);
    assert(deadline.tv_sec == 106);

    /* Each argument is checked for its own effect; a REGRESS needs its slot's state. */
    regress.hit = NULL;
    offset.effect = CHAOS_TIME_EFFECT_REGRESS;
    assert(chaos_time_rule_unshift_deadline(&offset, &regress, &deadline) == 0);
    regress.hit = &slot;
    regress.effect = CHAOS_TIME_EFFECT_OFFSET;
    assert(chaos_time_rule_unshift_deadline(&offset, &regress, &deadline) == 0);
}

/**
 * @brief Proves a sample follows from the rule and the number of the evaluation, and from
 *        nothing else.
 *
 * @details This is what makes a fault reproducible: the same rule at the same evaluation
 * number gives the same sample; the next evaluation, a rule of different text and a forked
 * child's lineage each give an unrelated one; and the draws within one evaluation differ
 * from each other.
 */
static void test_draws_are_reproducible(void)
{
    chaos_time_rule_t rule;
    chaos_hit_slot_t slot;
    uint32_t first;

    (void)memset(&rule, 0, sizeof(rule));
    (void)memset(&slot, 0, sizeof(slot));
    rule.hit = &slot;
    rule.key = chaos_time_prng_mix(g_chaos_time_process_seed ^ chaos_time_rule_hash("a"));

    chaos_time_rule_draw_begin(&rule);
    assert(slot.evaluations == 1U);
    first = chaos_time_rule_draw(&rule, CHAOS_TIME_DRAW_PROBABILITY);
    assert(chaos_time_rule_draw(&rule, CHAOS_TIME_DRAW_PROBABILITY) == first);
    assert(chaos_time_rule_draw(&rule, CHAOS_TIME_DRAW_FIRST_EFFECT) != first);

    chaos_time_rule_draw_begin(&rule);
    assert(slot.evaluations == 2U);
    assert(chaos_time_rule_draw(&rule, CHAOS_TIME_DRAW_PROBABILITY) != first);

    /* A rule whose text differs is a different rule, even in the same slot. */
    rule.key = chaos_time_prng_mix(g_chaos_time_process_seed ^ chaos_time_rule_hash("b"));
    slot.evaluations = 0U;
    chaos_time_rule_draw_begin(&rule);
    assert(chaos_time_rule_draw(&rule, CHAOS_TIME_DRAW_PROBABILITY) != first);

    /* Same rule, same evaluation, different lineage: a forked child decides on its own. */
    rule.key = chaos_time_prng_mix(g_chaos_time_process_seed ^ chaos_time_rule_hash("a"));
    slot.evaluations = 0U;
    g_chaos_time_lineage = chaos_time_prng_mix(1U);
    chaos_time_rule_draw_begin(&rule);
    assert(chaos_time_rule_draw(&rule, CHAOS_TIME_DRAW_PROBABILITY) != first);
    g_chaos_time_lineage = 0U;

    /* A rule outside a snapshot has no slot: evaluation 0 every time, which is what makes
     * the unit tests reproducible without seeding anything. */
    rule.hit = NULL;
    chaos_time_rule_draw_begin(&rule);
    first = chaos_time_rule_draw(&rule, CHAOS_TIME_DRAW_PROBABILITY);
    chaos_time_rule_draw_begin(&rule);
    assert(chaos_time_rule_draw(&rule, CHAOS_TIME_DRAW_PROBABILITY) == first);

    assert(chaos_time_rule_hash("a") == chaos_time_rule_hash("a"));
    assert(chaos_time_rule_hash("a") != chaos_time_rule_hash("b"));
    assert(chaos_time_rule_hash(NULL) != chaos_time_rule_hash("a"));
}

/**
 * @brief Proves `@every=N` lets only every Nth evaluation through, in the real gate.
 *
 * @details The gate itself is tested on values in test_common.c; what is asserted here is
 * that chaos_time_rule_should_trigger() actually consults it, and where. `@every` counts
 * evaluations, so a rule at probability 1.0 and `@every=3` fires on the 3rd, 6th and 9th
 * call and on no other -- and the two calls in between still count as evaluations, which is
 * what makes the third one the third.
 */
static void test_every_gates_evaluations(void)
{
    chaos_time_rule_t rule;
    chaos_hit_slot_t slot;
    unsigned call;
    unsigned fired = 0U;

    (void)memset(&rule, 0, sizeof(rule));
    (void)memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_TIME_EFFECT_ERRNO;
    rule.probability = 1.0;
    rule.hit = &slot;
    rule.policy.every = 3U;

    for (call = 1U; call <= 9U; ++call)
    {
        const int triggered = chaos_time_rule_should_trigger(&rule) != 0;

        assert(triggered == (call % 3U == 0U));
        fired += (unsigned)triggered;
    }
    assert(fired == 3U);
    assert(slot.evaluations == 9U);
    assert(slot.count == 3U);

    /* Without the qualifier every evaluation fires. */
    (void)memset(&slot, 0, sizeof(slot));
    rule.policy.every = 0U;
    assert(chaos_time_rule_should_trigger(&rule) != 0);
    assert(slot.count == 1U);
}

/**
 * @brief Proves FREEZE stops the clock at the value of the call that fired it.
 *
 * @details FREEZE is the effect §7 of the plan reads out of the state page, so it has to
 * exist as a rule effect first. Asserted here:
 * - before the rule fires the clock runs: the reading passes through unchanged;
 * - the first firing call's reading is kept, and every later read returns it, whatever the
 *   real clock says -- the probability decides when the freeze starts, not each read;
 * - the kept value lives in the hit slot, so a second rule copy of the same rule (another
 *   thread, or a copy taken before a reload) sees the same frozen time;
 * - outside the `@from`/`@until` window the clock runs, before and after the freeze, which
 *   is how REGRESS behaves too;
 * - a reading of 0 freezes as well: the slot keeps the reading with the top bit set, so a
 *   cleared bit, not a zero word, is what "not frozen" means;
 * - the top bit keeps a frozen reading clear of REGRESS's state machine in the same word:
 *   a reading of 2 ns would otherwise store a 3, which the fork handler rewrites to a 1.
 */
static void test_freeze_stops_the_clock(void)
{
    chaos_time_rule_t rule;
    chaos_hit_slot_t slot;
    struct timespec value;

    (void)memset(&rule, 0, sizeof(rule));
    (void)memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_TIME_EFFECT_FREEZE;
    rule.hit = &slot;
    rule.probability = 0.0;

    /* Probability 0: nothing is frozen and the reading is untouched. */
    value.tv_sec = 100;
    value.tv_nsec = 5;
    chaos_time_rule_apply_freeze(&rule, &value);
    assert(value.tv_sec == 100 && value.tv_nsec == 5);
    assert(slot.state == 0U);

    /* The first firing call's reading is kept. */
    rule.probability = 1.0;
    value.tv_sec = 200;
    value.tv_nsec = 7;
    chaos_time_rule_apply_freeze(&rule, &value);
    assert(value.tv_sec == 200 && value.tv_nsec == 7);
    assert(slot.state == ((UINT64_C(200) * UINT64_C(1000000000) + 7U) | (UINT64_C(1) << 63)));

    /* Later reads return it, whatever the clock says. */
    value.tv_sec = 999;
    value.tv_nsec = 123;
    chaos_time_rule_apply_freeze(&rule, &value);
    assert(value.tv_sec == 200 && value.tv_nsec == 7);

    /* Another copy of the same rule sees the same frozen time: it lives in the slot. */
    {
        chaos_time_rule_t other = rule;

        other.probability = 0.0;
        value.tv_sec = 555;
        value.tv_nsec = 1;
        chaos_time_rule_apply_freeze(&other, &value);
        assert(value.tv_sec == 200 && value.tv_nsec == 7);
    }

    /* Outside the window the clock runs, frozen or not. */
    rule.policy.from_ms = INT64_C(4000000000000);
    value.tv_sec = 777;
    value.tv_nsec = 9;
    chaos_time_rule_apply_freeze(&rule, &value);
    assert(value.tv_sec == 777 && value.tv_nsec == 9);
    (void)memset(&rule.policy, 0, sizeof(rule.policy));

    /* A reading of 0 freezes too, which the mark bit in the slot is there for. */
    (void)memset(&slot, 0, sizeof(slot));
    value.tv_sec = 0;
    value.tv_nsec = 0;
    chaos_time_rule_apply_freeze(&rule, &value);
    assert(slot.state == (UINT64_C(1) << 63));
    value.tv_sec = 42;
    value.tv_nsec = 42;
    chaos_time_rule_apply_freeze(&rule, &value);
    assert(value.tv_sec == 0 && value.tv_nsec == 0);

    /* A reading of 2 ns is the one REGRESS's state machine would claim: stored as a bare
     * `ns + 1` it is a 3, which chaos_hits_pool_after_fork() rewrites to a 1 and so hands
     * the child a clock frozen at 0. With the mark it stays 2 ns across the fork reset. */
    (void)memset(&slot, 0, sizeof(slot));
    value.tv_sec = 0;
    value.tv_nsec = 2;
    chaos_time_rule_apply_freeze(&rule, &value);
    assert(slot.state != 3U);
    if (slot.state == 3U)
    {
        slot.state = 1U;
    }
    value.tv_sec = 42;
    value.tv_nsec = 42;
    chaos_time_rule_apply_freeze(&rule, &value);
    assert(value.tv_sec == 0 && value.tv_nsec == 2);

    /* A FREEZE rule reaches the absolute-deadline conversion unchanged: a stopped clock is
     * no shift that could be undone, and TIME.md says so. The conversion checks the effect,
     * so this holds by construction -- asserted anyway, because a later hook that passed a
     * FREEZE rule in would otherwise shorten every absolute sleep silently. */
    {
        struct timespec deadline;

        deadline.tv_sec = 500;
        deadline.tv_nsec = 7;
        rule.effect = CHAOS_TIME_EFFECT_FREEZE;
        assert(chaos_time_rule_unshift_deadline(&rule, &rule, &deadline) == 0);
        assert(deadline.tv_sec == 500 && deadline.tv_nsec == 7);
    }

    /* Not a FREEZE rule, no rule, no value, no slot: all no-ops. */
    (void)memset(&slot, 0, sizeof(slot));
    value.tv_sec = 5;
    value.tv_nsec = 5;
    rule.effect = CHAOS_TIME_EFFECT_OFFSET;
    chaos_time_rule_apply_freeze(&rule, &value);
    rule.effect = CHAOS_TIME_EFFECT_FREEZE;
    chaos_time_rule_apply_freeze(NULL, &value);
    chaos_time_rule_apply_freeze(&rule, NULL);
    rule.hit = NULL;
    chaos_time_rule_apply_freeze(&rule, &value);
    assert(value.tv_sec == 5 && value.tv_nsec == 5);
    assert(slot.state == 0U);
}

int main(void)
{
    test_freeze_stops_the_clock();
    test_every_gates_evaluations();
    test_draws_are_reproducible();
    test_regress_goes_back_once();
    test_unshift_deadline();
    test_should_trigger_honours_qualifiers();
    test_should_trigger_counts_hits();
    test_probability_helpers();
    test_latency_helper();
    test_errno_and_offset_helpers();
    return 0;
}
