/**
 * @file chaos_bucket.h
 * @brief The token bucket behind the rate-limiting effects (`THROTTLE`).
 *
 * @details A bucket holds at most one second's worth of bytes and refills at the rule's
 * rate. A call takes what is there, up to what it asked for: that turns a rate into short
 * calls rather than long sleeps, which is what keeps a chaos test from blocking the
 * application's event loop.
 *
 * @par Why one word
 * The whole state is a single 64-bit word -- the tokens in the high half, the millisecond
 * the bucket was last accounted to in the low half -- so it is updated with one compare
 * and swap and needs no lock. Threads sharing a descriptor therefore share a rate without
 * waiting for each other; a thread that loses the race retries with what it then sees.
 *
 * The millisecond is truncated to 32 bits, and every comparison of two of them is a signed
 * difference (chaos_bucket_later()), so the wrap after 49 days of uptime is not a special
 * case: what matters is the distance between two stamps, and a bucket's is milliseconds.
 * The truncation is not optional -- a whole reading stored in the low half would spill into
 * the token half and hand out tokens nobody refilled.
 * Rates above 2^32 - 1 bytes per second cannot be expressed and are rejected by the
 * parsers, so the token half never overflows.
 *
 * @par Taking and reserving
 * A caller that may come back empty-handed takes (chaos_bucket_take()) and gets what is
 * there. A caller that has to move bytes -- a blocking write, or a supervisor that parks
 * the call instead of letting the thread sleep -- reserves (chaos_bucket_reserve()) and
 * gets the wait until the bytes it was charged for have arrived. Both leave the bucket in
 * the same arithmetic, which is why a rule enforces the same rate under `LD_PRELOAD` and
 * under chaos-init.
 *
 * @par Module: shared
 * @par Stability: private / internal
 */

#ifndef CHAOS_BUCKET_H
#define CHAOS_BUCKET_H

#include <stdint.h>

/**
 * @brief The compare and swap the state word is updated with.
 *
 * @details Test seam: a unit test defines this macro before including the header to make
 * an attempt fail, which is what another thread updating the same bucket does. The retry
 * is otherwise not reachable from one thread.
 */
#ifndef CHAOS_BUCKET_CAS
#define CHAOS_BUCKET_CAS(state, seen, next) __sync_bool_compare_and_swap((state), (seen), (next))
#endif

/** @brief State of one bucket; zero-initialised means "not used yet", i.e. full. */
typedef struct chaos_bucket
{
    volatile uint64_t state; /**< Tokens in the high 32 bits, the accounted ms in the low 32. */
} chaos_bucket_t;

/**
 * @brief Whether the truncated millisecond @p a is later than @p b.
 *
 * @details A signed difference, so the wrap of the 32-bit millisecond is not a special
 * case: it answers correctly as long as the two are less than 24 days apart, which two
 * stamps of one bucket are by construction.
 */
static inline int chaos_bucket_later(uint64_t a, uint64_t b)
{
    return (int32_t)((uint32_t)a - (uint32_t)b) > 0;
}

/**
 * @brief The state word holding @p tokens tokens accounted to millisecond @p mark.
 *
 * @details The one place the millisecond is truncated. It has to be: the whole reading of
 * a clock that has been running for weeks would spill into the token half of the word and
 * hand out tokens nobody refilled.
 */
static inline uint64_t chaos_bucket_state(uint64_t tokens, uint64_t mark)
{
    return (tokens << 32) | (mark & UINT64_C(0xffffffff));
}

/**
 * @brief Tokens in @p seen at @p now, and in @p mark the moment they belong to.
 *
 * @details @p mark is @p now for a bucket the clock has caught up with, and the stored
 * stamp while it is still ahead of the clock -- a reservation, whose bytes are already
 * spoken for and must not be refilled a second time by moving the stamp back.
 */
static inline uint64_t
chaos_bucket_refill(uint64_t seen, uint64_t rate, uint64_t now, uint64_t *mark)
{
    const uint64_t stamp = seen & UINT64_C(0xffffffff);
    uint64_t tokens = seen >> 32;

    *mark = now;
    if (stamp == 0U)
    {
        /* Never used: a full bucket, so a rule that is loaded while nothing happens does
         * not punish the first call. */
        tokens = rate;
    }
    else if (chaos_bucket_later(now, stamp))
    {
        /* The idle time is not bounded here: the clamp to one second's worth below bounds
         * the result anyway, and the product of two 32-bit values fits the word. */
        tokens += (uint32_t)(now - stamp) * rate / UINT64_C(1000);
    }
    else
    {
        *mark = stamp;
    }
    return tokens < rate ? tokens : rate;
}

/**
 * @brief Takes up to @p want bytes out of @p bucket at @p rate bytes per second.
 *
 * @details Refills first, by the time since the bucket was last accounted to, then takes
 * what is left over, up to @p want. A bucket holds at most one second's worth however
 * long it stood idle.
 *
 * @param bucket  The (rule, descriptor) bucket; its state is updated.
 * @param rate    Bytes per second; 0 means no limit and lets @p want through.
 * @param want    Bytes the call asked for.
 * @param now_ms  CLOCK_MONOTONIC milliseconds (chaos_hits_now_ms()); 0 means no clock,
 *                which lets @p want through rather than blocking on a clock nobody has.
 * @return Bytes the call may move now, 0 to @p want.
 */
static inline uint64_t
chaos_bucket_take(chaos_bucket_t *bucket, uint64_t rate, uint64_t want, uint64_t now_ms)
{
    if (rate == 0U || want == 0U || now_ms == 0U)
    {
        return want;
    }
    for (;;)
    {
        const uint64_t seen = bucket->state;
        uint64_t mark = 0U;
        const uint64_t tokens = chaos_bucket_refill(seen, rate, now_ms, &mark);
        const uint64_t taken = want < tokens ? want : tokens;

        if (CHAOS_BUCKET_CAS(&bucket->state, seen, chaos_bucket_state(tokens - taken, mark)))
        {
            return taken;
        }
    }
}

/**
 * @brief Milliseconds until @p want bytes are in a bucket of @p rate bytes per second.
 *
 * @details Rounded up, so the wait is never short of a token.
 *
 * @return The wait in ms, at least 1 while @p want is above 0; 0 when there is nothing to
 *         wait for (no rate, or nothing wanted).
 */
static inline uint64_t chaos_bucket_wait_ms(uint64_t rate, uint64_t want)
{
    uint64_t wait;

    if (rate == 0U || want == 0U)
    {
        return 0U;
    }
    wait = (want * UINT64_C(1000) + rate - 1U) / rate;
    return wait > 0U ? wait : 1U;
}

/**
 * @brief A tenth of a second's worth of @p rate, and never less than one byte.
 *
 * @details What a caller that has to wait asks for. A tenth of a second bounds the wait at
 * about 100 ms, which is the trade the effect makes: short calls over long sleeps. The
 * floor of one byte keeps a rate below ten bytes per second moving at all.
 */
static inline uint64_t chaos_bucket_chunk(uint64_t rate)
{
    return rate / 10U > 0U ? rate / 10U : 1U;
}

/**
 * @brief Charges @p want bytes to @p bucket, even ones that have not arrived yet.
 *
 * @details What a caller does that must not come back empty-handed: the bytes it is short
 * of are taken out of a later refill, and the wait until that refill is what it gets. The
 * bucket's stamp moves into the future by exactly that wait, so a second caller reserving
 * while the first still waits is told to wait longer instead of being handed the same
 * bytes twice -- which is what holds the rate when several threads write to one
 * descriptor, and what lets a supervisor park a call rather than take again on waking.
 *
 * The caller chooses @p want, and that choice is the one trade-off in the effect: a tenth
 * of a second's worth bounds the wait at 100 ms and makes the call short, a whole message
 * waits longer and stays whole.
 *
 * @param bucket  The (rule, descriptor) bucket; its state is updated.
 * @param rate    Bytes per second; 0 means no limit and nothing to wait for.
 * @param want    Bytes the caller will move once the wait is over.
 * @param now_ms  CLOCK_MONOTONIC milliseconds (chaos_hits_now_ms()); 0 means no clock,
 *                which reserves nothing and waits not at all.
 * @return Milliseconds to wait before moving @p want bytes; 0 when they were there.
 */
static inline uint64_t
chaos_bucket_reserve(chaos_bucket_t *bucket, uint64_t rate, uint64_t want, uint64_t now_ms)
{
    if (rate == 0U || want == 0U || now_ms == 0U)
    {
        return 0U;
    }
    for (;;)
    {
        const uint64_t seen = bucket->state;
        uint64_t mark = 0U;
        const uint64_t tokens = chaos_bucket_refill(seen, rate, now_ms, &mark);
        const uint64_t missing = want > tokens ? want - tokens : 0U;
        const uint64_t wait = chaos_bucket_wait_ms(rate, missing);
        const uint64_t left = want > tokens ? 0U : tokens - want;

        if (CHAOS_BUCKET_CAS(&bucket->state, seen, chaos_bucket_state(left, mark + wait)))
        {
            /* The wait of a caller that found the bucket already reserved runs from that
             * reservation, not from now: what is left of it, plus the new one. */
            return (uint32_t)(mark - now_ms) + wait;
        }
    }
}

#endif
