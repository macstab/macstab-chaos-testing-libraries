/**
 * @file chaos_io_fdcache.c
 * @brief Process-wide, lazily mapped descriptor-to-path cache (see chaos_io_fdcache.h).
 *
 * @details
 * @par Why process-wide and lazily mapped
 * A descriptor belongs to the process, not to a thread, so the cache does too. The
 * earlier per-thread table had two defects: every thread carried
 * `CHAOS_IO_FD_CACHE_SLOTS * PATH_MAX` bytes of static TLS from its first instruction
 * (the static-TLS budget that crashed the Erlang VM under libchaos-net), and a close() on
 * one thread left other threads' entries for that descriptor stale, so a reused number
 * could be matched against the old path. The table is now mapped once, on the first
 * store, with a raw `mmap` system call: no allocator (wrappers may run in a signal
 * handler), no interposed `mmap` (libchaos-memory must not be able to fault the cache),
 * nothing per thread and nothing to free at thread exit. The mapping is never unmapped
 * and is inherited across fork().
 *
 * @par Invariants
 * - Each slot has a seqlock sequence, odd while a writer fills it. A reader accepts a
 *   copy only when the sequence was even and unchanged across it, so a concurrent write
 *   makes the lookup miss, never return a torn path.
 * - Each slot has a generation, bumped by every invalidation, stored outside the table.
 *   An entry records the generation it was resolved under and is valid only while that
 *   is still current. Invalidation is one atomic increment: no lock, no waiting, and a
 *   resolution that raced with a close() can never store the path the close made stale.
 * - Excluded paths are never stored and never returned by chaos_io_fdcache_resolve().
 * - If the table cannot be mapped, every operation degrades to "no cache": resolution
 *   reads `/proc/self/fd` each time, slower but correct.
 *
 * @par Test seams
 * g_chaos_io_fdcache_map and g_chaos_io_fdcache_unmap may be replaced to simulate a failed
 * mapping or a lost publication race.
 */

#include "chaos_io_fdcache.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/**
 * @brief One slot of the cache; 4108 bytes.
 *
 * @details `fd_plus_one` is 0 for an empty slot, so the zero-filled pages of a fresh
 * anonymous mapping are an empty cache without an initialisation pass.
 */
typedef struct chaos_io_fd_cache_entry
{
    volatile unsigned int sequence; /**< Seqlock: odd while a writer fills the slot. */
    unsigned int generation;        /**< Slot generation the entry was resolved under. */
    int fd_plus_one;                /**< Cached descriptor + 1; 0 when empty. */
    char path[CHAOS_IO_MAX_PATH];   /**< Kernel path of the descriptor, NUL-terminated. */
} chaos_io_fd_cache_entry_t;

/** @brief Bytes of the mapped table: 32 * 4108 = 131456 (about 128 KiB). */
#define CHAOS_IO_FD_CACHE_BYTES (CHAOS_IO_FD_CACHE_SLOTS * sizeof(chaos_io_fd_cache_entry_t))

/** @brief The table, published by CAS on first store; NULL until then or after failures. */
static chaos_io_fd_cache_entry_t *volatile g_chaos_io_fd_cache = NULL;

/**
 * @brief Per-slot generations, bumped atomically by every invalidation.
 *
 * @details In BSS, outside the mapped table, so an invalidation never needs the table: a
 * close() before the first store still records that the slot changed. Wraparound after
 * 2^32 invalidations of one slot is harmless in practice: an entry would have to survive
 * exactly that many.
 */
static volatile unsigned int g_chaos_io_fd_generation[CHAOS_IO_FD_CACHE_SLOTS];

/**
 * @brief Maps the table's anonymous pages with a raw `mmap` system call, bypassing every
 *        interposed `mmap` (libchaos-memory); errno preserved.
 *
 * @return The mapping, or MAP_FAILED.
 */
static void *chaos_io_fdcache_default_map(void)
{
    const int saved_errno = errno;
    const long mapped = syscall(
        SYS_mmap,
        NULL,
        CHAOS_IO_FD_CACHE_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    errno = saved_errno;
    return mapped == -1L ? MAP_FAILED : (void *)mapped;
}

/** @brief Unmaps a table that lost the publication race (raw system call, errno preserved). */
static void chaos_io_fdcache_default_unmap(void *mapping)
{
    const int saved_errno = errno;

    (void)syscall(SYS_munmap, mapping, CHAOS_IO_FD_CACHE_BYTES);
    errno = saved_errno;
}

static void *(*g_chaos_io_fdcache_map)(void) = chaos_io_fdcache_default_map;
static void (*g_chaos_io_fdcache_unmap)(void *) = chaos_io_fdcache_default_unmap;

/**
 * @brief Returns the table, mapping and publishing it first when @p create is set.
 *
 * @details Two threads may map concurrently; the CAS publishes the first mapping and the
 * loser unmaps its own and uses the winner's. Acquire/release ordering makes the
 * zero-filled table visible before its address. A failed mapping disables the cache for
 * this call only; a later store tries again.
 *
 * @param create  Non-zero to map the table when it does not exist yet.
 * @return The table, or NULL.
 */
static chaos_io_fd_cache_entry_t *chaos_io_fdcache_table(int create)
{
    chaos_io_fd_cache_entry_t *table = __atomic_load_n(&g_chaos_io_fd_cache, __ATOMIC_ACQUIRE);
    chaos_io_fd_cache_entry_t *expected = NULL;
    void *mapping;

    if (table != NULL || create == 0)
    {
        return table;
    }

    mapping = g_chaos_io_fdcache_map();
    if (mapping == MAP_FAILED)
    {
        return NULL;
    }
    if (__atomic_compare_exchange_n(
            &g_chaos_io_fd_cache,
            &expected,
            (chaos_io_fd_cache_entry_t *)mapping,
            0,
            __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE
        ))
    {
        return (chaos_io_fd_cache_entry_t *)mapping;
    }
    g_chaos_io_fdcache_unmap(mapping);
    return expected;
}

/** @brief Slot index of @p fd: `fd % 32`. */
static unsigned int chaos_io_fdcache_slot(int fd)
{
    return (unsigned int)fd % CHAOS_IO_FD_CACHE_SLOTS;
}

/** @brief Current generation of @p slot (acquire load). */
static unsigned int chaos_io_fdcache_generation(unsigned int slot)
{
    return __atomic_load_n(&g_chaos_io_fd_generation[slot], __ATOMIC_ACQUIRE);
}

/**
 * @brief Stores @p path for @p fd tagged with @p generation, sampled by the caller before
 *        it resolved the path.
 *
 * @details The CAS from an even sequence to odd claims the slot; a writer that finds it
 * odd, or loses the CAS, skips the store and a later lookup resolves again. The release
 * store of sequence + 2 publishes the entry. If an invalidation happened since
 * @p generation was sampled, the entry is stored but never validates.
 */
static void chaos_io_fdcache_store_at(int fd, const char *path, unsigned int generation)
{
    chaos_io_fd_cache_entry_t *table;
    chaos_io_fd_cache_entry_t *entry;
    unsigned int sequence;
    size_t length;

    if (fd < 0 || path == NULL || chaos_io_is_excluded_path(path))
    {
        return;
    }
    length = strlen(path);
    if (length >= CHAOS_IO_MAX_PATH)
    {
        return;
    }
    table = chaos_io_fdcache_table(1);
    if (table == NULL)
    {
        return;
    }

    entry = &table[chaos_io_fdcache_slot(fd)];
    sequence = __atomic_load_n(&entry->sequence, __ATOMIC_ACQUIRE);
    if ((sequence & 1U) != 0U ||
        !__atomic_compare_exchange_n(
            &entry->sequence, &sequence, sequence + 1U, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE
        ))
    {
        return;
    }
    entry->fd_plus_one = fd + 1;
    entry->generation = generation;
    (void)memcpy(entry->path, path, length + 1U);
    __atomic_store_n(&entry->sequence, sequence + 2U, __ATOMIC_RELEASE);
}

void chaos_io_fdcache_reset(void)
{
    unsigned int slot;

    for (slot = 0U; slot < CHAOS_IO_FD_CACHE_SLOTS; ++slot)
    {
        (void)__atomic_add_fetch(&g_chaos_io_fd_generation[slot], 1U, __ATOMIC_ACQ_REL);
    }
}

int chaos_io_fdcache_lookup(int fd, char *path, size_t path_size)
{
    chaos_io_fd_cache_entry_t *table;
    chaos_io_fd_cache_entry_t *entry;
    unsigned int slot;
    unsigned int sequence;
    unsigned int generation;
    size_t length;

    if (fd < 0 || path == NULL || path_size == 0U)
    {
        return 0;
    }
    table = chaos_io_fdcache_table(0);
    if (table == NULL)
    {
        return 0;
    }

    slot = chaos_io_fdcache_slot(fd);
    entry = &table[slot];
    sequence = __atomic_load_n(&entry->sequence, __ATOMIC_ACQUIRE);
    if ((sequence & 1U) != 0U || entry->fd_plus_one != fd + 1)
    {
        return 0;
    }
    generation = entry->generation;
    length = strnlen(entry->path, CHAOS_IO_MAX_PATH);
    if (length + 1U > path_size)
    {
        return 0;
    }
    (void)memcpy(path, entry->path, length);
    path[length] = '\0';

    /* Seqlock validation: a writer that touched the slot during the copy changed the
     * sequence, and an invalidation since the entry was stored changed the generation.
     * Either way the copy is discarded. The acquire fence orders the copy before the
     * re-read of the sequence. */
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (__atomic_load_n(&entry->sequence, __ATOMIC_RELAXED) != sequence ||
        generation != chaos_io_fdcache_generation(slot))
    {
        return 0;
    }
    return 1;
}

void chaos_io_fdcache_store(int fd, const char *path)
{
    if (fd < 0)
    {
        return;
    }
    chaos_io_fdcache_store_at(fd, path, chaos_io_fdcache_generation(chaos_io_fdcache_slot(fd)));
}

void chaos_io_fdcache_invalidate(int fd)
{
    if (fd < 0)
    {
        return;
    }
    (void
    )__atomic_add_fetch(&g_chaos_io_fd_generation[chaos_io_fdcache_slot(fd)], 1U, __ATOMIC_ACQ_REL);
}

int chaos_io_fdcache_resolve(int fd, char *path, size_t path_size)
{
    char proc_path[64];
    unsigned int generation;
    int previous;
    int written;
    ssize_t length;
    int saved_errno;

    if (fd <= 2 || path == NULL || path_size < 2U)
    {
        return 0;
    }
    if (chaos_io_fdcache_lookup(fd, path, path_size))
    {
        return 1;
    }

    written = snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    if (written < 0)
        return 0;

    /* Generation before the readlink: a close() that runs while the link is read bumps
     * it, and the stale path then never validates. */
    generation = chaos_io_fdcache_generation(chaos_io_fdcache_slot(fd));

    /* Inside the guard so the readlink cannot re-enter a wrapper; errno preserved because
     * the lookup is the library's business, not the caller's. */
    saved_errno = errno;
    previous = chaos_io_enter_internal();
    length = readlink(proc_path, path, path_size - 1U);
    chaos_io_leave_internal(previous);
    errno = saved_errno;
    if (length <= 0 || (size_t)length >= path_size)
    {
        return 0;
    }

    path[length] = '\0';
    if (chaos_io_is_excluded_path(path))
    {
        return 0;
    }

    chaos_io_fdcache_store_at(fd, path, generation);
    return 1;
}
