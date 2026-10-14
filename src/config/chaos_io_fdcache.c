/**
 * @file chaos_io_fdcache.c
 * @brief Process-wide, lazily allocated fd-to-path cache implementation.
 *
 * @details
 * Fd-backed wrappers would otherwise need to readlink `/proc/self/fd/<fd>` on
 * every call before they could match path-based rules. A tiny direct-mapped
 * cache is enough for the expected usage while keeping the shared object small.
 *
 * **Why process-wide and lazy.** A descriptor belongs to the process, not to a
 * thread, so the cache does too. A per-thread table had two defects: every thread
 * carried `CHAOS_IO_FD_CACHE_SLOTS * PATH_MAX` bytes of static TLS from its first
 * instruction (the static-TLS budget that crashed the Erlang VM in libchaos-net),
 * and a `close()` on one thread left other threads' entries for that descriptor
 * stale, so a reused descriptor number could be matched against the old path.
 * The table is now mapped once, on the first store, with a raw `mmap` system
 * call: no allocator (the wrappers may run in a signal handler), no interposed
 * `mmap` (libchaos-memory must not be able to fault the cache), no per-thread
 * memory and nothing to free on thread exit.
 *
 * **Invariants maintained by this file:**
 * - Each slot is guarded by a sequence counter: odd while a writer fills it.
 *   Readers copy the entry and accept it only if the counter was even and
 *   unchanged across the copy (a seqlock); a concurrent write makes the lookup
 *   miss, never return a torn path.
 * - Each slot has a generation, bumped by every invalidation. An entry records
 *   the generation it was resolved under and is valid only while that is still
 *   the slot's generation. Invalidation is therefore one atomic increment: no
 *   lock, no waiting, and a lookup that raced with a `close()` can never
 *   re-store the path the close made stale.
 * - Excluded paths (config file, `/proc`, `/sys`, `/dev`) are never stored
 *   and are never returned by `chaos_io_fdcache_resolve()`.
 * - If the table cannot be mapped, every operation degrades to "no cache":
 *   resolution reads `/proc/self/fd` each time, which is slower but correct.
 *
 * **Module ownership:** config/
 * **Stability:** internal
 */

#include "chaos_io_fdcache.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/**
 * @brief One slot of the process-wide direct-mapped fd cache.
 *
 * @details `fd_plus_one` is zero for an empty slot, so the zero-filled pages of
 * a fresh mapping are an empty cache without any initialisation pass.
 */
typedef struct chaos_io_fd_cache_entry
{
    volatile unsigned int sequence; /**< Seqlock: odd while a writer fills the slot. */
    unsigned int generation;        /**< Slot generation the entry was resolved under. */
    int fd_plus_one;                /**< Cached descriptor plus one; zero when empty. */
    char path[CHAOS_IO_MAX_PATH];   /**< Null-terminated resolved filesystem path. */
} chaos_io_fd_cache_entry_t;

/** Size of the lazily mapped table. */
#define CHAOS_IO_FD_CACHE_BYTES (CHAOS_IO_FD_CACHE_SLOTS * sizeof(chaos_io_fd_cache_entry_t))

/** The table, mapped on first store; NULL until then or when mapping failed. */
static chaos_io_fd_cache_entry_t *volatile g_chaos_io_fd_cache = NULL;

/**
 * @brief Per-slot generations, bumped by every invalidation.
 *
 * @details Kept outside the lazily mapped table so an invalidation never has to
 * allocate it: a `close()` before the first cached path still records that the
 * slot changed.
 */
static volatile unsigned int g_chaos_io_fd_generation[CHAOS_IO_FD_CACHE_SLOTS];

/**
 * @brief Maps the anonymous pages of the table, bypassing every interposed `mmap`.
 *
 * @details Replaceable so tests can simulate a failed mapping or a lost race.
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

/** @brief Releases a mapping that lost the publication race. */
static void chaos_io_fdcache_default_unmap(void *mapping)
{
    const int saved_errno = errno;

    (void)syscall(SYS_munmap, mapping, CHAOS_IO_FD_CACHE_BYTES);
    errno = saved_errno;
}

static void *(*g_chaos_io_fdcache_map)(void) = chaos_io_fdcache_default_map;
static void (*g_chaos_io_fdcache_unmap)(void *) = chaos_io_fdcache_default_unmap;

/**
 * @brief Returns the table, mapping it first when @p create is set.
 *
 * @details Two threads may map concurrently; the first to publish wins and the
 * other releases its pages. A failed mapping leaves the cache disabled for this
 * call only, so a later call can try again.
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

/** @brief Slot index of @p fd. */
static unsigned int chaos_io_fdcache_slot(int fd)
{
    return (unsigned int)fd % CHAOS_IO_FD_CACHE_SLOTS;
}

/** @brief Current generation of @p slot. */
static unsigned int chaos_io_fdcache_generation(unsigned int slot)
{
    return __atomic_load_n(&g_chaos_io_fd_generation[slot], __ATOMIC_ACQUIRE);
}

/**
 * @brief Stores @p path for @p fd if the slot is still at @p generation.
 *
 * @details Best effort: if another writer holds the slot, the store is skipped
 * and the next lookup simply resolves again.
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

    /* Seqlock validation: a writer that touched the slot during the copy changed
     * the sequence, and an invalidation since the entry was stored changed the
     * generation. Either way the copy is discarded. */
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

    /* The generation is read before the link: a close() that runs while the link is
     * being read bumps it, and the stale path is then never accepted. */
    generation = chaos_io_fdcache_generation(chaos_io_fdcache_slot(fd));

    /* Enter internal mode: readlink must not be re-intercepted. The lookup is the
     * library's own business, so a failure must not leak into the caller's errno. */
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
