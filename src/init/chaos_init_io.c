/**
 * @file chaos_init_io.c
 * @brief `chaos-init`: libchaos-io rules applied to tracee system calls.
 *
 * @details The libchaos-io rule core (parsing, reload, status file, matching,
 * qualifiers) is compiled in by `#include` of its .c files, unchanged, as the unit tests
 * do. This file only translates a notified system call into the (operation, path, size)
 * the wrappers would pass to that core, following the wrappers exactly:
 *
 * | System call | Operation | Target |
 * |---|---|---|
 * | open, creat, openat, openat2 | open | path (dirfd-relative for *at) |
 * | read, readv / write, writev | read / write | fd |
 * | pread64, preadv, preadv2 / pwrite64, pwritev, pwritev2 | pread / pwrite | fd |
 * | sendfile, copy_file_range | write | the output fd |
 * | close, fsync, fdatasync, ftruncate, fallocate | as named (truncate, allocate) | fd |
 * | truncate | truncate | path |
 * | unlink, unlinkat, rmdir | unlink | path |
 * | rename, renameat, renameat2 | rename_from / rename_to | both paths (see below) |
 *
 * Paths are the strings the wrappers match: absolute, or joined lexically to
 * `/proc/<tid>/cwd` or to the dirfd's `/proc/<tid>/fd/<n>` target, then normalised
 * (no symlink resolution). fds 0-2, non-file descriptors (pipes, sockets) and paths under
 * /proc, /sys and /dev are never faulted. read/write/close on sockets never reach this
 * file: the net decider claims them first.
 *
 * @par Supported effects
 * ERRNO (not on close), LATENCY, DROP on `pwrite`, and TORN and CORRUPT through a ptrace
 * stop. FREE and FULL rewrite the structure the kernel returned, which neither a reply nor
 * a register reaches, so they stay rejected; `statfs` and `fstatfs` themselves are
 * notified, so ERRNO and LATENCY apply to them here as they do in the library. TORN and CORRUPT
 * change data the kernel moves, which a seccomp reply cannot do; ERRNO on close would have to close
 * and fail at once (the wrapper closes, then reports the error), while a notified call either runs
 * or fails. DROP is a reply with the byte count and no call, which is exactly what a notification
 * can answer -- but only for a positioned write: a dropped `write` has to move the descriptor's
 * file offset on, and the supervisor cannot reach another process's descriptor without
 * CAP_SYS_PTRACE. `write:DROP` is therefore rejected here rather than applied without the
 * correction, which would damage the file in a way no real lost write does. A rule file containing
 * any of them is rejected at parse time through the CHAOS_IO_RULE_SUPPORTED hook, so its status
 * file reports `unsupported in seccomp mode` and none of its rules apply.
 *
 * @par Failure behaviour
 * Fail-open: any argument or /proc entry that cannot be read means no match, and the
 * call passes.
 *
 * Test seam: CHAOS_INIT_IO_PROC_LINK replaces the /proc link reader.
 */

#include "chaos_init_io.h"

#include "chaos_bucket.h"

#include <limits.h>

/* Parser hook, defined before the core is included: rules this mode cannot apply reject
 * their file at load time. */
struct chaos_io_rule;
static int chaos_init_io_supported(const struct chaos_io_rule *rule);
#define CHAOS_IO_RULE_SUPPORTED(rule) chaos_init_io_supported(rule)

#include "../config/chaos_io_config.c"
#include "../effects/chaos_io_actions.c"
#include "chaos_init_core.h"
#include "chaos_init_proc.h"
#include "chaos_init_tracee.h"

#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/uio.h>

/* Symbols the rule core expects from the preload library. The "real functions" are
 * plain libc here: the supervisor is under no filter and wraps nothing. The TLS guard
 * and PRNG state are thread-local by contract but the supervisor has one thread. The
 * seed constant is replaced from getrandom() in chaos_init_io_start(). */
chaos_io_open_fn g_chaos_io_real_open = open;
chaos_io_read_fn g_chaos_io_real_read = read;
chaos_io_close_fn g_chaos_io_real_close = close;
__thread int g_chaos_io_tls_guard = 0;
uint64_t g_chaos_io_lineage = 0U;

/** @copydoc g_chaos_io_forks (the supervisor never forks a tracee itself). */
uint64_t g_chaos_io_forks = 0U;
uint64_t g_chaos_io_process_seed = UINT64_C(0x2545f4914f6cdd1d);

/**
 * @brief Whether @p rule's effect needs the tracee's registers rather than a reply.
 *
 * @details TORN shortens the byte count before the kernel reads it; CORRUPT changes a byte
 * the call wrote, which needs the stop after it; DROP on a `write` needs an `lseek` to run
 * in the tracee, which needs the registers twice over; THROTTLE shortens the count like
 * TORN, to whatever its rate allows. A notification can do none of them. The predicate is
 * what puts a system call in the filter's traced group (chaos_init_io_traced_calls()), so adding an
 * effect here without teaching the trace path to apply it would load a rule that never fires.
 */
static int chaos_init_io_traced_effect(const struct chaos_io_rule *rule)
{
    return rule->effect == CHAOS_IO_EFFECT_TORN || rule->effect == CHAOS_IO_EFFECT_CORRUPT ||
           rule->effect == CHAOS_IO_EFFECT_THROTTLE ||
           (rule->effect == CHAOS_IO_EFFECT_DROP && rule->operation == CHAOS_IO_OP_WRITE);
}

/* CHAOS_IO_RULE_SUPPORTED: ERRNO on anything but close, LATENCY, DROP on pwrite (whose
 * offset is its own argument), and the traced effects TORN, CORRUPT, THROTTLE and DROP on
 * write, which the trace path applies through the registers, the tracee's memory and a
 * call of its own. FREE and FULL stay out: they rewrite the structure the kernel returned,
 * which is none of those. */
static int chaos_init_io_supported(const struct chaos_io_rule *rule)
{
    return (rule->effect == CHAOS_IO_EFFECT_ERRNO && rule->operation != CHAOS_IO_OP_CLOSE) ||
           rule->effect == CHAOS_IO_EFFECT_LATENCY ||
           (rule->effect == CHAOS_IO_EFFECT_DROP && rule->operation == CHAOS_IO_OP_PWRITE) ||
           chaos_init_io_traced_effect(rule);
}

/** @brief Test seam: the /proc identity lookup, as in chaos_init_tracee.c. */
#ifndef CHAOS_INIT_PROCESS_OF
#define CHAOS_INIT_PROCESS_OF(tid, tgid, start) chaos_init_process_of((tid), (tgid), (start))
#endif

/** @brief Test seam: how /proc links are read; unit tests make one unreadable. */
#ifndef CHAOS_INIT_IO_PROC_LINK
#define CHAOS_INIT_IO_PROC_LINK chaos_init_proc_link
#endif

/** @brief Test seam: how a tracee's fdinfo is opened; unit tests make it fail. */
#ifndef CHAOS_INIT_IO_FDINFO_OPEN
#define CHAOS_INIT_IO_FDINFO_OPEN fopen
#endif

/** @brief Test seam: how a tracee's descriptor is stat'ed; unit tests make it fail. */
#ifndef CHAOS_INIT_IO_FD_STAT
#define CHAOS_INIT_IO_FD_STAT stat
#endif

/** @brief How a system call names what it acts on, i.e. how its target path is derived. */
typedef enum chaos_init_io_kind
{
    CHAOS_INIT_IO_FD,      /**< args[target] is a descriptor. */
    CHAOS_INIT_IO_PATH,    /**< args[target] is a path, relative to the cwd. */
    CHAOS_INIT_IO_PATH_AT, /**< args[target - 1] a directory fd, args[target] a path. */
#ifdef __NR_rename
    CHAOS_INIT_IO_RENAME, /**< args[0] and args[1] are paths (x86_64 rename). */
#endif
    CHAOS_INIT_IO_RENAME_AT /**< dirfd, path, dirfd, path in args[0..3]. */
} chaos_init_io_kind_t;

/** @brief One row of the io decode table: system call number to wrapper semantics. */
typedef struct chaos_init_io_call
{
    long nr;
    chaos_io_operation_t operation;
    chaos_init_io_kind_t kind;
    int target; /**< Argument index of the descriptor or path. */
    int size;   /**< Argument index of the byte count; -1 none, -2 an iovec array. */
} chaos_init_io_call_t;

/* Must list exactly the numbers of g_chaos_init_io_calls in chaos_init_core.c. */
static const chaos_init_io_call_t g_chaos_init_io_calls[] = {
    {__NR_openat, CHAOS_IO_OP_OPEN, CHAOS_INIT_IO_PATH_AT, 1, -1},
    {__NR_read, CHAOS_IO_OP_READ, CHAOS_INIT_IO_FD, 0, 2},
    {__NR_readv, CHAOS_IO_OP_READ, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_write, CHAOS_IO_OP_WRITE, CHAOS_INIT_IO_FD, 0, 2},
    {__NR_writev, CHAOS_IO_OP_WRITE, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_pread64, CHAOS_IO_OP_PREAD, CHAOS_INIT_IO_FD, 0, 2},
    {__NR_preadv, CHAOS_IO_OP_PREAD, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_preadv2, CHAOS_IO_OP_PREAD, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_pwrite64, CHAOS_IO_OP_PWRITE, CHAOS_INIT_IO_FD, 0, 2},
    {__NR_pwritev, CHAOS_IO_OP_PWRITE, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_pwritev2, CHAOS_IO_OP_PWRITE, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_sendfile, CHAOS_IO_OP_WRITE, CHAOS_INIT_IO_FD, 0, 3},
    {__NR_copy_file_range, CHAOS_IO_OP_WRITE, CHAOS_INIT_IO_FD, 2, 4},
    {__NR_close, CHAOS_IO_OP_CLOSE, CHAOS_INIT_IO_FD, 0, -1},
    {__NR_fsync, CHAOS_IO_OP_FSYNC, CHAOS_INIT_IO_FD, 0, -1},
    {__NR_fdatasync, CHAOS_IO_OP_FDATASYNC, CHAOS_INIT_IO_FD, 0, -1},
    {__NR_ftruncate, CHAOS_IO_OP_TRUNCATE, CHAOS_INIT_IO_FD, 0, 1},
    {__NR_truncate, CHAOS_IO_OP_TRUNCATE, CHAOS_INIT_IO_PATH, 0, 1},
    {__NR_fallocate, CHAOS_IO_OP_ALLOCATE, CHAOS_INIT_IO_FD, 0, 3},
    {__NR_unlinkat, CHAOS_IO_OP_UNLINK, CHAOS_INIT_IO_PATH_AT, 1, -1},
    {__NR_renameat2, CHAOS_IO_OP_RENAME_FROM, CHAOS_INIT_IO_RENAME_AT, 0, -1},
    {__NR_statfs, CHAOS_IO_OP_STATFS, CHAOS_INIT_IO_PATH, 0, -1},
    {__NR_fstatfs, CHAOS_IO_OP_STATFS, CHAOS_INIT_IO_FD, 0, -1},
#ifdef __NR_openat2
    {__NR_openat2, CHAOS_IO_OP_OPEN, CHAOS_INIT_IO_PATH_AT, 1, -1},
#endif
#ifdef __NR_open
    {__NR_open, CHAOS_IO_OP_OPEN, CHAOS_INIT_IO_PATH, 0, -1},
#endif
#ifdef __NR_creat
    {__NR_creat, CHAOS_IO_OP_OPEN, CHAOS_INIT_IO_PATH, 0, -1},
#endif
#ifdef __NR_unlink
    {__NR_unlink, CHAOS_IO_OP_UNLINK, CHAOS_INIT_IO_PATH, 0, -1},
#endif
#ifdef __NR_rmdir
    {__NR_rmdir, CHAOS_IO_OP_UNLINK, CHAOS_INIT_IO_PATH, 0, -1},
#endif
#ifdef __NR_rename
    {__NR_rename, CHAOS_IO_OP_RENAME_FROM, CHAOS_INIT_IO_RENAME, 0, -1},
#endif
#ifdef __NR_renameat
    {__NR_renameat, CHAOS_IO_OP_RENAME_FROM, CHAOS_INIT_IO_RENAME_AT, 0, -1},
#endif
};

/*---------------------------------------------------------------------------*
 * THROTTLE: the same token bucket as the library's, one per tracee descriptor
 *---------------------------------------------------------------------------*/

/** @brief Descriptors whose write rate the supervisor tracks at once. */
#define CHAOS_INIT_IO_THROTTLE_SLOTS 64U

/**
 * @brief One descriptor's bucket, keyed by the process and the descriptor number.
 *
 * @details The library keys its buckets by descriptor alone, because they belong to one
 * process; the supervisor serves a container, so the thread group is part of the key.
 * A colliding entry takes the slot over, as in the library.
 */
typedef struct chaos_init_io_throttle
{
    pid_t tgid;
    int fd;
    uint64_t rate;
    chaos_bucket_t bucket;
    /** Whether this slot has ever had an owner: a takeover starts empty, a first use full. */
    int taken;
} chaos_init_io_throttle_t;

static chaos_init_io_throttle_t g_chaos_init_io_throttles[CHAOS_INIT_IO_THROTTLE_SLOTS];

/** @brief The bucket of (@p tgid, @p fd, @p rate), reset when the slot held something else. */
static chaos_bucket_t *chaos_init_io_throttle_bucket(pid_t tgid, uint64_t fd, uint64_t rate)
{
    chaos_init_io_throttle_t *entry =
        &g_chaos_init_io_throttles[((unsigned)fd + (unsigned)tgid) % CHAOS_INIT_IO_THROTTLE_SLOTS];

    if (entry->tgid != tgid || entry->fd != (int)fd || entry->rate != rate)
    {
        /* Empty for a new owner, full only the first time: see chaos_io_rw.c. The key
         * holds the thread group here, so collisions are container-wide and a pre-forking
         * server reaches them easily. */
        const int stolen = entry->taken && (entry->fd != (int)fd || entry->tgid != tgid);

        entry->bucket.state = stolen ? chaos_bucket_state(0U, chaos_hits_now_ms()) : 0U;
        entry->taken = 1;
        entry->rate = rate;
        entry->fd = (int)fd;
        entry->tgid = tgid;
    }
    return &entry->bucket;
}

/** @brief Result value that means "the call has not run yet" (the entry stop). */
#define CHAOS_INIT_IO_NO_RESULT LONG_MIN

/**
 * @brief Whether @p rule needs a trace stop for @p entry in particular.
 *
 * @details TORN, CORRUPT and THROTTLE need the byte count or the buffer in a register,
 * which the vectored forms keep in memory: they stay on the notification path, as the
 * library leaves them whole too. DROP needs no register of the call, only a stop to put an
 * `lseek` in its place, so it takes the vectored form as well -- but not `sendfile` and
 * `copy_file_range`, which carry a `write` rule and never a DROP: they move bytes between
 * two descriptors, and dropping one would need both offsets.
 */
static int
chaos_init_io_traced_call(const struct chaos_io_rule *rule, const chaos_init_io_call_t *entry)
{
    if (rule->operation != entry->operation)
    {
        return 0;
    }
    if (rule->effect == CHAOS_IO_EFFECT_DROP)
    {
        return entry->nr == __NR_write || entry->nr == __NR_writev;
    }
    return entry->size >= 0;
}

/** @copydoc chaos_init_io_traced_calls */
size_t chaos_init_io_traced_calls(long *out, size_t capacity)
{
    const chaos_io_config_state_t *state;
    size_t count = 0U;
    size_t rule_index;

    if (out == NULL || !chaos_io_config_prepare())
    {
        return 0U;
    }
    state = chaos_io_config_active_state();
    for (rule_index = 0U; rule_index < state->rule_count; ++rule_index)
    {
        size_t entry;

        if (!chaos_init_io_traced_effect(&state->rules[rule_index]))
        {
            continue;
        }
        for (entry = 0U; entry < sizeof(g_chaos_init_io_calls) / sizeof(g_chaos_init_io_calls[0]);
             ++entry)
        {
            size_t seen;

            if (!chaos_init_io_traced_call(
                    &state->rules[rule_index], &g_chaos_init_io_calls[entry]
                ))
            {
                continue;
            }
            for (seen = 0U; seen < count; ++seen)
            {
                if (out[seen] == g_chaos_init_io_calls[entry].nr)
                {
                    break;
                }
            }
            if (seen < count)
            {
                continue;
            }
            if (count == capacity)
            {
                return count;
            }
            out[count++] = g_chaos_init_io_calls[entry].nr;
        }
    }
    return count;
}

/* Per-process hit slots of the io rules. */
CHAOS_INIT_RULES_STORAGE(g_chaos_init_io, CHAOS_IO_MAX_RULES);

/** @brief Load counter of the active snapshot (see chaos_init_rules_t::snapshot). */
static uint64_t g_chaos_init_io_load = 0U;
static const chaos_io_config_state_t *g_chaos_init_io_seen_state = NULL;
static uint64_t g_chaos_init_io_seen_stamp = 0U;

/* chaos_init_rules_t::snapshot for io. A reload is detected by the active state pointer
 * (the core alternates two snapshots) or the cached rule file mtime changing; either bumps
 * the load counter, which makes every process re-sync its slots by rule text. */
static size_t chaos_init_io_snapshot(const chaos_init_text_t **texts, uint64_t *generation)
{
    const chaos_io_config_state_t *state = chaos_io_config_active_state();

    if (g_chaos_init_io_load == 0U || state != g_chaos_init_io_seen_state ||
        g_chaos_io_cached_mtime != g_chaos_init_io_seen_stamp)
    {
        g_chaos_init_io_seen_state = state;
        g_chaos_init_io_seen_stamp = g_chaos_io_cached_mtime;
        ++g_chaos_init_io_load;
    }
    *texts = (const chaos_init_text_t *)state->text;
    *generation = g_chaos_init_io_load;
    return state->rule_count;
}

/**
 * @brief Sets the io draw lineage for the process with allocation serial @p serial.
 *
 * @details Serial 1 is the application itself and gets lineage 0, so a single-process run
 * decides exactly as it would under `LD_PRELOAD`. Every later process is a descendant and
 * gets a lineage of its own, which is what keeps the backends of a pre-forking server from
 * all drawing the same sample -- the library reaches the same end from the other side, by
 * mixing each child's ordinal among its siblings in the atfork handler.
 */
static void chaos_init_io_lineage(uint64_t serial)
{
    g_chaos_io_lineage = serial > 1U ? chaos_io_prng_mix(serial - 1U) : 0U;
}

static chaos_init_rules_t g_chaos_init_io_rules = {
    CHAOS_IO_HITS_PREFIX,
    CHAOS_IO_MAX_RULES,
    chaos_init_io_snapshot,
    /* The same header the library writes, so a reader correlates the counts with the
     * same reload generation whichever mode produced them. */
    chaos_io_hits_header,
    /* Each process the supervisor decides for draws with a lineage of its own. */
    chaos_init_io_lineage,
    g_chaos_init_io_slots,
    g_chaos_init_io_hashes,
    g_chaos_init_io_generation,
    g_chaos_init_io_count,
    g_chaos_init_io_total,
    g_chaos_init_io_pending,
    g_chaos_init_io_buffer,
    g_chaos_init_io_file,
};

void chaos_init_io_start(void)
{
    chaos_io_config_init();
    g_chaos_io_process_seed = chaos_init_seed();
    (void)chaos_init_tracee_register(&g_chaos_init_io_rules);
}

/** @copydoc chaos_init_io_reload */
void chaos_init_io_reload(void)
{
    (void)chaos_io_config_prepare();
}

/**
 * @brief Resolves descriptor @p fd of thread @p tid to its file path via
 *        `/proc/<tid>/fd/<fd>`. @p fd is sign-extended from 32 bits, so negative values
 *        and fds 0-2 are rejected, as are non-path targets (`pipe:[..]`, `socket:[..]`).
 * @return 1 with an absolute path in @p out, else 0.
 */
static int chaos_init_io_fd_path(pid_t tid, uint64_t fd, char *out, size_t size)
{
    char name[32];

    if ((int64_t)(int32_t)fd <= 2)
    {
        return 0;
    }
    (void)snprintf(name, sizeof(name), "fd/%d", (int)fd);
    return CHAOS_INIT_IO_PROC_LINK(tid, name, out, size) > 0 && out[0] == '/';
}

/** @brief What a dropped write has to do about the file offset of a tracee descriptor. */
typedef enum chaos_init_io_offset
{
    CHAOS_INIT_IO_OFFSET_NONE = 0, /**< No offset to move: leave the call alone. */
    CHAOS_INIT_IO_OFFSET_MOVE,     /**< Move it on by the byte count (an `lseek`). */
    CHAOS_INIT_IO_OFFSET_KEEP      /**< `O_APPEND`: the kernel ignores it, nothing to do. */
} chaos_init_io_offset_t;

/**
 * @brief Whether descriptor @p fd of thread @p tid has an offset a dropped write must
 *        move on, as chaos_io_drop_write() asks the descriptor itself.
 *
 * @details The flags come from `/proc/<tid>/fdinfo/<fd>` (octal, as the kernel prints
 * them) and the file type from the `/proc/<tid>/fd/<fd>` link, because the supervisor
 * cannot ask the descriptor with an `lseek` without moving the offset it is asking about.
 * That is the one difference to the library: a regular file and a block device have an
 * offset here, a character device is left alone even where its own `lseek` would work.
 * An unreadable descriptor is left alone too, as a failing `fcntl` leaves it there.
 */
/**
 * @brief The open flags of descriptor @p fd of thread @p tid, from its fdinfo.
 *
 * @details `/proc/<tid>/fdinfo/<fd>` prints them in octal, which is the only way to learn
 * them from outside: `fcntl` would have to run in the tracee.
 *
 * @return The flags, or -1 when they cannot be read.
 */
static long chaos_init_io_flags(pid_t tid, uint64_t fd)
{
    char name[64];
    char line[128];
    FILE *file;
    long flags = -1;

    (void)snprintf(name, sizeof(name), "/proc/%ld/fdinfo/%d", (long)tid, (int)fd);
    file = CHAOS_INIT_IO_FDINFO_OPEN(name, "r");
    if (file == NULL)
    {
        return -1;
    }
    while (fgets(line, sizeof(line), file) != NULL)
    {
        if (strncmp(line, "flags:", 6U) == 0)
        {
            flags = strtol(line + 6, NULL, 8);
            break;
        }
    }
    (void)fclose(file);
    return flags;
}

/** @brief Whether @p fd of @p tid is non-blocking; 0 when its flags cannot be read. */
static int chaos_init_io_nonblocking(pid_t tid, uint64_t fd)
{
    const long flags = chaos_init_io_flags(tid, fd);

    return flags >= 0 && (flags & O_NONBLOCK) != 0;
}

static chaos_init_io_offset_t chaos_init_io_offset_of(pid_t tid, uint64_t fd)
{
    char name[64];
    struct stat status;
    const long flags = chaos_init_io_flags(tid, fd);

    if (flags < 0)
    {
        return CHAOS_INIT_IO_OFFSET_NONE;
    }
    if ((flags & O_APPEND) != 0)
    {
        return CHAOS_INIT_IO_OFFSET_KEEP;
    }
    (void)snprintf(name, sizeof(name), "/proc/%ld/fd/%d", (long)tid, (int)fd);
    if (CHAOS_INIT_IO_FD_STAT(name, &status) != 0)
    {
        return CHAOS_INIT_IO_OFFSET_NONE;
    }
    return S_ISREG(status.st_mode) || S_ISBLK(status.st_mode) ? CHAOS_INIT_IO_OFFSET_MOVE
                                                              : CHAOS_INIT_IO_OFFSET_NONE;
}

/**
 * @brief Builds the path string the wrappers match for (dirfd, path) of thread @p tid.
 *
 * @details The path is read from tracee memory. An absolute path is used as is; a
 * relative one is joined to `/proc/<tid>/cwd` (no dirfd, or AT_FDCWD) or to the dirfd's
 * path. The result is normalised lexically (chaos_io_normalize_path()), as the wrappers
 * do; symlinks are not resolved.
 *
 * @param has_dirfd  Whether @p dirfd is meaningful (the *at variants).
 * @return 1 with the path in @p out; 0 when any part is unreadable or does not fit.
 */
static int chaos_init_io_at_path(
    pid_t tid, int has_dirfd, uint64_t dirfd, uint64_t address, char *out, size_t size
)
{
    char path[CHAOS_IO_MAX_PATH];
    char base[CHAOS_IO_MAX_PATH];
    int at_cwd;

    if (chaos_init_read_string(tid, address, path, sizeof(path)) < 0)
    {
        return 0;
    }
    at_cwd = !has_dirfd || (int)(int32_t)dirfd == AT_FDCWD;
    if (path[0] == '/' ? !chaos_io_copy_path(out, size, path)
                       : (at_cwd ? CHAOS_INIT_IO_PROC_LINK(tid, "cwd", base, sizeof(base)) <= 0
                                 : !chaos_init_io_fd_path(tid, dirfd, base, sizeof(base))) ||
                             !chaos_io_join_paths(out, size, base, path))
    {
        return 0;
    }
    chaos_io_normalize_path(out);
    return 1;
}

/**
 * @brief Total bytes of an iovec array of thread @p tid, for `@size`. Read in batches of
 *        64 entries; more than 1024 entries (the kernel's UIO_MAXIOV, which fails such a
 *        call with EINVAL anyway) or an unreadable array yields CHAOS_POLICY_NO_SIZE.
 */
static uint64_t chaos_init_io_iov_size(pid_t tid, uint64_t address, uint64_t count)
{
    struct iovec vector[64];
    uint64_t total = 0U;
    uint64_t done = 0U;

    if (count > 1024U)
    {
        return CHAOS_POLICY_NO_SIZE;
    }
    while (done < count)
    {
        const uint64_t chunk = count - done < 64U ? count - done : 64U;
        uint64_t index;

        if (chaos_init_read_memory(
                tid, address + done * sizeof(struct iovec), vector, chunk * sizeof(struct iovec)
            ) != 0)
        {
            return CHAOS_POLICY_NO_SIZE;
        }
        for (index = 0U; index < chunk; ++index)
        {
            /* A total above SSIZE_MAX is no byte count: the call returns ssize_t, so the
             * kernel rejects it with EINVAL. Summing it anyway would wrap and hand the
             * gates a small number for a huge request. Checked before the addition. */
            if ((uint64_t)vector[index].iov_len > (uint64_t)SSIZE_MAX - total)
            {
                return CHAOS_POLICY_NO_SIZE;
            }
            total += (uint64_t)vector[index].iov_len;
        }
        done += chunk;
    }
    return total;
}

/**
 * @brief Matches @p path for @p operation against the loaded rules, excluding /proc, /sys
 *        and /dev. Precondition: chaos_io_config_prepare() succeeded.
 */
static int
chaos_init_io_match(chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule)
{
    return !chaos_io_is_excluded_path(path) && chaos_io_config_match_loaded(operation, path, rule);
}

/**
 * @brief Selects the rule a rename is decided by, as the wrapper does: rename_to on the
 *        destination wins when it matches and its path prefix is at least as long as a
 *        rename_from match on the source; otherwise the source's rule.
 *
 * @param at  1 for renameat/renameat2 (dirfd, path, dirfd, path), 0 for rename (path, path).
 * @return 1 with the rule in @p rule, 0 when neither side matches or both are unreadable.
 */
static int chaos_init_io_rename(const chaos_init_call_t *call, int at, chaos_io_rule_t *rule)
{
    char from[CHAOS_IO_MAX_PATH];
    char to[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t from_rule;
    chaos_io_rule_t to_rule;
    const int from_ok = chaos_init_io_at_path(
        call->tid, at, call->args[0], call->args[at ? 1 : 0], from, sizeof(from)
    );
    const int to_ok =
        chaos_init_io_at_path(call->tid, at, call->args[2], call->args[at ? 3 : 1], to, sizeof(to));
    int have_from;
    int have_to;

    if ((!from_ok && !to_ok) || !chaos_io_config_prepare())
    {
        return 0;
    }
    have_from = from_ok && chaos_init_io_match(CHAOS_IO_OP_RENAME_FROM, from, &from_rule);
    have_to = to_ok && chaos_init_io_match(CHAOS_IO_OP_RENAME_TO, to, &to_rule);
    if (have_to && (!have_from || to_rule.path_len >= from_rule.path_len))
    {
        *rule = to_rule;
        return 1;
    }
    if (have_from)
    {
        *rule = from_rule;
        return 1;
    }
    return 0;
}

/* Decode by table, build the path, match, then let the core's trigger decide (probability,
 * qualifiers, hit counting) on the per-process slot. */
/**
 * @brief chaos_init_io_decide() and chaos_init_io_decide_result() in one body.
 *
 * @details The two stops of a traced call have to select the same rule, so they share the
 * selection rather than repeating it. @p result is CHAOS_INIT_IO_NO_RESULT at the entry
 * stop and the call's return value at the exit stop; the argument registers hold the same
 * values at both, so the path, the match and the `@size` input are identical.
 */
static int
chaos_init_io_decide_at(const chaos_init_call_t *call, long result, chaos_init_verdict_t *verdict)
{
    const chaos_init_io_call_t *entry = NULL;
    const chaos_io_config_state_t *state;
    chaos_bucket_t *throttle_bucket = NULL;
    uint64_t throttle_allowed = 0U;
    char path[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t rule;
    size_t index;
    int matched = 0;
    int drop_offset = 0;

    for (index = 0U; index < sizeof(g_chaos_init_io_calls) / sizeof(g_chaos_init_io_calls[0]);
         ++index)
    {
        if (g_chaos_init_io_calls[index].nr == call->nr)
        {
            entry = &g_chaos_init_io_calls[index];
            break;
        }
    }
    if (entry == NULL)
    {
        return 0;
    }
    verdict->action = CHAOS_INIT_PASS;

    switch (entry->kind)
    {
    case CHAOS_INIT_IO_FD:
        matched = chaos_init_io_fd_path(call->tid, call->args[entry->target], path, sizeof(path)) &&
                  chaos_io_config_match_path(entry->operation, path, &rule);
        break;
    case CHAOS_INIT_IO_PATH:
        matched = chaos_init_io_at_path(
                      call->tid, 0, 0U, call->args[entry->target], path, sizeof(path)
                  ) &&
                  chaos_io_config_match_path(entry->operation, path, &rule);
        break;
    case CHAOS_INIT_IO_PATH_AT:
        matched = chaos_init_io_at_path(
                      call->tid,
                      1,
                      call->args[entry->target - 1],
                      call->args[entry->target],
                      path,
                      sizeof(path)
                  ) &&
                  chaos_io_config_match_path(entry->operation, path, &rule);
        break;
#ifdef __NR_rename
    case CHAOS_INIT_IO_RENAME:
        matched = chaos_init_io_rename(call, 0, &rule);
        break;
#endif
    case CHAOS_INIT_IO_RENAME_AT:
        matched = chaos_init_io_rename(call, 1, &rule);
        break;
    }
    /* A loaded rule is ERRNO, LATENCY or DROP on pwrite only (chaos_init_io_supported()
     * rejected the rest at parse time). */
    if (!matched)
    {
        return 1;
    }

    /* `@size` input, measured only after a match: the iovec case costs tracee reads. */
    if (entry->size >= 0)
    {
        rule.call_size = call->args[entry->size];
    }
    else if (entry->size == -2)
    {
        rule.call_size = chaos_init_io_iov_size(call->tid, call->args[1], call->args[2]);
    }
    /* Swap the snapshot's shared slot for the calling process's, so probability,
     * `@first` and windows count per process as under LD_PRELOAD. No slot (the process
     * ended): do not fire. */
    /* DROP answers with the byte count, so it needs a count the call could have returned.
     * chaos_init_io_iov_size() sums a vector without bounding the total, unlike the
     * library's own, so the bound is here: reporting more than SSIZE_MAX as written would
     * hand the tracee a negative return, an error with no errno. One comparison covers the
     * unreadable case too, since the sentinel is UINT64_MAX. Checked before the draw, so
     * no hit is spent on a call it leaves alone. */
    if (rule.effect == CHAOS_IO_EFFECT_DROP && rule.call_size > (uint64_t)SSIZE_MAX)
    {
        return 1;
    }
    /* A dropped `write` has to move the file offset on by what it claims to have written,
     * or the caller's next write lands on top of bytes it believes are already there.
     * `pwrite` carries its own offset and moves none. The correction is an `lseek` run in
     * the tracee, so the call is replaced by it (CHAOS_INIT_INSTEAD) and the tracee is
     * told the byte count afterwards. Nothing to move -- `O_APPEND`, or a zero-byte write
     * -- needs no second call. A descriptor with no offset is left alone, as in the
     * library: the data would simply be gone, and that case belongs to net's DROP on a
     * datagram. All of it before the draw, so a call left alone counts no hit. */
    if (rule.effect == CHAOS_IO_EFFECT_DROP && rule.operation == CHAOS_IO_OP_WRITE)
    {
        const chaos_init_io_offset_t offset = chaos_init_io_offset_of(call->tid, call->args[0]);

        if (offset == CHAOS_INIT_IO_OFFSET_NONE ||
            (entry->nr != __NR_write && entry->nr != __NR_writev))
        {
            return 1;
        }
        drop_offset = offset == CHAOS_INIT_IO_OFFSET_MOVE && rule.call_size > 0U;
    }
    /* TORN and THROTTLE shorten the count where it sits in a register. The vectored forms
     * keep it in memory, so one argument cannot shorten them and they are written whole --
     * the same answer the library gives a vector it cannot tear or hold back. Checked
     * before the draw, so such a call counts no hit and no tokens. */
    /* An effect that only a trace stop can carry, on a call the installed filter does not
     * trace: the filter is fixed for the life of the container, so a reload that adds such
     * a rule cannot make it work. Before the draw, so the rule reports no hit for a fault
     * nobody injected -- which is what the documented "loads and does not fire" means. */
    if (chaos_init_io_traced_effect(&rule) && chaos_init_io_traced_call(&rule, entry) &&
        !chaos_init_traced(call->nr))
    {
        return 1;
    }
    if ((rule.effect == CHAOS_IO_EFFECT_TORN || rule.effect == CHAOS_IO_EFFECT_THROTTLE) &&
        entry->size < 0)
    {
        return 1;
    }
    if (rule.effect == CHAOS_IO_EFFECT_CORRUPT && result <= 0 && result != CHAOS_INIT_IO_NO_RESULT)
    {
        /* The read failed or hit end of file: there are no bytes to corrupt, and turning a
         * detectable error into silent corruption would change what is being tested. No
         * draw, so no hit -- as in the library. */
        return 1;
    }
    if (rule.effect == CHAOS_IO_EFFECT_CORRUPT)
    {
        /* Nothing to decide yet at the entry stop: how many bytes there are to corrupt is
         * the call's result. The thread is continued into its exit stop and this runs
         * again, so the draw happens where the library's does -- after the call -- and a
         * read that returned nothing counts no hit. A vectored read keeps its bytes across
         * segments; finding the one that holds byte N would mean walking the iovec in the
         * tracee, so those are left alone and count no hit either. */
        if (result == CHAOS_INIT_IO_NO_RESULT)
        {
            verdict->action = entry->size < 0 ? CHAOS_INIT_PASS : CHAOS_INIT_AFTER;
            return 1;
        }
    }
    else if (result != CHAOS_INIT_IO_NO_RESULT)
    {
        /* Every other effect was applied at the entry stop; the exit stop has nothing to
         * add, and must not draw again. */
        return 1;
    }
    /* THROTTLE takes its bytes before the rule is asked, as the library does: an
     * allowance that covers the whole call changes nothing, so it must spend neither a hit
     * nor a `@first` claim. The bytes are charged either way -- they are gone whether the
     * rule then fires or not -- which is why this effect decides before the draw. */
    if (rule.effect == CHAOS_IO_EFFECT_THROTTLE)
    {
        pid_t throttle_tgid = 0;
        uint64_t throttle_image = 0U;

        throttle_bucket =
            CHAOS_INIT_PROCESS_OF(call->tid, &throttle_tgid, &throttle_image) == 0
                ? chaos_init_io_throttle_bucket(throttle_tgid, call->args[0], rule.rate_bps)
                : NULL;
        throttle_allowed =
            throttle_bucket != NULL
                ? chaos_bucket_take(
                      throttle_bucket, rule.rate_bps, rule.call_size, chaos_hits_now_ms()
                  )
                : rule.call_size;
        if (throttle_allowed >= rule.call_size)
        {
            return 1;
        }
    }
    state = chaos_io_config_active_state();
    rule.hit = chaos_init_tracee_hit(
        &g_chaos_init_io_rules, call->tid, state->hits, state->rule_count, rule.hit
    );
    rule.hit_generation = rule.hit != NULL ? rule.hit->generation : 0U;
    if (rule.hit == NULL || !chaos_io_rule_should_trigger(&rule))
    {
        return 1;
    }
    if (rule.effect == CHAOS_IO_EFFECT_CORRUPT)
    {
        /* One byte of what the read delivered, chosen as chaos_io_corrupt_buffer_sample()
         * chooses it: the first draw picks the byte, the second its bit. The byte is read
         * out of the tracee, flipped and written back, which is the same edit the library
         * makes in its own address space. */
        const uint64_t length = (uint64_t)result;
        const uint64_t offset =
            (uint64_t)chaos_io_rule_draw(&rule, CHAOS_IO_DRAW_FIRST_EFFECT) % length;
        const unsigned bit = chaos_io_rule_draw(&rule, CHAOS_IO_DRAW_SECOND_EFFECT) & 7U;
        unsigned char byte = 0U;

        if (chaos_init_read_memory(call->tid, call->args[1] + offset, &byte, sizeof(byte)) == 0)
        {
            byte ^= (unsigned char)(1U << bit);
            (void)chaos_init_write_memory(call->tid, call->args[1] + offset, &byte, sizeof(byte));
        }
    }
    else if (rule.effect == CHAOS_IO_EFFECT_ERRNO)
    {
        verdict->action = CHAOS_INIT_FAIL;
        verdict->error = rule.errnum;
    }
    else if (rule.effect == CHAOS_IO_EFFECT_TORN)
    {
        /* The count is in a register, so the filter traced this call and the stop can
         * rewrite it. chaos_io_torn_count() draws from the same slot the notification path
         * uses, so a torn write counts one hit like everywhere else. */
        verdict->action = CHAOS_INIT_SHORTEN;
        verdict->arg_index = (unsigned)entry->size;
        verdict->value = (long)chaos_io_torn_count(&rule, (size_t)rule.call_size);
    }
    else if (rule.effect == CHAOS_IO_EFFECT_THROTTLE)
    {
        /* The bytes were taken before the draw (above); what is left is how to answer a
         * call the rate cannot serve whole. The supervisor shortens it where the count
         * sits in a register, and otherwise parks it rather than sleeping in the thread,
         * so the tracee's other threads keep being served. A non-blocking descriptor is
         * told EAGAIN, as in the library. */
        if (throttle_allowed > 0U)
        {
            verdict->action = CHAOS_INIT_SHORTEN;
            verdict->arg_index = (unsigned)entry->size;
            verdict->value = (long)throttle_allowed;
        }
        else if (chaos_init_io_nonblocking(call->tid, call->args[0]))
        {
            verdict->action = CHAOS_INIT_FAIL;
            verdict->error = EAGAIN;
        }
        else
        {
            const uint64_t chunk = chaos_bucket_chunk(rule.rate_bps);
            const uint64_t held = chunk < rule.call_size ? chunk : rule.call_size;
            /* Reserved, not just waited for: the bytes are charged when the call is
             * parked, so a second caller waits for the ones after them and the rate comes
             * out the same as the library's. */
            const uint64_t wait =
                chaos_bucket_reserve(throttle_bucket, rule.rate_bps, held, chaos_hits_now_ms());

            verdict->action = CHAOS_INIT_DELAY;
            verdict->delay_ms = (unsigned)wait;
            verdict->shortens = 1;
            verdict->arg_index = (unsigned)entry->size;
            verdict->value = (long)held;
        }
    }
    else if (rule.effect == CHAOS_IO_EFFECT_DROP)
    {
        verdict->action = drop_offset ? CHAOS_INIT_INSTEAD : CHAOS_INIT_RETURN;
        verdict->value = (long)rule.call_size;
        verdict->instead_nr = __NR_lseek;
        verdict->instead_args[0] = call->args[0];
        verdict->instead_args[1] = rule.call_size;
        verdict->instead_args[2] = (uint64_t)SEEK_CUR;
    }
    else
    {
        verdict->action = CHAOS_INIT_DELAY;
        verdict->delay_ms = rule.latency_ms;
    }
    return 1;
}

/** @copydoc chaos_init_io_decide */
int chaos_init_io_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    return chaos_init_io_decide_at(call, CHAOS_INIT_IO_NO_RESULT, verdict);
}

/** @copydoc chaos_init_io_decide_result */
int chaos_init_io_decide_result(const chaos_init_call_t *call, long result)
{
    chaos_init_verdict_t verdict;

    return chaos_init_io_decide_at(call, result, &verdict);
}
