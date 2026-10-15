/**
 * @file chaos_io_open.c
 * @brief Path-first wrappers for `open(2)` and `openat(2)`.
 *
 * @details
 * `open()` and `openat()` are grouped together because they share the same
 * varargs ABI handling, path-resolution semantics, and fd-cache seeding rules.
 *
 * **Open wrapper execution sequence:**
 * 1. Decode the optional `mode_t` argument from varargs if `O_CREAT` (or
 *    `O_TMPFILE`) is present in `flags`.
 * 2. Bail out immediately via the real open call if the reentrancy guard is set
 *    (the library is already inside an internal operation).
 * 3. Attempt to resolve the call-site path to a matchable absolute string via
 *    `chaos_io_resolve_at_path()`.  Failure here is non-fatal; the wrapper
 *    falls back to post-open fd-cache seeding instead.
 * 4. Match the resolved path against the config for the `OPEN` operation.
 * 5. If a `LATENCY` rule matched, sleep before delegating to libc.
 *    If an `ERRNO` rule matched and triggered, return -1 without calling libc.
 * 6. Call the real `open()` / `openat()`.
 * 7. On success, populate the fd cache so descriptor-based wrappers can later
 *    resolve the fd to its path without a `/proc/self/fd` round-trip.
 *
 * **`chaos_io_resolve_at_path()` is also defined here** (it is exported via
 * `chaos_io_wrappers.h`) because both `open.c` and `fsops.c` need it, and it
 * logically belongs alongside the code that resolves openat-style paths.
 *
 * **Varargs ABI note.**
 * The `mode_t` argument is decoded from `va_list` as `int` (default integer
 * promotion), then cast back to `mode_t` for the real call.  The real open
 * helper (`chaos_io_call_real_open`) then passes it as a literal third
 * argument when `has_mode != 0`.  This matches glibc's own open wrapper
 * behavior and avoids UB from passing a `mode_t` through a varargs slot
 * that is typed as `int`.
 *
 * **Invariants maintained by this file:**
 * - The fd cache is populated only for non-excluded paths.
 * - A failed open never populates the fd cache (fd < 0 is rejected by
 *   `chaos_io_fdcache_store`).
 * - `chaos_io_resolve_at_path()` never calls any interposed symbol.
 *
 * **Module ownership:** wrappers/
 * **Stability:** internal
 */

/*
 * Path-first wrappers for libchaos-io.
 *
 * `open()` and `openat()` are grouped together because they share the same
 * varargs ABI handling, path-resolution semantics, and fd-cache seeding rules.
 */

#include "chaos_io_actions.h"
#include "chaos_io_config.h"
#include "chaos_io_fdcache.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief Calls the real `open()` with the exact ABI shape expected by libc.
 *
 * @details Enters internal mode, dispatches the two- or three-argument call,
 * and restores the prior guard state on return.
 *
 * The `has_mode` / `mode` split exists because `open()` is varargs.  The real
 * symbol must be called with either two or three arguments—passing a third
 * argument when `flags` does not imply it is undefined behavior under strict
 * C and can confuse some libc implementations that read the stack.
 *
 * @param[in] path      Pathname to forward to the real `open()`.
 * @param[in] flags     Open flags, forwarded unchanged.
 * @param[in] has_mode  Non-zero when `mode` carries a valid file creation mode.
 * @param[in] mode      File mode; meaningful only when `has_mode != 0`.
 * @return Return value from the real `open()`.
 */
static int chaos_io_call_real_open(const char *path, int flags, int has_mode, mode_t mode)
{
    int previous;
    int result;

    previous = chaos_io_enter_internal();
    if (has_mode != 0)
    {
        result = g_chaos_io_real_open(path, flags, mode);
    }
    else
    {
        result = g_chaos_io_real_open(path, flags);
    }
    chaos_io_leave_internal(previous);
    return result;
}

/**
 * @brief Returns non-zero when an open-style call must forward a trailing mode.
 *
 * @details `open()` and `openat()` share the same varargs contract. Keeping the flag
 * check in one helper avoids subtle divergence between the two wrappers.
 *
 * On Linux, `O_TMPFILE` is a compound flag (`O_TMPFILE == __O_TMPFILE | O_DIRECTORY`)
 * so the check must be `(flags & O_TMPFILE) == O_TMPFILE` rather than a
 * simple bitwise AND to avoid false positives from partial flag values.
 *
 * @param[in] flags  The `flags` argument from the caller's `open()` call.
 * @return Non-zero when a `mode_t` argument must be read from varargs.
 */
static int chaos_io_open_needs_mode(int flags)
{
#ifdef O_TMPFILE
    return ((flags & O_CREAT) != 0) || ((flags & O_TMPFILE) == O_TMPFILE);
#else
    return ((flags & O_CREAT) != 0);
#endif
}

/**
 * @brief Calls the real `openat()` with the ABI shape expected by libc.
 *
 * @details This mirrors `chaos_io_call_real_open()` exactly, but keeps the
 * directory-fd argument in place for relative-path callers.
 *
 * @param[in] dirfd     Directory fd or `AT_FDCWD`, forwarded unchanged.
 * @param[in] path      Pathname to forward to the real `openat()`.
 * @param[in] flags     Open flags, forwarded unchanged.
 * @param[in] has_mode  Non-zero when `mode` carries a valid file creation mode.
 * @param[in] mode      File mode; meaningful only when `has_mode != 0`.
 * @return Return value from the real `openat()`.
 */
static int
chaos_io_call_real_openat(int dirfd, const char *path, int flags, int has_mode, mode_t mode)
{
    int previous;
    int result;

    previous = chaos_io_enter_internal();
    if (has_mode != 0)
    {
        result = g_chaos_io_real_openat(dirfd, path, flags, mode);
    }
    else
    {
        result = g_chaos_io_real_openat(dirfd, path, flags);
    }
    chaos_io_leave_internal(previous);
    return result;
}

/**
 * @brief Copies one path string into caller storage if it fits.
 *
 * @details Open-style wrappers resolve a match path up front and then reuse it for rule
 * selection and fd-cache seeding. This helper keeps the bounds check uniform.
 *
 * @param[out] destination       Target buffer.  Must not be NULL.
 * @param[in]  destination_size  Byte capacity of `destination`.
 * @param[in]  path              Source path.  Must not be NULL.
 * @return Non-zero on success; zero when `path` would not fit.
 */
static int chaos_io_copy_path(char *destination, size_t destination_size, const char *path)
{
    size_t length;

    if (destination == NULL || destination_size == 0U || path == NULL)
    {
        return 0;
    }

    length = strlen(path);
    if (length + 1U > destination_size)
    {
        return 0;
    }

    (void)memcpy(destination, path, length + 1U);
    return 1;
}

/**
 * @brief Joins a resolved base directory and a relative child path.
 *
 * @details `openat()` needs a stable absolute-ish string for config matching.
 * The join is intentionally lexical; it does not normalize `.` or `..` segments.
 * Normalization would require dynamic allocation or a complex state machine, and
 * is unnecessary because the result is only used for prefix matching against
 * operator-specified rule prefixes—not for filesystem access.
 *
 * A separator `/` is inserted when `base` does not already end with one.
 *
 * @param[out] destination       Target buffer.  Must not be NULL.
 * @param[in]  destination_size  Byte capacity.
 * @param[in]  base              Resolved base directory path.  Must not be NULL or empty.
 * @param[in]  path              Relative child path.  Must not be NULL or empty.
 * @return Non-zero on success; zero when the result would not fit or inputs are empty.
 */
static int
chaos_io_join_paths(char *destination, size_t destination_size, const char *base, const char *path)
{
    size_t base_length;
    size_t path_length;
    size_t needs_separator;

    if (destination == NULL || destination_size == 0U || base == NULL || path == NULL)
    {
        return 0;
    }
    if (*base == '\0' || *path == '\0')
    {
        return 0;
    }

    base_length = strlen(base);
    path_length = strlen(path);
    needs_separator = (base[base_length - 1U] == '/') ? 0U : 1U;
    if (base_length + needs_separator + path_length + 1U > destination_size)
    {
        return 0;
    }

    (void)memcpy(destination, base, base_length);
    if (needs_separator != 0U)
    {
        destination[base_length] = '/';
        ++base_length;
    }
    (void)memcpy(destination + base_length, path, path_length + 1U);
    return 1;
}

/**
 * @brief Resolves the current working directory without leaving the preload layer.
 *
 * @details Relative `open()` and `openat(AT_FDCWD, ...)` calls need a
 * matchable path before any rule can fire.  The library does not interpose
 * `getcwd()`, but it still enters internal mode so any libc work it performs
 * stays out of scope and cannot trigger reentrancy.
 *
 * @param[out] path       Buffer to receive the cwd path.  Must not be NULL.
 * @param[in]  path_size  Byte capacity of `path`.
 * @return Non-zero on success; zero if `getcwd()` fails.
 */
static int chaos_io_getcwd_path(char *path, size_t path_size)
{
    int previous;
    int ok;
    int saved_errno;

    if (path == NULL || path_size == 0U)
    {
        return 0;
    }

    saved_errno = errno;
    previous = chaos_io_enter_internal();
    ok = getcwd(path, path_size) != NULL;
    chaos_io_leave_internal(previous);
    errno = saved_errno;
    return ok;
}

/**
 * @brief Resolves an open-style pathname into the string used for matching.
 *
 * @details Resolution rules:
 * - Absolute paths are used as-is (fast path; no cwd or dirfd needed).
 * - Relative paths under `AT_FDCWD` are joined with the current working
 *   directory obtained from `getcwd()` inside the internal guard.
 * - Other relative paths are joined with the directory-fd path resolved
 *   through the fd cache or `/proc/self/fd/<dirfd>`.
 *
 * If resolution fails, the caller must bypass pre-open path injection and rely
 * on post-open fd resolution only.  Failure is intentionally non-fatal: the
 * wrapper still calls the real open and seeds the cache from the resulting fd.
 *
 * @param[in]  dirfd              Directory fd or `AT_FDCWD`.
 * @param[in]  path               User-supplied path.  Must not be NULL.
 * @param[out] resolved_path      Buffer for the result.  Must not be NULL.
 * @param[in]  resolved_path_size Byte capacity of `resolved_path`.
 * @return Non-zero on success; zero on any resolution failure.
 */
int chaos_io_resolve_at_path(
    int dirfd, const char *path, char *resolved_path, size_t resolved_path_size
)
{
    char base_path[CHAOS_IO_MAX_PATH];

    if (path == NULL || resolved_path == NULL || resolved_path_size == 0U)
    {
        return 0;
    }
    if (path[0] == '/')
    {
        return chaos_io_copy_path(resolved_path, resolved_path_size, path);
    }
    if (dirfd == AT_FDCWD)
    {
        return chaos_io_getcwd_path(base_path, sizeof(base_path)) &&
               chaos_io_join_paths(resolved_path, resolved_path_size, base_path, path);
    }
    if (!chaos_io_fdcache_resolve(dirfd, base_path, sizeof(base_path)))
    {
        return 0;
    }
    return chaos_io_join_paths(resolved_path, resolved_path_size, base_path, path);
}

/**
 * @brief Seeds the fd cache after a successful open-style call.
 *
 * @details Two code paths reach this helper:
 * 1. The wrapper already resolved a stable path before the open call: store
 *    it directly if it is not excluded.
 * 2. The wrapper could not resolve the path up front (e.g. the dirfd was
 *    unknown): trigger a lazy resolution via `chaos_io_fdcache_resolve()` so
 *    the new fd is available for subsequent descriptor-based wrappers.
 *
 * The `path != NULL` branch uses the pre-resolved string rather than going
 * through `/proc/self/fd` again because the string is already validated and
 * in the correct form.
 *
 * @param[in] fd    The fd returned by the real open call.  Negative values
 *                  are ignored (failed open; nothing to cache).
 * @param[in] path  Pre-resolved path if available; NULL to trigger lazy
 *                  resolution from `/proc/self/fd/<fd>`.
 */
static void chaos_io_cache_open_result(int fd, const char *path)
{
    char resolved_path[CHAOS_IO_MAX_PATH];

    if (fd < 0)
    {
        return;
    }
    if (path != NULL)
    {
        if (!chaos_io_is_excluded_path(path))
        {
            chaos_io_fdcache_store(fd, path);
        }
        return;
    }

    (void)chaos_io_fdcache_resolve(fd, resolved_path, sizeof(resolved_path));
}

/* --- Exported interposed symbols ------------------------------------------------- */

/**
 * @brief Interposed `open(2)` entry point.
 *
 * @details The reentrancy fast path (guard is set) delegates immediately
 * to the real open without any config or cache interaction.  This is the
 * path taken when the library's own config reader calls `open()`.
 *
 * The mode argument is decoded from varargs before the guard check so that the
 * `va_list` is always properly consumed, preventing stack corruption if the
 * compiler passes the mode in a register that is read regardless of whether
 * the caller consults it.
 *
 * @param[in] path   User-supplied pathname.
 * @param[in] flags  Open flags; inspected for mode presence, then forwarded.
 * @param[in] ...    Optional `mode_t`, present when `O_CREAT` or `O_TMPFILE`
 *                   is set in `flags`.
 * @return A new file descriptor on success; -1 with `errno` set on failure.
 */
CHAOS_IO_EXPORT int open(const char *path, int flags, ...)
{
    chaos_io_rule_t rule;
    char resolved_path[CHAOS_IO_MAX_PATH];
    const char *match_path = NULL;
    mode_t mode = 0;
    int has_mode;
    int fd;

    chaos_io_ensure_symbols();
    has_mode = chaos_io_open_needs_mode(flags);

    if (has_mode != 0)
    {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (chaos_io_in_internal())
    {
        return chaos_io_call_real_open(path, flags, has_mode, mode);
    }

    if (chaos_io_resolve_at_path(AT_FDCWD, path, resolved_path, sizeof(resolved_path)))
    {
        match_path = resolved_path;
    }

    if (match_path != NULL && !chaos_io_is_excluded_path(match_path) &&
        chaos_io_config_match_path(CHAOS_IO_OP_OPEN, match_path, &rule))
    {
        if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
        {
            chaos_io_rule_apply_latency(&rule);
        }
        else if (chaos_io_rule_apply_errno(&rule))
        {
            return -1;
        }
    }

    fd = chaos_io_call_real_open(path, flags, has_mode, mode);
    chaos_io_cache_open_result(fd, match_path);
    return fd;
}

/**
 * @brief Applies the open rules to @p path before a stdio open; 1 when it must fail.
 *
 * @details LATENCY delays the open; ERRNO sets errno and asks the caller to fail
 * without opening. Under the guard, or for an excluded or unmatched path, nothing
 * happens.
 */
static int chaos_io_stdio_open_fault(const char *path, char *resolved_path, size_t resolved_size)
{
    chaos_io_rule_t rule;

    resolved_path[0] = '\0';
    if (path == NULL || chaos_io_in_internal() ||
        !chaos_io_resolve_at_path(AT_FDCWD, path, resolved_path, resolved_size))
    {
        resolved_path[0] = '\0';
        return 0;
    }
    if (chaos_io_is_excluded_path(resolved_path) ||
        !chaos_io_config_match_path(CHAOS_IO_OP_OPEN, resolved_path, &rule))
    {
        return 0;
    }
    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
        return 0;
    }
    return chaos_io_rule_apply_errno(&rule);
}

/**
 * @brief Records the descriptor of a stream fopen()/freopen() just opened.
 *
 * @details The C library opens the file with its own system call, so the open()
 * wrapper never cached the path. Without this, the stream's descriptor keeps
 * whatever path a closed descriptor of the same number had, and the stdio and
 * read/write rules would match that stale path -- even for a /proc stream.
 */
static void chaos_io_cache_stream(FILE *stream, const char *resolved_path)
{
    const int saved_errno = errno;
    const int fd = stream != NULL ? fileno(stream) : -1;

    if (fd >= 0)
    {
        if (resolved_path[0] != '\0' && !chaos_io_is_excluded_path(resolved_path))
        {
            chaos_io_fdcache_store(fd, resolved_path);
        }
        else
        {
            chaos_io_fdcache_invalidate(fd);
        }
    }
    errno = saved_errno;
}

/**
 * @brief Interposed `fopen(3)`: the open rules apply to the path.
 *
 * @details glibc and musl open the file with their own system call, so an open
 * rule never saw `fopen()` -- the most common way C programs (and shells, via
 * redirections in some builds) open files. On an injected error no stream is
 * created and NULL is returned with errno set.
 */
CHAOS_IO_EXPORT FILE *fopen(const char *path, const char *mode)
{
    char resolved_path[CHAOS_IO_MAX_PATH];
    FILE *stream;

    chaos_io_ensure_symbols();
    if (chaos_io_stdio_open_fault(path, resolved_path, sizeof(resolved_path)))
    {
        return NULL;
    }
    stream = g_chaos_io_real_fopen(path, mode);
    if (stream != NULL && !chaos_io_in_internal())
    {
        chaos_io_cache_stream(stream, resolved_path);
    }
    return stream;
}

/**
 * @brief Interposed `freopen(3)`: the open rules apply to the new path.
 *
 * @details Like a failed freopen(), an injected error closes @p stream and returns
 * NULL with errno set. A NULL path only changes the mode of the open stream and is
 * forwarded unchanged.
 */
CHAOS_IO_EXPORT FILE *freopen(const char *path, const char *mode, FILE *stream)
{
    char resolved_path[CHAOS_IO_MAX_PATH];
    FILE *reopened;

    chaos_io_ensure_symbols();
    if (chaos_io_stdio_open_fault(path, resolved_path, sizeof(resolved_path)))
    {
        const int injected = errno;

        (void)fclose(stream);
        errno = injected;
        return NULL;
    }
    reopened = g_chaos_io_real_freopen(path, mode, stream);
    /* A NULL path keeps the open file; anything else replaced the descriptor's file. */
    if (reopened != NULL && path != NULL && !chaos_io_in_internal())
    {
        chaos_io_cache_stream(reopened, resolved_path);
    }
    return reopened;
}

/**
 * @brief Interposed `creat(2)`: `open(path, O_CREAT | O_WRONLY | O_TRUNC, mode)`.
 *
 * @details glibc and musl implement creat() with their own system call, not
 * through open(), so without this wrapper `open` rules would never see it.
 */
CHAOS_IO_EXPORT int creat(const char *path, mode_t mode)
{
    return open(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

/**
 * @brief Interposed `openat(2)` entry point.
 *
 * @details `openat()` reuses the logical `open` rule class. The only extra
 * work here is resolving relative paths with `chaos_io_resolve_at_path()`
 * using the caller-supplied `dirfd`, which may be a real directory descriptor
 * or `AT_FDCWD`.
 *
 * The mode is decoded from varargs with the same promotion rules as `open()`.
 *
 * @param[in] dirfd  Directory fd or `AT_FDCWD` for relative-path base.
 * @param[in] path   User-supplied pathname (may be relative to `dirfd`).
 * @param[in] flags  Open flags; inspected for mode presence, then forwarded.
 * @param[in] ...    Optional `mode_t`, present when `O_CREAT` or `O_TMPFILE`
 *                   is set in `flags`.
 * @return A new file descriptor on success; -1 with `errno` set on failure.
 */
CHAOS_IO_EXPORT int openat(int dirfd, const char *path, int flags, ...)
{
    chaos_io_rule_t rule;
    char resolved_path[CHAOS_IO_MAX_PATH];
    const char *match_path = NULL;
    mode_t mode = 0;
    int has_mode;
    int fd;

    chaos_io_ensure_symbols();
    has_mode = chaos_io_open_needs_mode(flags);
    if (has_mode != 0)
    {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (chaos_io_in_internal())
    {
        return chaos_io_call_real_openat(dirfd, path, flags, has_mode, mode);
    }

    if (chaos_io_resolve_at_path(dirfd, path, resolved_path, sizeof(resolved_path)))
    {
        match_path = resolved_path;
    }

    if (match_path != NULL && !chaos_io_is_excluded_path(match_path) &&
        chaos_io_config_match_path(CHAOS_IO_OP_OPEN, match_path, &rule))
    {
        if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
        {
            chaos_io_rule_apply_latency(&rule);
        }
        else if (chaos_io_rule_apply_errno(&rule))
        {
            return -1;
        }
    }

    fd = chaos_io_call_real_openat(dirfd, path, flags, has_mode, mode);
    chaos_io_cache_open_result(fd, match_path);
    return fd;
}

/* ---------------------------------------------------------------------------
 * glibc alternate entry points
 *
 * On 64-bit glibc the large-file names (`open64`, `pread64`, ...) are separate
 * symbols with the same signature as the base functions, and binaries built with
 * large-file support or by the JDK bind to them. Without these aliases every such
 * call would bypass the library. The fortified `_chk`/`_2` variants are what
 * `_FORTIFY_SOURCE` builds (Debian and Ubuntu packages) call instead of the base
 * function; they check the buffer the way glibc does and then run the wrapper.
 * musl has neither, so all of this is glibc-only.
 * ------------------------------------------------------------------------- */
#if defined(__GLIBC__) && defined(__LP64__)

extern void __chk_fail(void) __attribute__((__noreturn__));

/** Overflow handler of the fortified variants; replaceable so tests can observe it. */
static void (*g_chaos_io_open_chk_fail)(void) = __chk_fail;

CHAOS_IO_EXPORT int open64(const char *path, int flags, ...) __attribute__((alias("open")));
CHAOS_IO_EXPORT int creat64(const char *path, mode_t mode) __attribute__((alias("creat")));
CHAOS_IO_EXPORT FILE *fopen64(const char *path, const char *mode) __attribute__((alias("fopen")));
CHAOS_IO_EXPORT FILE *freopen64(const char *path, const char *mode, FILE *stream)
    __attribute__((alias("freopen")));
CHAOS_IO_EXPORT int openat64(int dirfd, const char *path, int flags, ...)
    __attribute__((alias("openat")));

/**
 * @brief Fortified `open()` without a mode argument.
 *
 * @details glibc aborts when flags that need a mode arrive without one; so does
 * this wrapper, through `__chk_fail()`. Otherwise it is `open()`.
 */
CHAOS_IO_EXPORT int __open_2(const char *path, int flags)
{
    if (chaos_io_open_needs_mode(flags))
    {
        g_chaos_io_open_chk_fail();
        return -1;
    }
    return open(path, flags);
}

/**
 * @brief Fortified `openat()` without a mode argument; see `__open_2()`.
 */
CHAOS_IO_EXPORT int __openat_2(int dirfd, const char *path, int flags)
{
    if (chaos_io_open_needs_mode(flags))
    {
        g_chaos_io_open_chk_fail();
        return -1;
    }
    return openat(dirfd, path, flags);
}

CHAOS_IO_EXPORT int __open64_2(const char *path, int flags) __attribute__((alias("__open_2")));
CHAOS_IO_EXPORT int __openat64_2(int dirfd, const char *path, int flags)
    __attribute__((alias("__openat_2")));

#endif
