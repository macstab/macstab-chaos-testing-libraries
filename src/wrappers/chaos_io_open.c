/**
 * @file chaos_io_open.c
 * @brief `open` rules: open, openat, creat, fopen, freopen (and the glibc `64` and
 *        fortified `_2` variants); also defines chaos_io_resolve_at_path().
 *
 * @details
 * @par open/openat sequence
 * 1. Resolve the real functions; read the optional mode argument when the flags need one
 *    (O_CREAT, O_TMPFILE).
 * 2. Inside a library section (guard set): call the real function, nothing else.
 * 3. Build the match path (chaos_io_resolve_at_path()); when that fails, or the path is
 *    excluded, skip injection.
 * 4. LATENCY delays the call; ERRNO returns -1 with the rule's errno without opening.
 *    (TORN and CORRUPT cannot be combined with `open`.)
 * 5. Call the real function.
 * 6. On success, invalidate the new descriptor's slot and resolve it through
 *    `/proc/self/fd`, so later descriptor-based calls match by the kernel's name for the
 *    file (links resolved) and never by an entry a previous holder of the number left.
 *
 * @par Why stdio and creat need their own wrappers
 * glibc and musl implement fopen, freopen and creat with internal system calls, not
 * through the exported open(); without these wrappers `open` rules would never see them.
 *
 * @par Varargs
 * The mode is read with `va_arg(args, int)`: mode_t is promoted when passed through
 * `...`, and reading the promoted type is what glibc's own wrapper does. The real
 * function is then called with or without the third argument, matching what the caller
 * passed.
 *
 * @par Invariants
 * - A failed open never touches the fd cache.
 * - chaos_io_resolve_at_path() calls no interposed function outside a library section.
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
 * @brief Calls the real open() inside a library section, with a mode argument only when
 *        the caller supplied one.
 *
 * @details Before resolution (pointer NULL) the call is the openat system call on
 * AT_FDCWD: aarch64 has no open system call, and openat(AT_FDCWD) is equivalent.
 *
 * @param[in] path      Path, forwarded unchanged.
 * @param[in] flags     Flags, forwarded unchanged.
 * @param[in] has_mode  Non-zero when @p mode was passed by the caller.
 * @param[in] mode      Creation mode; ignored when @p has_mode is 0.
 * @return The real function's result; errno as it set it.
 */
static int chaos_io_call_real_open(const char *path, int flags, int has_mode, mode_t mode)
{
    int previous;
    int result;

    if (g_chaos_io_real_open == NULL)
    {
        /* Not resolved yet: open is openat on the working directory (aarch64 has no open
         * system call). The kernel reads the mode only when the flags need it, so 0 is a
         * safe filler. */
        return (int)CHAOS_IO_SYSCALL(
            SYS_openat, AT_FDCWD, path, flags, has_mode != 0 ? (unsigned int)mode : 0U
        );
    }
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
 * @brief Non-zero when @p flags require a mode argument: O_CREAT, or all bits of O_TMPFILE.
 *
 * @details O_TMPFILE is `__O_TMPFILE | O_DIRECTORY` on Linux, so a plain AND would treat
 * every O_DIRECTORY open as needing a mode and read a nonexistent vararg.
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
 * @brief chaos_io_call_real_open() for openat(): same mode handling, @p dirfd forwarded.
 *
 * @return The real function's result (raw openat system call before resolution).
 */
static int
chaos_io_call_real_openat(int dirfd, const char *path, int flags, int has_mode, mode_t mode)
{
    int previous;
    int result;

    if (g_chaos_io_real_openat == NULL)
    {
        return (int
        )CHAOS_IO_SYSCALL(SYS_openat, dirfd, path, flags, has_mode != 0 ? (unsigned int)mode : 0U);
    }
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
 * @brief getcwd() inside a library section, errno preserved.
 *
 * @details libchaos-io does not interpose getcwd; the guard keeps any libc I/O it might
 * do from being matched, and errno is restored because a failed getcwd (ENOENT for a
 * removed working directory, ERANGE) belongs to the library, not the caller.
 *
 * @param[out] path       Buffer; NULL returns 0.
 * @param[in]  path_size  Capacity in bytes; 0 returns 0.
 * @return Non-zero on success; 0 when getcwd() fails.
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

/** @copydoc chaos_io_resolve_at_path */
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
        if (!chaos_io_copy_path(resolved_path, resolved_path_size, path))
        {
            return 0;
        }
    }
    else if (dirfd == AT_FDCWD)
    {
        if (!chaos_io_getcwd_path(base_path, sizeof(base_path)) ||
            !chaos_io_join_paths(resolved_path, resolved_path_size, base_path, path))
        {
            return 0;
        }
    }
    else if (!chaos_io_fdcache_resolve(dirfd, base_path, sizeof(base_path)) ||
             !chaos_io_join_paths(resolved_path, resolved_path_size, base_path, path))
    {
        return 0;
    }
    chaos_io_normalize_path(resolved_path);
    return 1;
}

/**
 * @brief Caches the kernel's path for a descriptor an open-style call just returned.
 *
 * @details Always resolves through `/proc/self/fd`, never from the caller's path string:
 * the kernel's name has links resolved, which is what later lookups of this descriptor
 * see. The slot is invalidated first, because the number may have been freed by a call
 * libchaos-io does not see (a raw close system call, for one). Costs one readlink per
 * successful open.
 *
 * @param[in] fd  Result of the real call; negative is a no-op.
 */
static void chaos_io_cache_open_result(int fd)
{
    char resolved_path[CHAOS_IO_MAX_PATH];

    if (fd < 0)
    {
        return;
    }
    /* Never reuse an entry an earlier holder of this number left behind (closed where
     * libchaos-io did not see it); then cache the kernel's name, links resolved. */
    chaos_io_fdcache_invalidate(fd);
    (void)chaos_io_fdcache_resolve(fd, resolved_path, sizeof(resolved_path));
}

/* --- Exported interposed symbols ------------------------------------------------- */

/**
 * @brief Interposed open(2): `open` rules on the path; see the file header for the
 *        sequence.
 *
 * @details Inside a library section (the rule-file read, or libc I/O inside another real
 * call) the call goes straight to the real function. The mode is read before that check
 * because both paths forward it.
 *
 * @param[in] path   Path, relative to the working directory or absolute.
 * @param[in] flags  Flags, forwarded unchanged.
 * @param[in] ...    Mode (promoted mode_t), read only when O_CREAT or O_TMPFILE is set.
 * @return New descriptor; -1 with errno on a real or injected failure.
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
    chaos_io_cache_open_result(fd);
    return fd;
}

/**
 * @brief Applies `open` rules to @p path before fopen()/freopen(); 1 when the caller must
 *        fail without opening (errno set).
 *
 * @details LATENCY delays and returns 0. Inside a library section, or for a NULL,
 * unresolvable, excluded or unmatched path, nothing happens. @p resolved_path receives
 * the match path, or "" when none was built.
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
 * @brief Caches the descriptor of a stream fopen()/freopen() just opened.
 *
 * @details libc opened it with its own system call, so open() never saw it. Without this,
 * the descriptor would keep whatever path a closed descriptor of the same number had, and
 * stdio and read/write rules would match that stale path, even for a `/proc` stream.
 * errno is preserved.
 */
static void chaos_io_cache_stream(FILE *stream)
{
    const int saved_errno = errno;
    const int fd = stream != NULL ? fileno(stream) : -1;

    /* fileno() sets EBADF for streams without a descriptor (fmemopen, cookies). */
    errno = saved_errno;
    chaos_io_cache_open_result(fd);
}

/**
 * @brief Calls the real fopen(); NULL with ENOSYS before resolution, because no system
 *        call can create a libc stream.
 */
static FILE *chaos_io_call_real_fopen(const char *path, const char *mode)
{
    if (g_chaos_io_real_fopen == NULL)
    {
        errno = ENOSYS;
        return NULL;
    }
    return g_chaos_io_real_fopen(path, mode);
}

/** @brief Calls the real freopen(); NULL with ENOSYS before resolution. */
static FILE *chaos_io_call_real_freopen(const char *path, const char *mode, FILE *stream)
{
    if (g_chaos_io_real_freopen == NULL)
    {
        errno = ENOSYS;
        return NULL;
    }
    return g_chaos_io_real_freopen(path, mode, stream);
}

/**
 * @brief Interposed fopen(3): `open` rules on the path.
 *
 * @details fopen is the most common way C programs open files, and libc opens the file
 * with an internal system call, invisible to open(). An injected error creates no stream
 * and returns NULL with the rule's errno. A stream opened inside a library section is not
 * cached.
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
    stream = chaos_io_call_real_fopen(path, mode);
    if (stream != NULL && !chaos_io_in_internal())
    {
        chaos_io_cache_stream(stream);
    }
    return stream;
}

/**
 * @brief Interposed freopen(3): `open` rules on the new path.
 *
 * @details An injected error still calls the real freopen() with an empty path, which
 * always fails to open, so @p stream ends in exactly the state of a real failure: its old
 * file closed and, on glibc, the FILE still allocated, which matters to callers that
 * fclose() it anyway. The old descriptor's slot is invalidated and NULL is returned with
 * the rule's errno. A NULL path (mode change of the open file) is not matched and keeps
 * the cached path.
 */
CHAOS_IO_EXPORT FILE *freopen(const char *path, const char *mode, FILE *stream)
{
    char resolved_path[CHAOS_IO_MAX_PATH];
    FILE *reopened;

    chaos_io_ensure_symbols();
    if (chaos_io_stdio_open_fault(path, resolved_path, sizeof(resolved_path)))
    {
        const int injected = errno;
        const int fd = fileno(stream);

        (void)chaos_io_call_real_freopen("", mode, stream);
        chaos_io_fdcache_invalidate(fd);
        errno = injected;
        return NULL;
    }
    reopened = chaos_io_call_real_freopen(path, mode, stream);
    /* A NULL path keeps the open file; anything else replaced the descriptor's file. */
    if (reopened != NULL && path != NULL && !chaos_io_in_internal())
    {
        chaos_io_cache_stream(reopened);
    }
    return reopened;
}

/**
 * @brief Interposed creat(2): exactly `open(path, O_CREAT | O_WRONLY | O_TRUNC, mode)`.
 *
 * @details libc implements creat() with its own system call, not through open(), so
 * without this wrapper `open` rules would never see it.
 */
CHAOS_IO_EXPORT int creat(const char *path, mode_t mode)
{
    return open(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

/**
 * @brief Interposed openat(2): `open` rules on the path @p dirfd and @p path name.
 *
 * @details Identical to open() except that a relative path is resolved against @p dirfd
 * (a directory descriptor or AT_FDCWD).
 *
 * @param[in] dirfd  Directory descriptor or AT_FDCWD.
 * @param[in] path   Path, relative to @p dirfd or absolute.
 * @param[in] flags  Flags, forwarded unchanged.
 * @param[in] ...    Mode, read only when O_CREAT or O_TMPFILE is set.
 * @return New descriptor; -1 with errno on a real or injected failure.
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
    chaos_io_cache_open_result(fd);
    return fd;
}

/* ---------------------------------------------------------------------------
 * glibc alternate entry points
 *
 * On 64-bit glibc the large-file names (`open64`, `fopen64`, ...) are separate symbols
 * with the same signature as the base functions, and binaries built with large-file
 * support, or the JDK, bind to them; without these aliases such calls would bypass the
 * library. The fortified `_2` variants are what `_FORTIFY_SOURCE` builds (Debian and
 * Ubuntu packages) call instead of open/openat; they apply glibc's check and then run the
 * wrapper. musl has neither, so all of this is glibc-only, and only on LP64, where off_t
 * is already 64 bits and the signatures are identical.
 * ------------------------------------------------------------------------- */
#if defined(__GLIBC__) && defined(__LP64__)

extern void __chk_fail(void) __attribute__((__noreturn__));

/** @brief Failure handler of the fortified variants (glibc's __chk_fail, which aborts);
 *         a test seam. */
static void (*g_chaos_io_open_chk_fail)(void) = __chk_fail;

CHAOS_IO_EXPORT int open64(const char *path, int flags, ...) __attribute__((alias("open")));
CHAOS_IO_EXPORT int creat64(const char *path, mode_t mode) __attribute__((alias("creat")));
CHAOS_IO_EXPORT FILE *fopen64(const char *path, const char *mode) __attribute__((alias("fopen")));
CHAOS_IO_EXPORT FILE *freopen64(const char *path, const char *mode, FILE *stream)
    __attribute__((alias("freopen")));
CHAOS_IO_EXPORT int openat64(int dirfd, const char *path, int flags, ...)
    __attribute__((alias("openat")));

/**
 * @brief Fortified open() without a mode: aborts through __chk_fail() when @p flags need a
 *        mode (as glibc does), otherwise open().
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

/** @brief Fortified openat() without a mode; see __open_2(). */
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
