/**
 * @file chaos_io_stdio.c
 * @brief stdio wrappers: `read` and `write` rules applied to a FILE stream's descriptor.
 *
 * @details
 * glibc and musl read and write a FILE with internal system calls, never through the
 * exported read/write, so without these wrappers `read` and `write` rules would miss
 * fread, fgets, fwrite, fprintf and every other buffered call: how most C programs read
 * configuration and write logs and data files.
 *
 * - `read`: fread, fgets, fgetc, getc, getline, getdelim, __getdelim (what optimised
 *   glibc builds call for getline), __fread_chk, __fgets_chk.
 * - `write`: fwrite, fputs, fputc, putc, fprintf, vfprintf, fflush, __fprintf_chk,
 *   __vfprintf_chk.
 *
 * Descriptors 0-2 are never faulted, so printf, puts, putchar and getchar, which only use
 * the standard streams, are not wrapped. Streams without a descriptor (fmemopen,
 * fopencookie) are never matched. fclose is wrapped only to invalidate the cache.
 *
 * @par Effects
 * - LATENCY delays the call.
 * - ERRNO fails it the way stdio reports an I/O error (0 items, NULL, EOF or -1) with
 *   errno set and the stream's error indicator raised, so ferror() is true as after a
 *   real failure.
 * - CORRUPT flips one bit of the bytes a read returned.
 * - TORN is ignored (no hit counted): a short fwrite means an error in stdio, not a
 *   partial success.
 *
 * @par Error indicator
 * There is no API to set it. glibc (`_IO_ERR_SEEN`) and musl (`F_ERR`) both keep it as bit
 * 0x20 of the first int of FILE; the wrapper sets that bit under the stream lock.
 * `test/runtime/test_stdio.sh` checks ferror() on both.
 *
 * @par Granularity and gaps
 * A rule fires once per stdio call, not per system call: the reads and writes libc makes
 * while filling or flushing a buffer are internal system calls no wrapper sees.
 * Not covered: the scanf family (glibc redirects it to `__isoc99_*` and `__isoc23_*`
 * names) and the `*_unlocked` variants.
 *
 * @par Size gates
 * fread/fwrite: size * count; fgets: the buffer size; fgetc/fputc: 1; fputs: strlen;
 * getdelim, fflush and the printf family: unknown (CHAOS_POLICY_NO_SIZE), so a
 * size-gated rule never fires for them.
 */

#include "chaos_io_actions.h"
#include "chaos_io_fdcache.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/** @brief Error-indicator bit in the first int of FILE (glibc _IO_ERR_SEEN, musl F_ERR). */
#define CHAOS_IO_STDIO_ERROR_FLAG 0x20

/**
 * @brief Raises @p stream's error indicator, as a failed real call would (Linux only;
 *        elsewhere the layout is unknown and nothing is set).
 */
static void chaos_io_stdio_mark_error(FILE *stream)
{
#ifdef __linux__
    /* Under the stream lock: libc updates the same word under it, and an unlocked
     * read-modify-write could lose a concurrent flag change. */
    flockfile(stream);
    *(volatile int *)(void *)stream |= CHAOS_IO_STDIO_ERROR_FLAG;
    funlockfile(stream);
#else
    (void)stream;
#endif
}

/** @brief Bytes of @p count items of @p size bytes for `@size` gates; CHAOS_POLICY_NO_SIZE
 *         on overflow. */
static uint64_t chaos_io_stdio_size(size_t size, size_t count)
{
    if (size != 0U && count > UINT64_MAX / size)
    {
        return CHAOS_POLICY_NO_SIZE;
    }
    return (uint64_t)size * (uint64_t)count;
}

/**
 * @brief Finds the rule for @p operation on @p stream's descriptor; errno preserved.
 *
 * @details Returns 0 for a NULL stream, inside a library section (libc I/O made from
 * inside another real call), and for streams without a descriptor.
 *
 * @return Non-zero when a rule matched (written to @p rule, with `call_size = size`).
 */
static int chaos_io_stdio_rule(
    FILE *stream, chaos_io_operation_t operation, uint64_t size, chaos_io_rule_t *rule
)
{
    const int saved_errno = errno;
    int matched;
    int fd;

    if (stream == NULL || chaos_io_in_internal())
    {
        return 0;
    }
    /* fileno() sets EBADF for streams without a descriptor (fmemopen, cookies). */
    fd = fileno(stream);
    matched = fd >= 0 && chaos_io_match_fd_rule_sized(fd, operation, size, rule);
    errno = saved_errno;
    return matched;
}

/**
 * @brief Applies the pre-call effects: LATENCY delays (returns 0); a firing ERRNO sets
 *        errno, raises the error indicator and returns 1, so the caller fails without
 *        calling libc. TORN and CORRUPT return 0 here.
 */
static int chaos_io_stdio_fails(FILE *stream, const chaos_io_rule_t *rule)
{
    if (rule->effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(rule);
        return 0;
    }
    if (rule->effect == CHAOS_IO_EFFECT_ERRNO && chaos_io_rule_apply_errno(rule))
    {
        chaos_io_stdio_mark_error(stream);
        return 1;
    }
    return 0;
}

/** @brief CORRUPT after a stdio read: flips one bit among the @p bytes returned, when the
 *         rule fires; nothing for 0 bytes. */
static void chaos_io_stdio_corrupt(const chaos_io_rule_t *rule, void *buffer, size_t bytes)
{
    if (bytes > 0U && rule->effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(rule))
    {
        chaos_io_corrupt_buffer(buffer, bytes);
    }
}

/* --- Real-call trampolines ------------------------------------------------------- */

/*
 * A stream is libc's own object, so no system call can stand in for these. While a
 * `g_chaos_io_real_*` pointer is still NULL (a call during symbol resolution) the call
 * fails the way the function reports errors, with ENOSYS. They do not enter a library
 * section: libc's buffer I/O inside them uses internal system calls no wrapper sees.
 */

static size_t chaos_io_call_real_fread(void *buffer, size_t size, size_t count, FILE *stream)
{
    if (g_chaos_io_real_fread == NULL)
    {
        errno = ENOSYS;
        return 0U;
    }
    return g_chaos_io_real_fread(buffer, size, count, stream);
}

/** @brief The real `__fread_chk` where libc has it (glibc), else the real fread. */
static size_t chaos_io_call_real_fread_chk(
    void *buffer, size_t buffer_size, size_t size, size_t count, FILE *stream
)
{
    if (g_chaos_io_real_fread_chk != NULL)
    {
        return g_chaos_io_real_fread_chk(buffer, buffer_size, size, count, stream);
    }
    return chaos_io_call_real_fread(buffer, size, count, stream);
}

static char *chaos_io_call_real_fgets(char *buffer, int size, FILE *stream)
{
    if (g_chaos_io_real_fgets == NULL)
    {
        errno = ENOSYS;
        return NULL;
    }
    return g_chaos_io_real_fgets(buffer, size, stream);
}

/** @brief The real `__fgets_chk` where libc has it (glibc), else the real fgets. */
static char *chaos_io_call_real_fgets_chk(char *buffer, size_t buffer_size, int size, FILE *stream)
{
    if (g_chaos_io_real_fgets_chk != NULL)
    {
        return g_chaos_io_real_fgets_chk(buffer, buffer_size, size, stream);
    }
    return chaos_io_call_real_fgets(buffer, size, stream);
}

/** @brief Calls @p real (the real fgetc or getc); EOF with ENOSYS when NULL. */
static int chaos_io_call_real_getc(chaos_io_fgetc_fn real, FILE *stream)
{
    if (real == NULL)
    {
        errno = ENOSYS;
        return EOF;
    }
    return real(stream);
}

static ssize_t
chaos_io_call_real_getdelim(char **line, size_t *capacity, int delimiter, FILE *stream)
{
    if (g_chaos_io_real_getdelim == NULL)
    {
        errno = ENOSYS;
        return -1;
    }
    return g_chaos_io_real_getdelim(line, capacity, delimiter, stream);
}

static size_t chaos_io_call_real_fwrite(const void *buffer, size_t size, size_t count, FILE *stream)
{
    if (g_chaos_io_real_fwrite == NULL)
    {
        errno = ENOSYS;
        return 0U;
    }
    return g_chaos_io_real_fwrite(buffer, size, count, stream);
}

static int chaos_io_call_real_fputs(const char *text, FILE *stream)
{
    if (g_chaos_io_real_fputs == NULL)
    {
        errno = ENOSYS;
        return EOF;
    }
    return g_chaos_io_real_fputs(text, stream);
}

/** @brief Calls @p real (the real fputc or putc); EOF with ENOSYS when NULL. */
static int chaos_io_call_real_putc(chaos_io_fputc_fn real, int c, FILE *stream)
{
    if (real == NULL)
    {
        errno = ENOSYS;
        return EOF;
    }
    return real(c, stream);
}

static int chaos_io_call_real_fflush(FILE *stream)
{
    if (g_chaos_io_real_fflush == NULL)
    {
        errno = ENOSYS;
        return EOF;
    }
    return g_chaos_io_real_fflush(stream);
}

/**
 * @brief The real formatter: `__vfprintf_chk` for a fortified call (@p flag >= 0) where
 *        libc has it, so `%n` checks stay in force; else vfprintf.
 */
static int
chaos_io_call_real_vfprintf(FILE *stream, int flag, const char *format, va_list arguments)
{
    if (flag >= 0 && g_chaos_io_real_vfprintf_chk != NULL)
    {
        return g_chaos_io_real_vfprintf_chk(stream, flag, format, arguments);
    }
    if (g_chaos_io_real_vfprintf == NULL)
    {
        errno = ENOSYS;
        return -1;
    }
    return g_chaos_io_real_vfprintf(stream, format, arguments);
}

static int chaos_io_call_real_fclose(FILE *stream)
{
    if (g_chaos_io_real_fclose == NULL)
    {
        errno = ENOSYS;
        return EOF;
    }
    return g_chaos_io_real_fclose(stream);
}

/* --- Reads ------------------------------------------------------------------------ */

/**
 * @brief Interposed fread(3): `read` rules; ERRNO returns 0 items with the error indicator
 *        set; CORRUPT flips a bit among the items returned.
 */
CHAOS_IO_EXPORT size_t fread(void *buffer, size_t size, size_t count, FILE *stream)
{
    chaos_io_rule_t rule;
    size_t items;

    chaos_io_ensure_symbols();
    if (!chaos_io_stdio_rule(stream, CHAOS_IO_OP_READ, chaos_io_stdio_size(size, count), &rule))
    {
        return chaos_io_call_real_fread(buffer, size, count, stream);
    }
    if (chaos_io_stdio_fails(stream, &rule))
    {
        return 0U;
    }
    items = chaos_io_call_real_fread(buffer, size, count, stream);
    chaos_io_stdio_corrupt(&rule, buffer, items * size);
    return items;
}

/**
 * @brief Interposed fgets(3): `read` rules; ERRNO returns NULL with the error indicator set;
 *        CORRUPT flips a bit of the returned line (up to its NUL; may hit the newline).
 */
CHAOS_IO_EXPORT char *fgets(char *buffer, int size, FILE *stream)
{
    chaos_io_rule_t rule;
    char *line;

    chaos_io_ensure_symbols();
    if (!chaos_io_stdio_rule(
            stream, CHAOS_IO_OP_READ, size > 0 ? (uint64_t)size : CHAOS_POLICY_NO_SIZE, &rule
        ))
    {
        return chaos_io_call_real_fgets(buffer, size, stream);
    }
    if (chaos_io_stdio_fails(stream, &rule))
    {
        return NULL;
    }
    line = chaos_io_call_real_fgets(buffer, size, stream);
    if (line != NULL)
    {
        chaos_io_stdio_corrupt(&rule, line, strlen(line));
    }
    return line;
}

/** @brief Shared body of fgetc and getc: `read` rules with size 1; CORRUPT flips a bit of
 *         the returned byte. */
static int chaos_io_stdio_getc(FILE *stream, chaos_io_fgetc_fn real)
{
    chaos_io_rule_t rule;
    unsigned char byte;
    int c;

    chaos_io_ensure_symbols();
    if (!chaos_io_stdio_rule(stream, CHAOS_IO_OP_READ, 1U, &rule))
    {
        return chaos_io_call_real_getc(real, stream);
    }
    if (chaos_io_stdio_fails(stream, &rule))
    {
        return EOF;
    }
    c = chaos_io_call_real_getc(real, stream);
    if (c == EOF)
    {
        return c;
    }
    byte = (unsigned char)c;
    chaos_io_stdio_corrupt(&rule, &byte, 1U);
    return (int)byte;
}

/** @brief Interposed fgetc(3): see chaos_io_stdio_getc(); ERRNO returns EOF. */
CHAOS_IO_EXPORT int fgetc(FILE *stream)
{
    chaos_io_ensure_symbols();
    return chaos_io_stdio_getc(stream, g_chaos_io_real_fgetc);
}

/** @brief Interposed getc(3) (when not a macro): as fgetc(). */
CHAOS_IO_EXPORT int getc(FILE *stream)
{
    chaos_io_ensure_symbols();
    return chaos_io_stdio_getc(stream, g_chaos_io_real_getc);
}

/**
 * @brief Interposed getdelim(3): `read` rules (size unknown); ERRNO returns -1 with the error
 *        indicator set; CORRUPT flips a bit of the returned bytes.
 */
CHAOS_IO_EXPORT ssize_t getdelim(char **line, size_t *capacity, int delimiter, FILE *stream)
{
    chaos_io_rule_t rule;
    ssize_t length;

    chaos_io_ensure_symbols();
    if (!chaos_io_stdio_rule(stream, CHAOS_IO_OP_READ, CHAOS_POLICY_NO_SIZE, &rule))
    {
        return chaos_io_call_real_getdelim(line, capacity, delimiter, stream);
    }
    if (chaos_io_stdio_fails(stream, &rule))
    {
        return -1;
    }
    length = chaos_io_call_real_getdelim(line, capacity, delimiter, stream);
    if (length > 0 && line != NULL)
    {
        chaos_io_stdio_corrupt(&rule, *line, (size_t)length);
    }
    return length;
}

/** @brief Interposed getline(3): getdelim() with '\n'. */
CHAOS_IO_EXPORT ssize_t getline(char **line, size_t *capacity, FILE *stream)
{
    return getdelim(line, capacity, '\n', stream);
}

/* glibc's headers turn getline() into an inline call to __getdelim() when optimising, so
 * the alias is what optimised binaries actually bind to. */
ssize_t __getdelim(char **line, size_t *capacity, int delimiter, FILE *stream);
CHAOS_IO_EXPORT ssize_t __getdelim(char **line, size_t *capacity, int delimiter, FILE *stream)
    __attribute__((alias("getdelim")));

/* --- Writes ----------------------------------------------------------------------- */

/** @brief Interposed fwrite(3): `write` rules; ERRNO returns 0 items without writing. */
CHAOS_IO_EXPORT size_t fwrite(const void *buffer, size_t size, size_t count, FILE *stream)
{
    chaos_io_rule_t rule;

    chaos_io_ensure_symbols();
    if (chaos_io_stdio_rule(stream, CHAOS_IO_OP_WRITE, chaos_io_stdio_size(size, count), &rule) &&
        chaos_io_stdio_fails(stream, &rule))
    {
        return 0U;
    }
    return chaos_io_call_real_fwrite(buffer, size, count, stream);
}

/** @brief Interposed fputs(3): `write` rules; ERRNO returns EOF without writing. */
CHAOS_IO_EXPORT int fputs(const char *text, FILE *stream)
{
    chaos_io_rule_t rule;

    chaos_io_ensure_symbols();
    if (chaos_io_stdio_rule(stream, CHAOS_IO_OP_WRITE, (uint64_t)strlen(text), &rule) &&
        chaos_io_stdio_fails(stream, &rule))
    {
        return EOF;
    }
    return chaos_io_call_real_fputs(text, stream);
}

/** @brief Shared body of fputc and putc: `write` rules with size 1. */
static int chaos_io_stdio_putc(int c, FILE *stream, chaos_io_fputc_fn real)
{
    chaos_io_rule_t rule;

    if (chaos_io_stdio_rule(stream, CHAOS_IO_OP_WRITE, 1U, &rule) &&
        chaos_io_stdio_fails(stream, &rule))
    {
        return EOF;
    }
    return chaos_io_call_real_putc(real, c, stream);
}

/** @brief Interposed fputc(3): `write` rules with size 1; ERRNO returns EOF. */
CHAOS_IO_EXPORT int fputc(int c, FILE *stream)
{
    chaos_io_ensure_symbols();
    return chaos_io_stdio_putc(c, stream, g_chaos_io_real_fputc);
}

/** @brief Interposed putc(3) (when not a macro): as fputc(). */
CHAOS_IO_EXPORT int putc(int c, FILE *stream)
{
    chaos_io_ensure_symbols();
    return chaos_io_stdio_putc(c, stream, g_chaos_io_real_putc);
}

/**
 * @brief Interposed fflush(3): `write` rules (size unknown); ERRNO returns EOF without
 *        flushing. fflush(NULL) has no descriptor and is never matched.
 */
CHAOS_IO_EXPORT int fflush(FILE *stream)
{
    chaos_io_rule_t rule;

    chaos_io_ensure_symbols();
    if (chaos_io_stdio_rule(stream, CHAOS_IO_OP_WRITE, CHAOS_POLICY_NO_SIZE, &rule) &&
        chaos_io_stdio_fails(stream, &rule))
    {
        return EOF;
    }
    return chaos_io_call_real_fflush(stream);
}

/**
 * @brief Shared body of the printf family: `write` rules (size unknown), then the real
 *        formatter. An injected failure returns -1 without formatting.
 *
 * @param flag  Fortification level of the `__*_chk` forms; -1 for the plain forms.
 */
static int chaos_io_stdio_vprintf(FILE *stream, int flag, const char *format, va_list arguments)
{
    chaos_io_rule_t rule;

    chaos_io_ensure_symbols();
    if (chaos_io_stdio_rule(stream, CHAOS_IO_OP_WRITE, CHAOS_POLICY_NO_SIZE, &rule) &&
        chaos_io_stdio_fails(stream, &rule))
    {
        return -1;
    }
    return chaos_io_call_real_vfprintf(stream, flag, format, arguments);
}

/** @brief Interposed vfprintf(3): `write` rules; ERRNO returns -1 without formatting. */
CHAOS_IO_EXPORT int vfprintf(FILE *stream, const char *format, va_list arguments)
{
    return chaos_io_stdio_vprintf(stream, -1, format, arguments);
}

/** @brief Interposed fprintf(3): as vfprintf(). */
CHAOS_IO_EXPORT int fprintf(FILE *stream, const char *format, ...)
{
    va_list arguments;
    int rc;

    va_start(arguments, format);
    rc = chaos_io_stdio_vprintf(stream, -1, format, arguments);
    va_end(arguments);
    return rc;
}

/**
 * @brief Interposed fclose(3): no rules; invalidates the stream's descriptor after the
 *        close.
 *
 * @details libc closes the descriptor with its own system call, which close() never sees,
 * and the next file opened under the same number would otherwise inherit this stream's
 * path. Invalidated after the close, as close() does: before it, a lookup on another
 * thread could still re-cache the open file's path for the number. Inside a library
 * section (libc closing a stream it opened internally) the cache is left alone.
 * @p stream must not be NULL (fileno() is called on it).
 */
CHAOS_IO_EXPORT int fclose(FILE *stream)
{
    const int saved_errno = errno;
    const int fd = fileno(stream);
    int rc;

    chaos_io_ensure_symbols();
    errno = saved_errno;
    rc = chaos_io_call_real_fclose(stream);
    if (!chaos_io_in_internal())
    {
        chaos_io_fdcache_invalidate(fd);
    }
    return rc;
}

/* --- Fortified entry points (_FORTIFY_SOURCE builds) ------------------------------ */
/* Prototypes of the fortified entry points, which the libc headers declare only in some
 * configurations. */

int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list arguments);
int __fprintf_chk(FILE *stream, int flag, const char *format, ...);
size_t __fread_chk(void *buffer, size_t buffer_size, size_t size, size_t count, FILE *stream);
char *__fgets_chk(char *buffer, size_t buffer_size, int size, FILE *stream);

/** @brief Fortified vfprintf(): the rules, then the real `__vfprintf_chk`. */
CHAOS_IO_EXPORT int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list arguments)
{
    return chaos_io_stdio_vprintf(stream, flag, format, arguments);
}

/** @brief Fortified fprintf(): the rules, then the real `__vfprintf_chk`. */
CHAOS_IO_EXPORT int __fprintf_chk(FILE *stream, int flag, const char *format, ...)
{
    va_list arguments;
    int rc;

    va_start(arguments, format);
    rc = chaos_io_stdio_vprintf(stream, flag, format, arguments);
    va_end(arguments);
    return rc;
}

/** @brief Fortified fread(): fread() semantics, the real `__fread_chk` does the check. */
CHAOS_IO_EXPORT size_t
__fread_chk(void *buffer, size_t buffer_size, size_t size, size_t count, FILE *stream)
{
    chaos_io_rule_t rule;
    size_t items;

    chaos_io_ensure_symbols();
    if (!chaos_io_stdio_rule(stream, CHAOS_IO_OP_READ, chaos_io_stdio_size(size, count), &rule))
    {
        return chaos_io_call_real_fread_chk(buffer, buffer_size, size, count, stream);
    }
    if (chaos_io_stdio_fails(stream, &rule))
    {
        return 0U;
    }
    items = chaos_io_call_real_fread_chk(buffer, buffer_size, size, count, stream);
    chaos_io_stdio_corrupt(&rule, buffer, items * size);
    return items;
}

/** @brief Fortified fgets(): fgets() semantics, the real `__fgets_chk` does the check. */
CHAOS_IO_EXPORT char *__fgets_chk(char *buffer, size_t buffer_size, int size, FILE *stream)
{
    chaos_io_rule_t rule;
    char *line;

    chaos_io_ensure_symbols();
    if (!chaos_io_stdio_rule(
            stream, CHAOS_IO_OP_READ, size > 0 ? (uint64_t)size : CHAOS_POLICY_NO_SIZE, &rule
        ))
    {
        return chaos_io_call_real_fgets_chk(buffer, buffer_size, size, stream);
    }
    if (chaos_io_stdio_fails(stream, &rule))
    {
        return NULL;
    }
    line = chaos_io_call_real_fgets_chk(buffer, buffer_size, size, stream);
    if (line != NULL)
    {
        chaos_io_stdio_corrupt(&rule, line, strlen(line));
    }
    return line;
}
