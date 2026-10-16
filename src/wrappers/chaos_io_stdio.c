/**
 * @file chaos_io_stdio.c
 * @brief stdio read and write wrappers for libchaos-io.
 *
 * @details
 * glibc and musl read and write a `FILE` stream with their own internal system
 * calls, never through the `read`/`write` symbols, so a `read` or `write` rule
 * did not see `fread`, `fgets`, `fwrite`, `fprintf` or any other buffered I/O --
 * how most C programs read configuration and write logs and data files. These
 * wrappers apply the same rules to the stream's descriptor:
 *
 * - read: `fread`, `fgets`, `fgetc`, `getc`, `getline`, `getdelim` (and
 *   `__getdelim`, which optimized glibc builds call for getline) and the
 *   fortified `__fread_chk`, `__fgets_chk`;
 * - write: `fwrite`, `fputs`, `fputc`, `putc`, `fprintf`, `vfprintf`, `fflush`
 *   and the fortified `__fprintf_chk`, `__vfprintf_chk`.
 *
 * Like every libchaos-io wrapper they leave descriptors 0-2 alone, so the
 * standard streams are never faulted; `printf`, `puts`, `putchar` and `getchar`,
 * which only use them, are therefore not wrapped.
 *
 * **Effects.** `LATENCY` delays the call. `ERRNO` fails it the way the C library
 * reports an I/O error -- 0 items, NULL, EOF or a negative count -- with errno set
 * and the stream's error indicator raised, so `ferror()` is true as after a real
 * failure. `CORRUPT` changes the bytes a read returned. `TORN` does not apply: a
 * short `fwrite` means an error in stdio, not a partial success.
 *
 * **Error indicator.** There is no API to set it. glibc (`_IO_ERR_SEEN`) and musl
 * (`F_ERR`) both keep it as bit 0x20 of the first word of `FILE`; the wrapper sets
 * that bit. `test/runtime/test_stdio.sh` checks `ferror()` on both.
 *
 * **Not covered.** The scanf family (glibc redirects it to `__isoc99_*` and
 * `__isoc23_*` names) and the `*_unlocked` variants. Reads and writes the C library
 * performs while filling or flushing a buffer happen inside one of these calls, so
 * a rule fires once per call, not once per system call.
 *
 * **Module ownership:** wrappers/
 * **Stability:** internal
 */

#include "chaos_io_actions.h"
#include "chaos_io_fdcache.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/** @brief Bit of the first word of FILE that glibc and musl use for the error indicator. */
#define CHAOS_IO_STDIO_ERROR_FLAG 0x20

/**
 * @brief Raises @p stream's error indicator, as a failed real call would.
 */
static void chaos_io_stdio_mark_error(FILE *stream)
{
#ifdef __linux__
    /* Under the stream lock: the C library updates the same word under it. */
    flockfile(stream);
    *(volatile int *)(void *)stream |= CHAOS_IO_STDIO_ERROR_FLAG;
    funlockfile(stream);
#else
    (void)stream;
#endif
}

/** @brief Byte count of @p count items of @p size bytes; CHAOS_POLICY_NO_SIZE on overflow. */
static uint64_t chaos_io_stdio_size(size_t size, size_t count)
{
    if (size != 0U && count > UINT64_MAX / size)
    {
        return CHAOS_POLICY_NO_SIZE;
    }
    return (uint64_t)size * (uint64_t)count;
}

/**
 * @brief Finds the rule for an operation on @p stream's descriptor.
 *
 * @return Non-zero when a rule matched (written to @p rule).
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
 * @brief Applies the pre-call effects; 1 when the call must fail without running.
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

/** @brief Corrupts @p bytes bytes a read returned when a CORRUPT rule fires. */
static void chaos_io_stdio_corrupt(const chaos_io_rule_t *rule, void *buffer, size_t bytes)
{
    if (bytes > 0U && rule->effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(rule))
    {
        chaos_io_corrupt_buffer(buffer, bytes);
    }
}

/* --- Real-call trampolines ------------------------------------------------------- */

/*
 * A stream is the C library's own object, so no system call can stand in for these.
 * While a `g_chaos_io_real_*` pointer is still NULL (a call that arrives during
 * symbol resolution) the call fails the way the function reports errors, with ENOSYS.
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

/** @brief `__fread_chk` where the C library has it, else the plain fread. */
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

/** @brief `__fgets_chk` where the C library has it, else the plain fgets. */
static char *chaos_io_call_real_fgets_chk(char *buffer, size_t buffer_size, int size, FILE *stream)
{
    if (g_chaos_io_real_fgets_chk != NULL)
    {
        return g_chaos_io_real_fgets_chk(buffer, buffer_size, size, stream);
    }
    return chaos_io_call_real_fgets(buffer, size, stream);
}

/** @brief Calls @p real, the resolved fgetc or getc. */
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

/** @brief Calls @p real, the resolved fputc or putc. */
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
 * @brief The real formatter: `__vfprintf_chk` for a fortified call (@p flag >= 0)
 *        where the C library has it, else vfprintf.
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

/** @brief Shared body of fgetc, getc and getchar. */
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

CHAOS_IO_EXPORT int fgetc(FILE *stream)
{
    chaos_io_ensure_symbols();
    return chaos_io_stdio_getc(stream, g_chaos_io_real_fgetc);
}

CHAOS_IO_EXPORT int getc(FILE *stream)
{
    chaos_io_ensure_symbols();
    return chaos_io_stdio_getc(stream, g_chaos_io_real_getc);
}

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

CHAOS_IO_EXPORT ssize_t getline(char **line, size_t *capacity, FILE *stream)
{
    return getdelim(line, capacity, '\n', stream);
}

/* glibc's headers turn getline() into an inline call to __getdelim() when optimizing. */
ssize_t __getdelim(char **line, size_t *capacity, int delimiter, FILE *stream);
CHAOS_IO_EXPORT ssize_t __getdelim(char **line, size_t *capacity, int delimiter, FILE *stream)
    __attribute__((alias("getdelim")));

/* --- Writes ----------------------------------------------------------------------- */

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

/** @brief Shared body of fputc, putc and putchar. */
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

CHAOS_IO_EXPORT int fputc(int c, FILE *stream)
{
    chaos_io_ensure_symbols();
    return chaos_io_stdio_putc(c, stream, g_chaos_io_real_fputc);
}

CHAOS_IO_EXPORT int putc(int c, FILE *stream)
{
    chaos_io_ensure_symbols();
    return chaos_io_stdio_putc(c, stream, g_chaos_io_real_putc);
}

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
 * @brief Shared body of the printf family: the rules, then the real formatter.
 *
 * @param flag  Fortification level for the `__*_chk` forms; -1 for the plain forms.
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

CHAOS_IO_EXPORT int vfprintf(FILE *stream, const char *format, va_list arguments)
{
    return chaos_io_stdio_vprintf(stream, -1, format, arguments);
}

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
 * @brief Interposed `fclose(3)`: forgets the descriptor's cached path.
 *
 * @details The C library closes the descriptor with its own system call, so the
 * close() wrapper never sees it, and the next file opened under the same number
 * would otherwise inherit this stream's path. Forgotten after the close, like
 * close() does: before it, a lookup on another thread could still cache the
 * open file's path for the number.
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

int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list arguments);
int __fprintf_chk(FILE *stream, int flag, const char *format, ...);
size_t __fread_chk(void *buffer, size_t buffer_size, size_t size, size_t count, FILE *stream);
char *__fgets_chk(char *buffer, size_t buffer_size, int size, FILE *stream);

CHAOS_IO_EXPORT int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list arguments)
{
    return chaos_io_stdio_vprintf(stream, flag, format, arguments);
}

CHAOS_IO_EXPORT int __fprintf_chk(FILE *stream, int flag, const char *format, ...)
{
    va_list arguments;
    int rc;

    va_start(arguments, format);
    rc = chaos_io_stdio_vprintf(stream, flag, format, arguments);
    va_end(arguments);
    return rc;
}

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
