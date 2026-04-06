#ifndef CHAOS_IO_TEST_HARNESS_H
#define CHAOS_IO_TEST_HARNESS_H

#include "test_support.h"

#include "../src/chaos_io_actions.h"
#include "../src/chaos_io_config.h"
#include "../src/chaos_io_fdcache.h"

#include <dlfcn.h>
#include <sys/syscall.h>

static int g_config_init_calls = 0;
static int g_config_prepare_calls = 0;
static int g_config_match_loaded_calls = 0;
static int g_config_match_path_calls = 0;
static int g_config_prepare_result = 0;
static int g_config_match_loaded_result = 0;
static int g_config_match_path_result = 0;
static chaos_io_rule_t g_config_rule;
static chaos_io_operation_t g_last_match_loaded_operation = CHAOS_IO_OP_INVALID;
static chaos_io_operation_t g_last_match_path_operation = CHAOS_IO_OP_INVALID;
static char g_last_match_loaded_path[CHAOS_IO_MAX_PATH];
static char g_last_match_path[CHAOS_IO_MAX_PATH];

static int g_fdcache_reset_calls = 0;
static int g_fdcache_resolve_calls = 0;
static int g_fdcache_store_calls = 0;
static int g_fdcache_invalidate_calls = 0;
static int g_fdcache_resolve_result = 0;
static int g_last_resolve_fd = -1;
static int g_last_store_fd = -1;
static int g_last_invalidate_fd = -1;
static char g_resolved_path[CHAOS_IO_MAX_PATH];
static char g_last_store_path[CHAOS_IO_MAX_PATH];

static int g_latency_calls = 0;
static int g_rule_apply_errno_calls = 0;
static int g_rule_should_trigger_calls = 0;
static int g_rule_apply_errno_result = 0;
static int g_rule_should_trigger_result = 0;
static size_t g_torn_count_result = 0U;
static size_t g_last_torn_requested = 0U;
static int g_corrupt_calls = 0;
static size_t g_last_corrupt_size = 0U;

static int g_real_open_calls = 0;
static int g_real_open_return = 0;
static int g_real_open_flags = 0;
static int g_real_open_has_mode = 0;
static int g_real_open_guard = 0;
static mode_t g_real_open_mode = 0;
static char g_real_open_path[CHAOS_IO_MAX_PATH];

static int g_real_openat_calls = 0;
static int g_real_openat_return = 0;
static int g_real_openat_dirfd = -1;
static int g_real_openat_flags = 0;
static int g_real_openat_has_mode = 0;
static int g_real_openat_guard = 0;
static mode_t g_real_openat_mode = 0;
static char g_real_openat_path[CHAOS_IO_MAX_PATH];

static int g_real_read_calls = 0;
static ssize_t g_real_read_return = 0;
static int g_real_read_guard = 0;
static int g_real_read_fd = -1;
static size_t g_real_read_count = 0U;
static char g_real_read_fill[64];

static int g_real_write_calls = 0;
static ssize_t g_real_write_return = 0;
static int g_real_write_guard = 0;
static int g_real_write_fd = -1;
static size_t g_real_write_count = 0U;
#ifdef __linux__
static int g_real_sendfile_calls = 0;
static ssize_t g_real_sendfile_return = 0;
static int g_real_sendfile_guard = 0;
static int g_real_sendfile_out_fd = -1;
static int g_real_sendfile_in_fd = -1;
static off_t *g_real_sendfile_offset = NULL;
static size_t g_real_sendfile_count = 0U;
#endif

static int g_real_close_calls = 0;
static int g_real_close_return = 0;
static int g_real_close_guard = 0;
static int g_real_close_fd = -1;

static int g_real_fsync_calls = 0;
static int g_real_fsync_return = 0;
static int g_real_fsync_guard = 0;
static int g_real_fsync_fd = -1;

static int g_real_fdatasync_calls = 0;
static int g_real_fdatasync_return = 0;
static int g_real_fdatasync_guard = 0;
static int g_real_fdatasync_fd = -1;

static int g_real_pread_calls = 0;
static ssize_t g_real_pread_return = 0;
static int g_real_pread_guard = 0;
static int g_real_pread_fd = -1;
static size_t g_real_pread_count = 0U;
static off_t g_real_pread_offset = 0;
static char g_real_pread_fill[64];

static int g_real_pwrite_calls = 0;
static ssize_t g_real_pwrite_return = 0;
static int g_real_pwrite_guard = 0;
static int g_real_pwrite_fd = -1;
static size_t g_real_pwrite_count = 0U;
static off_t g_real_pwrite_offset = 0;

static int g_sys_open_calls = 0;
static int g_sys_read_calls = 0;
static int g_sys_close_calls = 0;
static long g_sys_open_result = -1;
static long g_sys_read_result = -1;
static long g_sys_close_result = 0;
static uint64_t g_sys_seed_value = 0U;

static const char *g_dlsym_fail_symbol = NULL;
static const char *g_dlerror_pending = NULL;

void chaos_io_config_init(void)
{
    ++g_config_init_calls;
}

int chaos_io_config_prepare(void)
{
    ++g_config_prepare_calls;
    return g_config_prepare_result;
}

int chaos_io_config_match_loaded(
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule)
{
    ++g_config_match_loaded_calls;
    g_last_match_loaded_operation = operation;
    if (path != NULL) {
        (void)snprintf(g_last_match_loaded_path, sizeof(g_last_match_loaded_path), "%s", path);
    } else {
        g_last_match_loaded_path[0] = '\0';
    }

    if (!g_config_match_loaded_result || rule == NULL) {
        return 0;
    }

    *rule = g_config_rule;
    return 1;
}

int chaos_io_config_match_path(
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule)
{
    ++g_config_match_path_calls;
    g_last_match_path_operation = operation;
    if (path != NULL) {
        (void)snprintf(g_last_match_path, sizeof(g_last_match_path), "%s", path);
    } else {
        g_last_match_path[0] = '\0';
    }

    if (!g_config_match_path_result || rule == NULL) {
        return 0;
    }

    *rule = g_config_rule;
    return 1;
}

void chaos_io_fdcache_reset(void)
{
    ++g_fdcache_reset_calls;
}

int chaos_io_fdcache_resolve(int fd, char *path, size_t path_size)
{
    ++g_fdcache_resolve_calls;
    g_last_resolve_fd = fd;

    if (!g_fdcache_resolve_result || path == NULL || path_size == 0U) {
        return 0;
    }

    assert(strlen(g_resolved_path) + 1U <= path_size);
    (void)memcpy(path, g_resolved_path, strlen(g_resolved_path) + 1U);
    return 1;
}

void chaos_io_fdcache_store(int fd, const char *path)
{
    ++g_fdcache_store_calls;
    g_last_store_fd = fd;
    if (path != NULL) {
        (void)snprintf(g_last_store_path, sizeof(g_last_store_path), "%s", path);
    } else {
        g_last_store_path[0] = '\0';
    }
}

void chaos_io_fdcache_invalidate(int fd)
{
    ++g_fdcache_invalidate_calls;
    g_last_invalidate_fd = fd;
}

void chaos_io_rule_apply_latency(const chaos_io_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

int chaos_io_rule_should_trigger(const chaos_io_rule_t *rule)
{
    assert(rule != NULL);
    ++g_rule_should_trigger_calls;
    return g_rule_should_trigger_result;
}

int chaos_io_rule_apply_errno(const chaos_io_rule_t *rule)
{
    assert(rule != NULL);
    ++g_rule_apply_errno_calls;
    if (g_rule_apply_errno_result != 0) {
        errno = rule->errnum;
    }
    return g_rule_apply_errno_result;
}

size_t chaos_io_torn_count(size_t requested)
{
    g_last_torn_requested = requested;
    return g_torn_count_result;
}

void chaos_io_corrupt_buffer(void *buffer, size_t size)
{
    unsigned char *bytes = (unsigned char *)buffer;

    ++g_corrupt_calls;
    g_last_corrupt_size = size;
    if (bytes != NULL && size > 0U) {
        bytes[0] ^= 0x01U;
    }
}

static int chaos_test_real_open_impl(const char *path, int flags, ...)
{
    ++g_real_open_calls;
    g_real_open_flags = flags;
    g_real_open_guard = g_chaos_io_tls_guard;
    if (path != NULL) {
        (void)snprintf(g_real_open_path, sizeof(g_real_open_path), "%s", path);
    } else {
        g_real_open_path[0] = '\0';
    }

    if ((flags & O_CREAT) != 0) {
        va_list args;

        g_real_open_has_mode = 1;
        va_start(args, flags);
        g_real_open_mode = (mode_t)va_arg(args, int);
        va_end(args);
    } else {
        g_real_open_has_mode = 0;
        g_real_open_mode = 0;
    }

    return g_real_open_return;
}

static int chaos_test_real_openat_impl(int dirfd, const char *path, int flags, ...)
{
    ++g_real_openat_calls;
    g_real_openat_dirfd = dirfd;
    g_real_openat_flags = flags;
    g_real_openat_guard = g_chaos_io_tls_guard;
    if (path != NULL) {
        (void)snprintf(g_real_openat_path, sizeof(g_real_openat_path), "%s", path);
    } else {
        g_real_openat_path[0] = '\0';
    }

    if ((flags & O_CREAT) != 0
#ifdef O_TMPFILE
        || ((flags & O_TMPFILE) == O_TMPFILE)
#endif
    ) {
        va_list args;

        g_real_openat_has_mode = 1;
        va_start(args, flags);
        g_real_openat_mode = (mode_t)va_arg(args, int);
        va_end(args);
    } else {
        g_real_openat_has_mode = 0;
        g_real_openat_mode = 0;
    }

    return g_real_openat_return;
}

static ssize_t chaos_test_real_read_impl(int fd, void *buffer, size_t count)
{
    ++g_real_read_calls;
    g_real_read_fd = fd;
    g_real_read_count = count;
    g_real_read_guard = g_chaos_io_tls_guard;

    if (buffer != NULL && g_real_read_return > 0) {
        (void)memcpy(buffer, g_real_read_fill, (size_t)g_real_read_return);
    }

    return g_real_read_return;
}

static ssize_t chaos_test_real_write_impl(int fd, const void *buffer, size_t count)
{
    (void)buffer;
    ++g_real_write_calls;
    g_real_write_fd = fd;
    g_real_write_count = count;
    g_real_write_guard = g_chaos_io_tls_guard;
    return g_real_write_return;
}

#ifdef __linux__
static ssize_t chaos_test_real_sendfile_impl(int out_fd, int in_fd, off_t *offset, size_t count)
{
    ++g_real_sendfile_calls;
    g_real_sendfile_out_fd = out_fd;
    g_real_sendfile_in_fd = in_fd;
    g_real_sendfile_offset = offset;
    g_real_sendfile_count = count;
    g_real_sendfile_guard = g_chaos_io_tls_guard;
    return g_real_sendfile_return;
}
#endif

static int chaos_test_real_close_impl(int fd)
{
    ++g_real_close_calls;
    g_real_close_fd = fd;
    g_real_close_guard = g_chaos_io_tls_guard;
    return g_real_close_return;
}

static int chaos_test_real_fsync_impl(int fd)
{
    ++g_real_fsync_calls;
    g_real_fsync_fd = fd;
    g_real_fsync_guard = g_chaos_io_tls_guard;
    return g_real_fsync_return;
}

static int chaos_test_real_fdatasync_impl(int fd)
{
    ++g_real_fdatasync_calls;
    g_real_fdatasync_fd = fd;
    g_real_fdatasync_guard = g_chaos_io_tls_guard;
    return g_real_fdatasync_return;
}

static ssize_t chaos_test_real_pread_impl(int fd, void *buffer, size_t count, off_t offset)
{
    ++g_real_pread_calls;
    g_real_pread_fd = fd;
    g_real_pread_count = count;
    g_real_pread_offset = offset;
    g_real_pread_guard = g_chaos_io_tls_guard;

    if (buffer != NULL && g_real_pread_return > 0) {
        (void)memcpy(buffer, g_real_pread_fill, (size_t)g_real_pread_return);
    }

    return g_real_pread_return;
}

static ssize_t chaos_test_real_pwrite_impl(int fd, const void *buffer, size_t count, off_t offset)
{
    (void)buffer;
    ++g_real_pwrite_calls;
    g_real_pwrite_fd = fd;
    g_real_pwrite_count = count;
    g_real_pwrite_offset = offset;
    g_real_pwrite_guard = g_chaos_io_tls_guard;
    return g_real_pwrite_return;
}

static void *chaos_test_dlsym_pointer(const void *function_bytes, size_t function_size)
{
    void *resolved = NULL;

    assert(function_bytes != NULL);
    assert(function_size <= sizeof(resolved));
    (void)memcpy(&resolved, function_bytes, function_size);
    return resolved;
}

#define CHAOS_TEST_DLSYM_RESULT(type, function) \
    chaos_test_dlsym_pointer(&(type){ function }, sizeof(type))

static void *chaos_test_dlsym(void *handle, const char *symbol)
{
    (void)handle;

    g_dlerror_pending = NULL;
    if (g_dlsym_fail_symbol != NULL && strcmp(symbol, g_dlsym_fail_symbol) == 0) {
        g_dlerror_pending = "missing symbol";
        return NULL;
    }
    if (strcmp(symbol, "read") == 0) {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_read_fn, chaos_test_real_read_impl);
    }
    if (strcmp(symbol, "write") == 0) {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_write_fn, chaos_test_real_write_impl);
    }
#ifdef __linux__
    if (strcmp(symbol, "sendfile") == 0) {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_sendfile_fn, chaos_test_real_sendfile_impl);
    }
#endif
    if (strcmp(symbol, "open") == 0) {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_open_fn, chaos_test_real_open_impl);
    }
    if (strcmp(symbol, "openat") == 0) {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_openat_fn, chaos_test_real_openat_impl);
    }
    if (strcmp(symbol, "close") == 0) {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_close_fn, chaos_test_real_close_impl);
    }
    if (strcmp(symbol, "fsync") == 0) {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_sync_fn, chaos_test_real_fsync_impl);
    }
    if (strcmp(symbol, "fdatasync") == 0) {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_sync_fn, chaos_test_real_fdatasync_impl);
    }
    if (strcmp(symbol, "pread") == 0) {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_pread_fn, chaos_test_real_pread_impl);
    }
    if (strcmp(symbol, "pwrite") == 0) {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_pwrite_fn, chaos_test_real_pwrite_impl);
    }

    g_dlerror_pending = "unexpected symbol";
    return NULL;
}

static char *chaos_test_dlerror(void)
{
    char *message = (char *)g_dlerror_pending;
    g_dlerror_pending = NULL;
    return message;
}

static void chaos_test_abort(void)
{
    exit(111);
}

static long chaos_test_syscall(long number, ...)
{
    va_list args;
    long result = -1;

    va_start(args, number);
    if (number == SYS_openat) {
        (void)va_arg(args, int);
        (void)va_arg(args, const char *);
        (void)va_arg(args, int);
        (void)va_arg(args, int);
        ++g_sys_open_calls;
        result = g_sys_open_result;
    } else if (number == SYS_read) {
        int fd = va_arg(args, int);
        void *buffer = va_arg(args, void *);
        size_t size = va_arg(args, size_t);

        (void)fd;
        ++g_sys_read_calls;
        if (g_sys_read_result > 0) {
            size_t copy_size = (size_t)g_sys_read_result;
            if (copy_size > size) {
                copy_size = size;
            }
            (void)memcpy(buffer, &g_sys_seed_value, copy_size);
        }
        result = g_sys_read_result;
    } else if (number == SYS_close) {
        (void)va_arg(args, int);
        ++g_sys_close_calls;
        result = g_sys_close_result;
    }
    va_end(args);

    return result;
}

#define dlsym chaos_test_dlsym
#define dlerror chaos_test_dlerror
#define abort chaos_test_abort
#define syscall chaos_test_syscall
#define CHAOS_IO_CONSTRUCTOR
#include "../src/chaos_io.c"
#include "../src/chaos_io_open.c"
#include "../src/chaos_io_rw.c"
#include "../src/chaos_io_sync.c"
#undef CHAOS_IO_CONSTRUCTOR
#undef syscall
#undef abort
#undef dlerror
#undef dlsym

static void chaos_test_reset_state(void)
{
    (void)memset(&g_config_rule, 0, sizeof(g_config_rule));
    g_config_init_calls = 0;
    g_config_prepare_calls = 0;
    g_config_match_loaded_calls = 0;
    g_config_match_path_calls = 0;
    g_config_prepare_result = 0;
    g_config_match_loaded_result = 0;
    g_config_match_path_result = 0;
    g_last_match_loaded_operation = CHAOS_IO_OP_INVALID;
    g_last_match_path_operation = CHAOS_IO_OP_INVALID;
    g_last_match_loaded_path[0] = '\0';
    g_last_match_path[0] = '\0';

    g_fdcache_reset_calls = 0;
    g_fdcache_resolve_calls = 0;
    g_fdcache_store_calls = 0;
    g_fdcache_invalidate_calls = 0;
    g_fdcache_resolve_result = 0;
    g_last_resolve_fd = -1;
    g_last_store_fd = -1;
    g_last_invalidate_fd = -1;
    g_resolved_path[0] = '\0';
    g_last_store_path[0] = '\0';

    g_latency_calls = 0;
    g_rule_apply_errno_calls = 0;
    g_rule_should_trigger_calls = 0;
    g_rule_apply_errno_result = 0;
    g_rule_should_trigger_result = 0;
    g_torn_count_result = 0U;
    g_last_torn_requested = 0U;
    g_corrupt_calls = 0;
    g_last_corrupt_size = 0U;

    g_real_open_calls = 0;
    g_real_open_return = 10;
    g_real_open_flags = 0;
    g_real_open_has_mode = 0;
    g_real_open_guard = 0;
    g_real_open_mode = 0;
    g_real_open_path[0] = '\0';

    g_real_openat_calls = 0;
    g_real_openat_return = 10;
    g_real_openat_dirfd = -1;
    g_real_openat_flags = 0;
    g_real_openat_has_mode = 0;
    g_real_openat_guard = 0;
    g_real_openat_mode = 0;
    g_real_openat_path[0] = '\0';

    g_real_read_calls = 0;
    g_real_read_return = 0;
    g_real_read_guard = 0;
    g_real_read_fd = -1;
    g_real_read_count = 0U;
    (void)memset(g_real_read_fill, 0, sizeof(g_real_read_fill));

    g_real_write_calls = 0;
    g_real_write_return = 0;
    g_real_write_guard = 0;
    g_real_write_fd = -1;
    g_real_write_count = 0U;
#ifdef __linux__
    g_real_sendfile_calls = 0;
    g_real_sendfile_return = 0;
    g_real_sendfile_guard = 0;
    g_real_sendfile_out_fd = -1;
    g_real_sendfile_in_fd = -1;
    g_real_sendfile_offset = NULL;
    g_real_sendfile_count = 0U;
#endif

    g_real_close_calls = 0;
    g_real_close_return = 0;
    g_real_close_guard = 0;
    g_real_close_fd = -1;

    g_real_fsync_calls = 0;
    g_real_fsync_return = 0;
    g_real_fsync_guard = 0;
    g_real_fsync_fd = -1;

    g_real_fdatasync_calls = 0;
    g_real_fdatasync_return = 0;
    g_real_fdatasync_guard = 0;
    g_real_fdatasync_fd = -1;

    g_real_pread_calls = 0;
    g_real_pread_return = 0;
    g_real_pread_guard = 0;
    g_real_pread_fd = -1;
    g_real_pread_count = 0U;
    g_real_pread_offset = 0;
    (void)memset(g_real_pread_fill, 0, sizeof(g_real_pread_fill));

    g_real_pwrite_calls = 0;
    g_real_pwrite_return = 0;
    g_real_pwrite_guard = 0;
    g_real_pwrite_fd = -1;
    g_real_pwrite_count = 0U;
    g_real_pwrite_offset = 0;

    g_sys_open_calls = 0;
    g_sys_read_calls = 0;
    g_sys_close_calls = 0;
    g_sys_open_result = -1;
    g_sys_read_result = -1;
    g_sys_close_result = 0;
    g_sys_seed_value = UINT64_C(0x0123456789abcdef);

    g_dlsym_fail_symbol = NULL;
    g_dlerror_pending = NULL;
    g_chaos_io_real_read = NULL;
    g_chaos_io_real_write = NULL;
    g_chaos_io_real_open = NULL;
    g_chaos_io_real_openat = NULL;
    g_chaos_io_real_close = NULL;
    g_chaos_io_real_fsync = NULL;
    g_chaos_io_real_fdatasync = NULL;
    g_chaos_io_real_pread = NULL;
    g_chaos_io_real_pwrite = NULL;
#ifdef __linux__
    g_chaos_io_real_sendfile = NULL;
#endif
    g_chaos_io_tls_guard = 0;
    g_chaos_io_tls_prng_state = 0U;
    g_chaos_io_process_seed = 0U;
}

static void chaos_test_bind_real_functions(void)
{
    g_chaos_io_real_read = chaos_test_real_read_impl;
    g_chaos_io_real_write = chaos_test_real_write_impl;
    g_chaos_io_real_open = chaos_test_real_open_impl;
    g_chaos_io_real_openat = chaos_test_real_openat_impl;
    g_chaos_io_real_close = chaos_test_real_close_impl;
    g_chaos_io_real_fsync = chaos_test_real_fsync_impl;
    g_chaos_io_real_fdatasync = chaos_test_real_fdatasync_impl;
    g_chaos_io_real_pread = chaos_test_real_pread_impl;
    g_chaos_io_real_pwrite = chaos_test_real_pwrite_impl;
#ifdef __linux__
    g_chaos_io_real_sendfile = chaos_test_real_sendfile_impl;
#endif
}

static void chaos_test_bind_libc_functions_for_exit(void)
{
    void *resolved;

    resolved = dlsym(RTLD_NEXT, "read");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_read, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "write");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_write, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "open");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_open, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "openat");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_openat, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "close");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_close, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "fsync");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_fsync, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "fdatasync");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_fdatasync, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "pread");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_pread, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "pwrite");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_pwrite, &resolved, sizeof(resolved));
#ifdef __linux__
    resolved = dlsym(RTLD_NEXT, "sendfile");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_sendfile, &resolved, sizeof(resolved));
#endif

    g_config_prepare_result = 0;
    g_config_match_loaded_result = 0;
    g_config_match_path_result = 0;
    g_fdcache_resolve_result = 0;
    g_rule_apply_errno_result = 0;
    g_rule_should_trigger_result = 0;
}

#endif
