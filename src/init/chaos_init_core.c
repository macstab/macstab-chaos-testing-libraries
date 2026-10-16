/**
 * @file chaos_init_core.c
 * @brief chaos-init logic without system calls: arguments, filter, status, exit code.
 */

#include "chaos_init_core.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the filter reads the low word of 64-bit arguments at their offset"
#endif

#if defined(__x86_64__)
#define CHAOS_INIT_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define CHAOS_INIT_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "chaos-init supports x86_64 and aarch64"
#endif

/** @brief Library names for --libs and the status file, in bit order. */
static const struct
{
    const char *name;
    unsigned bit;
} g_chaos_init_libs[] = {
    {"io", CHAOS_INIT_LIB_IO},
    {"net", CHAOS_INIT_LIB_NET},
    {"dns", CHAOS_INIT_LIB_DNS},
    {"time", CHAOS_INIT_LIB_TIME},
    {"memory", CHAOS_INIT_LIB_MEMORY},
    {"process", CHAOS_INIT_LIB_PROCESS},
};

#define CHAOS_INIT_LIB_COUNT (sizeof(g_chaos_init_libs) / sizeof(g_chaos_init_libs[0]))

/** @brief Bit of library @p name (of @p length bytes); 0 when unknown. */
static unsigned chaos_init_lib_bit(const char *name, size_t length)
{
    size_t index;

    for (index = 0U; index < CHAOS_INIT_LIB_COUNT; ++index)
    {
        if (strlen(g_chaos_init_libs[index].name) == length &&
            strncmp(g_chaos_init_libs[index].name, name, length) == 0)
        {
            return g_chaos_init_libs[index].bit;
        }
    }
    return 0U;
}

int chaos_init_parse_args(int argc, char **argv, chaos_init_options_t *options)
{
    const char *cursor;

    if (argc < 5 || strcmp(argv[1], "--libs") != 0 || strcmp(argv[3], "--") != 0)
    {
        return -1;
    }
    options->libs = 0U;
    options->command = 4;
    cursor = argv[2];
    for (;;)
    {
        const char *comma = strchr(cursor, ',');
        const size_t length = comma != NULL ? (size_t)(comma - cursor) : strlen(cursor);
        const unsigned bit = chaos_init_lib_bit(cursor, length);

        if (bit == 0U)
        {
            return -1;
        }
        options->libs |= bit;
        if (comma == NULL)
        {
            return 0;
        }
        cursor = comma + 1;
    }
}

/** @brief Appends @p nr to @p list unless it is there already. */
static void chaos_init_add_syscall(long nr, long *list, size_t *count)
{
    size_t index;

    for (index = 0U; index < *count; ++index)
    {
        if (list[index] == nr)
        {
            return;
        }
    }
    list[(*count)++] = nr;
}

/** @brief System calls each library acts on; architecture-specific ones where they exist. */
static const long g_chaos_init_io_calls[] = {
    __NR_openat,    __NR_read,     __NR_readv,     __NR_write,           __NR_writev,
    __NR_pread64,   __NR_preadv,   __NR_pwrite64,  __NR_pwritev,         __NR_sendfile,
    __NR_ftruncate, __NR_truncate, __NR_fallocate, __NR_unlinkat,        __NR_renameat2,
    __NR_close,     __NR_fsync,    __NR_fdatasync, __NR_copy_file_range, __NR_preadv2,
    __NR_pwritev2,
#ifdef __NR_openat2
    __NR_openat2,
#endif
#ifdef __NR_open
    __NR_open,
#endif
#ifdef __NR_creat
    __NR_creat,
#endif
#ifdef __NR_unlink
    __NR_unlink,
#endif
#ifdef __NR_rmdir
    __NR_rmdir,
#endif
#ifdef __NR_rename
    __NR_rename,
#endif
#ifdef __NR_renameat
    __NR_renameat,
#endif
};

static const long g_chaos_init_net_calls[] = {
    __NR_socket,       __NR_socketpair,  __NR_bind,    __NR_listen,   __NR_connect,  __NR_accept4,
    __NR_shutdown,     __NR_sendto,      __NR_sendmsg, __NR_sendmmsg, __NR_recvfrom, __NR_recvmsg,
    __NR_recvmmsg,     __NR_read,        __NR_readv,   __NR_write,    __NR_writev,   __NR_ppoll,
    __NR_pselect6,     __NR_epoll_pwait, __NR_close,
#ifdef __NR_accept
    __NR_accept,
#endif
#ifdef __NR_poll
    __NR_poll,
#endif
#ifdef __NR_select
    __NR_select,
#endif
#ifdef __NR_epoll_wait
    __NR_epoll_wait,
#endif
#ifdef __NR_epoll_pwait2
    __NR_epoll_pwait2,
#endif
};

static const long g_chaos_init_memory_calls[] = {
    __NR_mmap,
    __NR_munmap,
    __NR_mprotect,
    __NR_madvise,
};

static const long g_chaos_init_process_calls[] = {
    __NR_clone,
    __NR_execve,
    __NR_execveat,
    __NR_wait4,
    __NR_waitid,
#ifdef __NR_clone3
    __NR_clone3,
#endif
#ifdef __NR_fork
    __NR_fork,
#endif
#ifdef __NR_vfork
    __NR_vfork,
#endif
};

#define CHAOS_INIT_ADD_ALL(table, list, count)                                                     \
    do                                                                                             \
    {                                                                                              \
        size_t chaos_init_i;                                                                       \
        for (chaos_init_i = 0U; chaos_init_i < sizeof(table) / sizeof((table)[0]); ++chaos_init_i) \
        {                                                                                          \
            chaos_init_add_syscall((table)[chaos_init_i], (list), (count));                        \
        }                                                                                          \
    } while (0)

size_t chaos_init_build_filter(unsigned libs, struct sock_filter *out, size_t capacity)
{
    long calls[CHAOS_INIT_MAX_FILTER];
    size_t count = 0U;
    size_t index;
    size_t length = 0U;
    int handover = 0;

    if ((libs & CHAOS_INIT_LIB_IO) != 0U)
    {
        CHAOS_INIT_ADD_ALL(g_chaos_init_io_calls, calls, &count);
    }
    if ((libs & CHAOS_INIT_LIB_NET) != 0U)
    {
        CHAOS_INIT_ADD_ALL(g_chaos_init_net_calls, calls, &count);
    }
    if ((libs & CHAOS_INIT_LIB_MEMORY) != 0U)
    {
        CHAOS_INIT_ADD_ALL(g_chaos_init_memory_calls, calls, &count);
    }
    if ((libs & CHAOS_INIT_LIB_PROCESS) != 0U)
    {
        CHAOS_INIT_ADD_ALL(g_chaos_init_process_calls, calls, &count);
    }
    /* sendmsg gets its own block, which lets the handover through. */
    for (index = 0U; index < count; ++index)
    {
        if (calls[index] == __NR_sendmsg)
        {
            calls[index] = calls[--count];
            handover = 1;
            break;
        }
    }
    if (count + 16U > capacity)
    {
        return 0U;
    }

    /* Another architecture (the x32 ABI included) passes: chaos-init decodes only its own. */
    out[length++] =
        (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    out[length++] =
        (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CHAOS_INIT_AUDIT_ARCH, 1, 0);
    out[length++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    out[length++] =
        (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#ifdef __x86_64__
    out[length++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000U, 0, 1);
    out[length++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
#endif
    if (handover)
    {
        /* sendmsg(CHAOS_INIT_HANDOVER_FD, ..., CHAOS_INIT_HANDOVER_FLAGS) passes, any
         * other sendmsg is notified. The accumulator still holds nr when it skips. */
        out[length++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 6);
        out[length++] = (struct sock_filter
        )BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
        out[length++] =
            (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CHAOS_INIT_HANDOVER_FD, 0, 3);
        out[length++] = (struct sock_filter
        )BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2]));
        out[length++] = (struct sock_filter
        )BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CHAOS_INIT_HANDOVER_FLAGS, 0, 1);
        out[length++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        out[length++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    }
    for (index = 0U; index < count; ++index)
    {
        /* A match jumps over the remaining tests and the ALLOW to the notification. */
        out[length++] = (struct sock_filter)BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K, (unsigned)calls[index], (unsigned char)(count - index), 0
        );
    }
    out[length++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    out[length++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    return length;
}

int chaos_init_exit_code(int status)
{
    if ((status & 0x7f) == 0)
    {
        return (status >> 8) & 0xff;
    }
    return 128 + (status & 0x7f);
}

int chaos_init_find_command(const char *command, const char *path, char *out, size_t size)
{
    const char *entry;

    if (command == NULL || *command == '\0' || out == NULL || size == 0U)
    {
        return 0;
    }
    if (strchr(command, '/') != NULL)
    {
        return (size_t)snprintf(out, size, "%s", command) < size;
    }
    entry = path != NULL ? path : "/usr/local/bin:/usr/bin:/bin";
    for (;;)
    {
        const char *end = strchr(entry, ':');
        const size_t length = end != NULL ? (size_t)(end - entry) : strlen(entry);
        struct stat info;

        if ((size_t
            )snprintf(out, size, "%.*s%s%s", (int)length, entry, length > 0U ? "/" : "", command) <
                size &&
            stat(out, &info) == 0 && S_ISREG(info.st_mode) && access(out, X_OK) == 0)
        {
            return 1;
        }
        if (end == NULL)
        {
            return 0;
        }
        entry = end + 1;
    }
}

int chaos_init_kernel_supported(const char *release)
{
    unsigned major = 0U;
    unsigned minor = 0U;

    if (release == NULL || sscanf(release, "%u.%u", &major, &minor) != 2)
    {
        return 0;
    }
    return major > 5U || (major == 5U && minor >= 5U);
}

const char *chaos_init_unsupported_reason(int error)
{
    switch (error)
    {
    case EINVAL:
        return "seccomp user notification not available (emulated architecture?)";
    case ENOSYS:
        return "seccomp not available in this kernel";
    case EACCES:
    case EPERM:
        return "seccomp refused by the container's security settings";
    case ENOTSUP:
        return "kernel older than 5.5";
    default:
        return "seccomp could not be installed";
    }
}

size_t
chaos_init_format_status(char *buffer, size_t size, unsigned libs, const char *reason, long pid)
{
    char names[64] = "";
    size_t index;
    int written;

    for (index = 0U; index < CHAOS_INIT_LIB_COUNT; ++index)
    {
        if ((libs & g_chaos_init_libs[index].bit) != 0U)
        {
            if (names[0] != '\0')
            {
                (void)strcat(names, ",");
            }
            (void)strcat(names, g_chaos_init_libs[index].name);
        }
    }
    if (reason == NULL)
    {
        written = snprintf(buffer, size, "state=active\nlibs=%s\npid=%ld\n", names, pid);
    }
    else
    {
        written = snprintf(
            buffer, size, "state=unsupported\nreason=%s\nlibs=%s\npid=%ld\n", reason, names, pid
        );
    }
    if (written < 0 || (size_t)written >= size)
    {
        return 0U;
    }
    return (size_t)written;
}
