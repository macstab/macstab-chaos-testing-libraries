/**
 * @file chaos_init_proc.c
 * @brief chaos-init: reading a supervised process's memory and /proc entries.
 */

#include "chaos_init_proc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

/** @brief Granularity of string reads; a page of every architecture we build for. */
#define CHAOS_INIT_PAGE 4096U

int chaos_init_read_memory(pid_t pid, uint64_t address, void *out, size_t size)
{
    struct iovec local;
    struct iovec remote;

    local.iov_base = out;
    local.iov_len = size;
    remote.iov_base = (void *)(uintptr_t)address;
    remote.iov_len = size;
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) != (ssize_t)size)
    {
        if (errno == 0)
        {
            errno = EFAULT; /* a partial read: the rest is not mapped */
        }
        return -1;
    }
    return 0;
}

int chaos_init_write_memory(pid_t pid, uint64_t address, const void *data, size_t size)
{
    struct iovec local;
    struct iovec remote;

    local.iov_base = (void *)(uintptr_t)data;
    local.iov_len = size;
    remote.iov_base = (void *)(uintptr_t)address;
    remote.iov_len = size;
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) != (ssize_t)size)
    {
        if (errno == 0)
        {
            errno = EFAULT;
        }
        return -1;
    }
    return 0;
}

long chaos_init_read_string(pid_t pid, uint64_t address, char *out, size_t size)
{
    size_t length = 0U;

    while (length < size)
    {
        /* Never across a page boundary: the next page may not be mapped. */
        const size_t to_page = CHAOS_INIT_PAGE - (size_t)((address + length) % CHAOS_INIT_PAGE);
        const size_t chunk = to_page < size - length ? to_page : size - length;
        const char *end;

        if (chaos_init_read_memory(pid, address + length, out + length, chunk) != 0)
        {
            return -1;
        }
        end = memchr(out + length, '\0', chunk);
        if (end != NULL)
        {
            return (long)(end - out);
        }
        length += chunk;
    }
    errno = ENAMETOOLONG;
    return -1;
}

long chaos_init_proc_link(pid_t pid, const char *name, char *out, size_t size)
{
    char path[64];
    ssize_t length;

    if (size == 0U ||
        (size_t)snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, name) >= sizeof(path))
    {
        return -1;
    }
    length = readlink(path, out, size - 1U);
    if (length < 0)
    {
        return -1;
    }
    out[length] = '\0';
    return (long)length;
}

/** @brief Reads `/proc/<pid>/<name>` into @p out (NUL-terminated); its length or -1. */
static long chaos_init_proc_read(pid_t pid, const char *name, char *out, size_t size)
{
    char path[64];
    ssize_t length;
    int fd;

    (void)snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, name);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        return -1;
    }
    length = read(fd, out, size - 1U);
    (void)close(fd);
    if (length < 0)
    {
        return -1;
    }
    out[length] = '\0';
    return (long)length;
}

/** @brief How /proc files are read; unit tests replace it to feed malformed ones. */
#ifndef CHAOS_INIT_PROC_READ
#define CHAOS_INIT_PROC_READ chaos_init_proc_read
#endif

int chaos_init_process_of(pid_t tid, pid_t *tgid, uint64_t *start)
{
    char text[1024];
    const char *field;
    unsigned long long ticks;
    long group;
    int index;

    if (CHAOS_INIT_PROC_READ(tid, "status", text, sizeof(text)) < 0 ||
        (field = strstr(text, "\nTgid:")) == NULL || sscanf(field, "\nTgid: %ld", &group) != 1 ||
        CHAOS_INIT_PROC_READ((pid_t)group, "stat", text, sizeof(text)) < 0 ||
        (field = strrchr(text, ')')) == NULL)
    {
        return -1;
    }
    /* field points at the space before field 3 (the state); each step moves to the
     * space before the next field, so 19 steps reach field 22, the start time. */
    ++field;
    for (index = 3; index < 22; ++index)
    {
        field = strchr(field + 1, ' ');
        if (field == NULL)
        {
            return -1;
        }
    }
    if (sscanf(field, " %llu", &ticks) != 1)
    {
        return -1;
    }
    /* Fields 26 (start of code) and 28 (start of stack) change with every execve,
     * which keeps pid and start time: a new image is a new process for the rules,
     * as it is under LD_PRELOAD. 0 where the kernel hides them. */
    for (; index < 28; ++index)
    {
        field = strchr(field + 1, ' ');
        if (field == NULL)
        {
            break;
        }
        if (index == 25 || index == 27)
        {
            unsigned long long address = 0ULL;

            (void)sscanf(field, " %llu", &address);
            ticks ^= address *
                     (index == 25 ? UINT64_C(0x9e3779b97f4a7c15) : UINT64_C(0xbf58476d1ce4e5b9));
        }
    }
    *tgid = (pid_t)group;
    *start = (uint64_t)ticks;
    return 0;
}
