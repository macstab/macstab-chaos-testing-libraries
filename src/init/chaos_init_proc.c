/**
 * @file chaos_init_proc.c
 * @brief `chaos-init`: tracee memory access and /proc parsing (see chaos_init_proc.h for
 *        access rules and TOCTOU limits).
 *
 * @details No caching: every call goes to the kernel, so results reflect the tracee at the
 * moment of the call. Test seam: CHAOS_INIT_PROC_READ replaces the /proc file reader so
 * unit tests can feed malformed status/stat contents.
 */

#include "chaos_init_proc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

/**
 * @brief Chunk boundary for string reads. 4 KiB is the smallest page size on x86_64 and
 *        aarch64; larger pages (16/64 KiB arm64 kernels) are multiples, so no chunk spans
 *        two pages.
 */
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
            errno = EFAULT; /* short read sets no errno: the rest is not mapped */
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
        /* Never across a page boundary: a chunk whose tail is unmapped reads short, which
         * chaos_init_read_memory() treats as failure, though the NUL may lie before it. */
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

/**
 * @brief Reads up to @p size - 1 bytes of `/proc/<pid>/<name>` into @p out with one read(),
 *        NUL-terminated. The callers' fields (Tgid, PPid, stat fields up to 28) lie within
 *        their 1 KiB buffers. @p size must be > 0. @return The length, or -1.
 */
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

/** @brief Test seam: how /proc files are read; unit tests substitute malformed contents. */
#ifndef CHAOS_INIT_PROC_READ
#define CHAOS_INIT_PROC_READ chaos_init_proc_read
#endif

pid_t chaos_init_parent_of(pid_t pid)
{
    char text[1024];
    const char *field;
    long parent;

    if (CHAOS_INIT_PROC_READ(pid, "status", text, sizeof(text)) < 0 ||
        (field = strstr(text, "\nPPid:")) == NULL || sscanf(field, "\nPPid: %ld", &parent) != 1)
    {
        return -1;
    }
    return (pid_t)parent;
}

int chaos_init_process_of(pid_t tid, pid_t *tgid, uint64_t *start)
{
    char text[1024];
    const char *field;
    unsigned long long ticks;
    long group;
    int index;

    /* /proc/<tid> resolves for any thread id, not only group leaders. stat's comm field
     * (2) may hold spaces and ')', so parsing starts after the last ')'. */
    if (CHAOS_INIT_PROC_READ(tid, "status", text, sizeof(text)) < 0 ||
        (field = strstr(text, "\nTgid:")) == NULL || sscanf(field, "\nTgid: %ld", &group) != 1 ||
        CHAOS_INIT_PROC_READ((pid_t)group, "stat", text, sizeof(text)) < 0 ||
        (field = strrchr(text, ')')) == NULL)
    {
        return -1;
    }
    /* field now points at the space before field 3 (state); each step moves to the space
     * before the next field, so 19 steps reach field 22, starttime. */
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
    /* Fields 26 (startcode) and 28 (startstack) differ after an execve(), which keeps pid
     * and start time: a new image is a new process for the rules, as under LD_PRELOAD.
     * They are 0 where the kernel hides them, and a missing tail is tolerated. Each is
     * multiplied by a distinct odd 64-bit constant before XOR so the two cannot cancel
     * trivially; the result serves only equality tests. */
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
