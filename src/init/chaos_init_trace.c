/**
 * @file chaos_init_trace.c
 * @brief Register access for a tracee at a seccomp trace stop (see chaos_init_trace.h).
 *
 * @details `PTRACE_GETREGSET`/`PTRACE_SETREGSET` with `NT_PRSTATUS` rather than
 * `PTRACE_PEEKUSER`: the regset interface is the one both supported architectures
 * implement, and it moves the whole block in one call instead of one word per register.
 *
 * The register block is kept opaque above this file so that nothing else has to know
 * which architecture it was built for.
 *
 * @par Module: chaos-init
 * @par Stability: private / internal
 */

#include "chaos_init_trace.h"

#include <elf.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#if defined(__aarch64__)
#include <asm/ptrace.h>
typedef struct user_pt_regs chaos_init_trace_block_t;
/** @brief Argument registers of the aarch64 system call ABI. */
static const unsigned char g_chaos_init_trace_args[CHAOS_INIT_TRACE_ARGS] = {
    0U, 1U, 2U, 3U, 4U, 5U
};
#elif defined(__x86_64__)
#include <sys/user.h>
typedef struct user_regs_struct chaos_init_trace_block_t;
#else
#error "chaos-init supports aarch64 and x86_64"
#endif

/** @brief The register block inside @p regs, or NULL when it was never read. */
static chaos_init_trace_block_t *chaos_init_trace_block(chaos_init_trace_regs_t *regs)
{
    if (regs == NULL || regs->size < sizeof(chaos_init_trace_block_t))
    {
        return NULL;
    }
    return (chaos_init_trace_block_t *)(void *)regs->raw;
}

/** @copydoc chaos_init_trace_read */
int chaos_init_trace_read(pid_t tid, chaos_init_trace_regs_t *regs)
{
    struct iovec area;

    if (regs == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    (void)memset(regs, 0, sizeof(*regs));
    area.iov_base = regs->raw;
    area.iov_len = sizeof(chaos_init_trace_block_t);
    if (ptrace(PTRACE_GETREGSET, tid, (void *)(long)NT_PRSTATUS, &area) != 0)
    {
        return -1;
    }
    regs->size = area.iov_len;
    return 0;
}

/** @copydoc chaos_init_trace_write */
int chaos_init_trace_write(pid_t tid, const chaos_init_trace_regs_t *regs)
{
    struct iovec area;

    if (regs == NULL || regs->size < sizeof(chaos_init_trace_block_t))
    {
        errno = EINVAL;
        return -1;
    }
    /* The kernel reads through the iovec, so the cast drops only this module's const. */
    area.iov_base = (void *)(uintptr_t)regs->raw;
    area.iov_len = regs->size;
    return ptrace(PTRACE_SETREGSET, tid, (void *)(long)NT_PRSTATUS, &area) != 0 ? -1 : 0;
}

/** @copydoc chaos_init_trace_number */
long chaos_init_trace_number(const chaos_init_trace_regs_t *regs)
{
    const chaos_init_trace_block_t *block =
        chaos_init_trace_block((chaos_init_trace_regs_t *)(uintptr_t)regs);

    if (block == NULL)
    {
        return -1;
    }
#if defined(__aarch64__)
    return (long)block->regs[8];
#else
    return (long)block->orig_rax;
#endif
}

/** @copydoc chaos_init_trace_arg */
uint64_t chaos_init_trace_arg(const chaos_init_trace_regs_t *regs, unsigned index)
{
    const chaos_init_trace_block_t *block =
        chaos_init_trace_block((chaos_init_trace_regs_t *)(uintptr_t)regs);

    if (block == NULL || index >= CHAOS_INIT_TRACE_ARGS)
    {
        return 0U;
    }
#if defined(__aarch64__)
    return (uint64_t)block->regs[g_chaos_init_trace_args[index]];
#else
    switch (index)
    {
    case 0U:
        return (uint64_t)block->rdi;
    case 1U:
        return (uint64_t)block->rsi;
    case 2U:
        return (uint64_t)block->rdx;
    case 3U:
        return (uint64_t)block->r10;
    case 4U:
        return (uint64_t)block->r8;
    default:
        return (uint64_t)block->r9;
    }
#endif
}

/** @copydoc chaos_init_trace_set_arg */
void chaos_init_trace_set_arg(chaos_init_trace_regs_t *regs, unsigned index, uint64_t value)
{
    chaos_init_trace_block_t *block = chaos_init_trace_block(regs);

    if (block == NULL || index >= CHAOS_INIT_TRACE_ARGS)
    {
        return;
    }
#if defined(__aarch64__)
    block->regs[g_chaos_init_trace_args[index]] = value;
#else
    switch (index)
    {
    case 0U:
        block->rdi = value;
        break;
    case 1U:
        block->rsi = value;
        break;
    case 2U:
        block->rdx = value;
        break;
    case 3U:
        block->r10 = value;
        break;
    case 4U:
        block->r8 = value;
        break;
    default:
        block->r9 = value;
        break;
    }
#endif
}

/** @copydoc chaos_init_trace_skip */
int chaos_init_trace_skip(pid_t tid, chaos_init_trace_regs_t *regs, long value)
{
    chaos_init_trace_block_t *block = chaos_init_trace_block(regs);
#if defined(__aarch64__)
    int number = -1;
    struct iovec area;
#endif

    if (block == NULL)
    {
        errno = EINVAL;
        return -1;
    }
#if defined(__aarch64__)
    /* x8 is not where the kernel looks after the stop: the number lives in its own regset
     * on this architecture, and writing the general one would change nothing. */
    block->regs[0] = (uint64_t)value;
    if (chaos_init_trace_write(tid, regs) != 0)
    {
        return -1;
    }
    area.iov_base = &number;
    area.iov_len = sizeof(number);
    return ptrace(PTRACE_SETREGSET, tid, (void *)(long)NT_ARM_SYSTEM_CALL, &area) != 0 ? -1 : 0;
#else
    block->orig_rax = (unsigned long long)-1;
    block->rax = (unsigned long long)value;
    return chaos_init_trace_write(tid, regs);
#endif
}
