/**
 * @file chaos_init_vdso.c
 * @brief Renaming a tracee's vDSO time symbols (see chaos_init_vdso.h).
 *
 * @par Module: chaos-init
 * @par Stability: private / internal
 */

#include "chaos_init_vdso.h"

#include "chaos_init_proc.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/** @brief The auxiliary vector entry holding the vDSO's base address. */
#ifndef AT_SYSINFO_EHDR
#define AT_SYSINFO_EHDR 33
#endif

/** @brief Longest symbol name compared; the longest of interest is 22 bytes. */
#define CHAOS_INIT_VDSO_NAME_MAX 32U

/** @brief Dynamic entries read at most, so a malformed segment cannot be walked for ever. */
#define CHAOS_INIT_VDSO_DYNAMIC_MAX 64U

/** @brief Symbols read at most, for the same reason. */
#define CHAOS_INIT_VDSO_SYMBOLS_MAX 64U

/**
 * @brief The vDSO symbols that answer a clock read, as the three runtimes name them.
 *
 * @details aarch64 exports the `__kernel_` names, x86_64 the `__vdso_` ones and their
 * unversioned aliases. Everything else the vDSO offers is left alone.
 */
static const char *const g_chaos_init_vdso_names[] = {
    "__kernel_clock_gettime",
    "__kernel_gettimeofday",
    "__vdso_clock_gettime",
    "__vdso_gettimeofday",
    "__vdso_time",
    "clock_gettime",
    "gettimeofday",
    "time"
};

#define CHAOS_INIT_VDSO_NAME_COUNT                                                                 \
    (sizeof(g_chaos_init_vdso_names) / sizeof(g_chaos_init_vdso_names[0]))

/** @brief Test seam: how the forced write is made; unit tests make it fail. */
#ifndef CHAOS_INIT_VDSO_POKE
#define CHAOS_INIT_VDSO_POKE chaos_init_vdso_poke
#endif

/**
 * @brief Test seam: where the vDSO starts.
 *
 * @details A unit test points this at an image it built itself, which is the only way to
 * reach the answers a malformed one gives: the real vDSO is always well formed.
 */
#ifndef CHAOS_INIT_VDSO_BASE
#define CHAOS_INIT_VDSO_BASE chaos_init_vdso_base
#endif

/**
 * @brief Writes @p size bytes at @p address of @p pid through `/proc/<pid>/mem`.
 *
 * @details The way to write a read-only mapping: that path writes with `FOLL_FORCE`,
 * where process_vm_writev() refuses. errno is the open's or the write's.
 *
 * @return 0, or -1.
 */
static int chaos_init_vdso_poke(pid_t pid, uint64_t address, const void *data, size_t size)
{
    char path[64];
    ssize_t written;
    int fd;

    (void)snprintf(path, sizeof(path), "/proc/%ld/mem", (long)pid);
    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
    {
        return -1;
    }
    written = pwrite(fd, data, size, (off_t)address);
    (void)close(fd);
    return written == (ssize_t)size ? 0 : -1;
}

/** @brief The vDSO base of @p pid from its auxiliary vector; 0 when it has none. */
static uint64_t chaos_init_vdso_base(pid_t pid)
{
    char path[64];
    uint64_t pair[2];
    FILE *file;
    uint64_t base = 0U;

    (void)snprintf(path, sizeof(path), "/proc/%ld/auxv", (long)pid);
    file = fopen(path, "rb");
    if (file == NULL)
    {
        return 0U;
    }
    while (fread(pair, sizeof(pair[0]), 2U, file) == 2U && pair[0] != 0U)
    {
        if (pair[0] == (uint64_t)AT_SYSINFO_EHDR)
        {
            base = pair[1];
            break;
        }
    }
    (void)fclose(file);
    return base;
}

/**
 * @brief Resolves an address the dynamic segment reports.
 *
 * @details The kernel does not relocate the vDSO's dynamic entries, so they hold
 * link-time addresses, which are offsets from the mapping. A value at or above the base
 * is already absolute (which is what a relocated object would hold), and is taken as is.
 */
static uint64_t chaos_init_vdso_address(uint64_t base, uint64_t value)
{
    return value >= base ? value : base + value;
}

/** @copydoc chaos_init_vdso_blind */
int chaos_init_vdso_blind(pid_t pid)
{
    const uint64_t base = CHAOS_INIT_VDSO_BASE(pid);
    Elf64_Ehdr header;
    uint64_t dynamic = 0U;
    uint64_t strtab = 0U;
    uint64_t symtab = 0U;
    uint64_t entry_size = sizeof(Elf64_Sym);
    uint64_t symbols = 0U;
    unsigned index;
    int renamed = 0;

    if (base == 0U)
    {
        return 0;
    }
    if (chaos_init_read_memory(pid, base, &header, sizeof(header)) != 0 ||
        memcmp(header.e_ident, ELFMAG, SELFMAG) != 0)
    {
        return -1;
    }
    for (index = 0U; index < header.e_phnum; ++index)
    {
        Elf64_Phdr segment;
        const uint64_t at = base + header.e_phoff + (uint64_t)index * header.e_phentsize;

        if (chaos_init_read_memory(pid, at, &segment, sizeof(segment)) != 0)
        {
            return -1;
        }
        if (segment.p_type == PT_DYNAMIC)
        {
            dynamic = chaos_init_vdso_address(base, segment.p_vaddr);
        }
    }
    if (dynamic == 0U)
    {
        return -1;
    }
    for (index = 0U; index < CHAOS_INIT_VDSO_DYNAMIC_MAX; ++index)
    {
        Elf64_Dyn entry;

        if (chaos_init_read_memory(
                pid, dynamic + (uint64_t)index * sizeof(entry), &entry, sizeof(entry)
            ) != 0)
        {
            return -1;
        }
        if (entry.d_tag == DT_NULL)
        {
            break;
        }
        if (entry.d_tag == DT_STRTAB)
        {
            strtab = chaos_init_vdso_address(base, entry.d_un.d_ptr);
        }
        else if (entry.d_tag == DT_SYMTAB)
        {
            symtab = chaos_init_vdso_address(base, entry.d_un.d_ptr);
        }
        else if (entry.d_tag == DT_SYMENT)
        {
            entry_size = entry.d_un.d_val;
        }
        else if (entry.d_tag == DT_HASH)
        {
            /* The hash table leads with nbucket and nchain; nchain is the number of
             * symbols, which the symbol table itself does not report. */
            uint32_t counts[2];

            if (chaos_init_read_memory(
                    pid, chaos_init_vdso_address(base, entry.d_un.d_ptr), counts, sizeof(counts)
                ) != 0)
            {
                return -1;
            }
            symbols = counts[1];
        }
    }
    if (strtab == 0U || symtab == 0U || symbols == 0U || entry_size < sizeof(Elf64_Sym))
    {
        return -1;
    }
    if (symbols > CHAOS_INIT_VDSO_SYMBOLS_MAX)
    {
        symbols = CHAOS_INIT_VDSO_SYMBOLS_MAX;
    }
    /* Index 0 is the undefined symbol and has no name. */
    for (index = 1U; index < (unsigned)symbols; ++index)
    {
        char name[CHAOS_INIT_VDSO_NAME_MAX];
        Elf64_Sym symbol;
        size_t which;

        if (chaos_init_read_memory(
                pid, symtab + (uint64_t)index * entry_size, &symbol, sizeof(symbol)
            ) != 0)
        {
            return -1;
        }
        if (symbol.st_name == 0U ||
            chaos_init_read_string(pid, strtab + symbol.st_name, name, sizeof(name)) < 0)
        {
            continue;
        }
        for (which = 0U; which < CHAOS_INIT_VDSO_NAME_COUNT; ++which)
        {
            if (strcmp(name, g_chaos_init_vdso_names[which]) == 0)
            {
                /* One byte is enough: a lookup compares the whole name, and no runtime
                 * asks for a symbol starting with this character. */
                static const char mark = 'x';

                if (CHAOS_INIT_VDSO_POKE(pid, strtab + symbol.st_name, &mark, sizeof(mark)) != 0)
                {
                    return -1;
                }
                ++renamed;
                break;
            }
        }
    }
    return renamed;
}
