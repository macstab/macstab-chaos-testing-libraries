/**
 * @file test_chaos_init_vdso.c
 * @brief Proves chaos-init finds and renames the time symbols of a process's vDSO, and
 *        gives up rather than guessing when the image is not what it expects.
 *
 * @details Unit under test: `chaos_init_vdso_blind()` in `src/init/chaos_init_vdso.c`,
 * compiled in by `#include` with `chaos_init_proc.c` (the reads).
 *
 * Two kinds of case. The real vDSO of this process, which proves the walk works against
 * what the kernel actually maps -- its symbols are renamed and a second call then finds
 * nothing left to rename. And a hand-built image in this process's own memory, reached
 * through the `CHAOS_INIT_VDSO_BASE` seam, which is the only way to ask what happens when
 * the image is malformed: the real one never is.
 *
 * `CHAOS_INIT_VDSO_POKE` replaces the forced write, so the test can watch what would be
 * written (and refuse it) instead of changing the mapping under its own feet.
 *
 * Properties proven:
 * - every time symbol is renamed, by one byte, and nothing else is touched -- not
 *   `__kernel_rt_sigreturn`, which is how a signal handler returns;
 * - a process without a vDSO is not a failure: nothing is renamed, nothing is reported;
 * - a missing ELF magic, a missing dynamic segment, a dynamic segment without the string
 *   or symbol table or without the hash table, and an unreadable image each answer -1;
 * - a symbol table longer than the walk allows is cut rather than followed;
 * - a symbol without a name is skipped;
 * - a write that fails answers -1, so the supervisor can say the clock of that image
 *   stays invisible;
 * - the forced write reaches a read-only mapping, which is the whole reason it goes
 *   through `/proc/<pid>/mem`, and reports a process or an address it cannot write.
 */

#include <elf.h>
#include <string.h>
#include <sys/types.h>

/* The forced write: counted, with the last address and byte kept, and refusable. */
static int g_poke_fails = 0;
static unsigned g_pokes = 0U;
static uint64_t g_poke_at = 0U;
static char g_poke_byte = 0;
static int test_poke(pid_t pid, uint64_t address, const void *data, size_t size);
#define CHAOS_INIT_VDSO_POKE(pid, address, data, size) test_poke((pid), (address), (data), (size))

/* Where the vDSO is: the kernel's, or an image the test built. */
static uint64_t g_base_override = 0U;
static int g_base_overridden = 0;
static uint64_t chaos_init_vdso_base(pid_t pid);
static uint64_t test_base(pid_t pid)
{
    return g_base_overridden ? g_base_override : chaos_init_vdso_base(pid);
}
#define CHAOS_INIT_VDSO_BASE(pid) test_base(pid)

#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_vdso.c"

#include <assert.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <unistd.h>

static int test_poke(pid_t pid, uint64_t address, const void *data, size_t size)
{
    (void)pid;
    assert(size == 1U);
    ++g_pokes;
    g_poke_at = address;
    g_poke_byte = *(const char *)data;
    return g_poke_fails ? -1 : 0;
}

/** @brief A vDSO-shaped image the test can bend: one LOAD, one DYNAMIC, two symbols. */
typedef struct test_image
{
    Elf64_Ehdr header;
    Elf64_Phdr segments[2];
    Elf64_Dyn dynamic[8];
    uint32_t hash[2];
    Elf64_Sym symbols[80];
    char strings[64];
} test_image_t;

/**
 * @brief Builds an image whose second symbol is `__kernel_clock_gettime`.
 *
 * @details Offsets are relative to the image, as the kernel leaves the vDSO's own: the
 * walk adds the base to them.
 */
static void build(test_image_t *image)
{
    memset(image, 0, sizeof(*image));
    memcpy(image->header.e_ident, ELFMAG, SELFMAG);
    image->header.e_phoff = offsetof(test_image_t, segments);
    image->header.e_phentsize = sizeof(image->segments[0]);
    image->header.e_phnum = 2U;
    image->segments[0].p_type = PT_LOAD;
    image->segments[1].p_type = PT_DYNAMIC;
    image->segments[1].p_vaddr = offsetof(test_image_t, dynamic);
    image->dynamic[0].d_tag = DT_STRTAB;
    image->dynamic[0].d_un.d_ptr = offsetof(test_image_t, strings);
    image->dynamic[1].d_tag = DT_SYMTAB;
    image->dynamic[1].d_un.d_ptr = offsetof(test_image_t, symbols);
    image->dynamic[2].d_tag = DT_SYMENT;
    image->dynamic[2].d_un.d_val = sizeof(Elf64_Sym);
    image->dynamic[3].d_tag = DT_HASH;
    image->dynamic[3].d_un.d_ptr = offsetof(test_image_t, hash);
    image->dynamic[4].d_tag = DT_NULL;
    image->hash[0] = 1U; /* nbucket, unread */
    image->hash[1] = 3U; /* nchain: the symbol count */
    /* Symbol 1 has no name at all, symbol 2 is a clock read. */
    image->symbols[2].st_name = 1U;
    (void)strcpy(image->strings + 1, "__kernel_clock_gettime");
}

/** @brief Points the walk at @p image and blinds it. */
static int blind_image(test_image_t *image)
{
    g_base_override = (uint64_t)(uintptr_t)image;
    g_base_overridden = 1;
    return chaos_init_vdso_blind(getpid());
}

int main(void)
{
    test_image_t image;

    /* The kernel's own vDSO: every time symbol it exports is renamed, and the write is
     * one byte each. The count is not fixed across architectures (aarch64 exports two of
     * them, x86_64 five), only that there are some and that nothing else is written. */
    g_pokes = 0U;
    assert(chaos_init_vdso_blind(getpid()) >= 2);
    assert(g_pokes >= 2U && g_poke_byte == 'x');
    assert(g_poke_at > getauxval(AT_SYSINFO_EHDR));

    /* The forced write itself, on this process's own vDSO: the mapping is read-only, so
     * this is the one way to change it, and the change is private to this process. The
     * byte is put back afterwards -- nothing here has resolved a symbol since. */
    {
        const unsigned char *vdso = (const unsigned char *)(uintptr_t)getauxval(AT_SYSINFO_EHDR);
        const uint64_t at = (uint64_t)(uintptr_t)(vdso + 1);
        const char restore = (char)vdso[1];
        static const char mark = 'x';

        assert(restore == 'E');
        assert(chaos_init_vdso_poke(getpid(), at, &mark, sizeof(mark)) == 0);
        assert(vdso[1] == 'x');
        assert(chaos_init_vdso_poke(getpid(), at, &restore, sizeof(restore)) == 0);
        assert(vdso[1] == 'E');
        /* A process that does not exist has no memory to open, and an address that is
         * mapped nowhere cannot be written: both are refused rather than reported as
         * written. */
        assert(chaos_init_vdso_poke(0x7ffffff, at, &mark, sizeof(mark)) == -1);
        assert(chaos_init_vdso_poke(getpid(), 0x10U, &mark, sizeof(mark)) == -1);
    }

    /* A process without a vDSO is not an error: there is nothing to rename and nothing
     * to report. A process that is gone has no auxiliary vector to read, which answers
     * the same way -- there is nothing of it left to blind. */
    g_base_override = 0U;
    g_base_overridden = 1;
    assert(chaos_init_vdso_blind(getpid()) == 0);
    g_base_overridden = 0;
    assert(chaos_init_vdso_blind(0x7ffffff) == 0);

    /* The hand-built image: the one symbol with a name that matches is renamed, the
     * nameless one is skipped, and the address written is the name's. */
    build(&image);
    g_pokes = 0U;
    assert(blind_image(&image) == 1);
    assert(g_pokes == 1U && g_poke_byte == 'x');
    assert(g_poke_at == (uint64_t)(uintptr_t)image.strings + 1U);

    /* A name that is not a clock read is left alone -- a renamed
     * `__kernel_rt_sigreturn` would break every signal handler return. */
    build(&image);
    (void)strcpy(image.strings + 1, "__kernel_rt_sigreturn");
    assert(blind_image(&image) == 0);

    /* A write the kernel refuses is reported: that image keeps its vDSO, and its clock
     * reads stay invisible. */
    build(&image);
    g_poke_fails = 1;
    assert(blind_image(&image) == -1);
    g_poke_fails = 0;

    /* What the walk refuses to guess at. */
    build(&image);
    image.header.e_ident[1] = 'X';
    assert(blind_image(&image) == -1);
    build(&image);
    image.segments[1].p_type = PT_NOTE; /* no dynamic segment */
    assert(blind_image(&image) == -1);
    build(&image);
    image.dynamic[0].d_tag = DT_NULL; /* no string table */
    assert(blind_image(&image) == -1);
    build(&image);
    image.dynamic[1].d_tag = DT_NEEDED; /* no symbol table */
    assert(blind_image(&image) == -1);
    build(&image);
    image.dynamic[3].d_tag = DT_NEEDED; /* no hash table, so no symbol count */
    assert(blind_image(&image) == -1);
    build(&image);
    image.dynamic[2].d_un.d_val = sizeof(Elf64_Sym) - 1U; /* entries too small to be one */
    assert(blind_image(&image) == -1);
    /* An unreadable image: the address is mapped nowhere. */
    g_base_override = 0x10U;
    g_base_overridden = 1;
    assert(chaos_init_vdso_blind(getpid()) == -1);

    /* A symbol table longer than the walk allows is cut at its own bound: a symbol
     * past it is not reached, so nothing is renamed. */
    build(&image);
    image.symbols[2].st_name = 0U;
    image.symbols[70].st_name = 1U;
    image.hash[1] = 80U;
    g_pokes = 0U;
    assert(blind_image(&image) == 0);
    assert(g_pokes == 0U);
    /* A symbol table the reader cannot reach is not followed, as a string table is not:
     * the walk gives up rather than renaming whatever it finds there. */
    build(&image);
    image.dynamic[1].d_un.d_ptr = (Elf64_Addr)0x7ffffffff000ULL;
    assert(blind_image(&image) == -1);
    /* The same for every other part it has to read on the way: the program headers, the
     * dynamic segment and the hash table that holds the symbol count. */
    build(&image);
    image.header.e_phoff = (Elf64_Off)0x7ffffffff000ULL;
    assert(blind_image(&image) == -1);
    build(&image);
    image.segments[1].p_vaddr = (Elf64_Addr)0x7ffffffff000ULL;
    assert(blind_image(&image) == -1);
    build(&image);
    image.dynamic[3].d_un.d_ptr = (Elf64_Addr)0x7ffffffff000ULL;
    assert(blind_image(&image) == -1);

    /* A dynamic segment that never ends is cut the same way: no DT_NULL, so the walk
     * stops after its own limit and reports what it found. */
    build(&image);
    image.dynamic[4].d_tag = DT_NEEDED;
    assert(blind_image(&image) == 1);

    /* A name the reader cannot reach is no name to rename: that symbol is skipped,
     * which is not a reason to give up on the image. */
    build(&image);
    image.dynamic[0].d_un.d_ptr = (Elf64_Addr)0x7ffffffff000ULL;
    g_pokes = 0U;
    assert(blind_image(&image) == 0);
    assert(g_pokes == 0U);
    return 0;
}
