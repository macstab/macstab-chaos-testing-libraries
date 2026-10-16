/**
 * @file locale_probe.c
 * @brief Runtime probe: rules are read the same under a locale with a decimal comma.
 *
 * Usage: locale_probe   (under LD_PRELOAD of libchaos-io, with de_DE.UTF-8 installed)
 *
 * Switches to de_DE.UTF-8 as a JVM does from LANG, writes the rule
 * `/tmp/locale-data:open:EIO:1.0`, and opens a file it covers. Prints "EIO" when
 * the rule was applied, "ok" when it was not, "no-locale" when the locale is missing.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    struct timespec delay = {0, 5000000L};
    FILE *file;
    int fd;

    if (setlocale(LC_ALL, "de_DE.UTF-8") == NULL)
    {
        (void)puts("no-locale");
        return 0;
    }
    (void)mkdir("/tmp/locale-data", 0700);
    file = fopen("/tmp/.chaos-io.conf.staging", "w");
    if (file == NULL || fputs("/tmp/locale-data:open:EIO:1.0\n", file) < 0 || fclose(file) != 0 ||
        rename("/tmp/.chaos-io.conf.staging", "/tmp/.chaos-io.conf") != 0)
    {
        perror("rules");
        return 2;
    }
    /* Past the library's next look at the rule file; a raw call no rule can fault. */
    (void)syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &delay, NULL);
    errno = 0;
    fd = open("/tmp/locale-data/file", O_RDONLY | O_CREAT, 0600);
    (void)puts(fd < 0 && errno == EIO ? "EIO" : "ok");
    return 0;
}
