/**
 * @file locale_probe.c
 * @brief Proves that libchaos-io parses a rule file the same way after the program switched to
 *        a locale with a decimal comma.
 *
 * @details
 * A JVM calls setlocale() from LANG. Under de_DE.UTF-8, strtod() reads "1.0" as 1 followed by
 * junk, so a parser using locale-dependent conversion would reject or misread every
 * probability. The probe switches to de_DE.UTF-8, installs `/tmp/locale-data:open:EIO:1.0`
 * atomically, sleeps 5 ms (raw clock_nanosleep, past the 1 ms rule-file check throttle) and
 * opens a covered file.
 *
 * Prints "EIO" when the rule applied, "ok" when it did not, "no-locale" when de_DE.UTF-8 is
 * not installed. Usage: locale_probe, under LD_PRELOAD of libchaos-io; run by test_status.sh on
 * glibc, which judges the output.
 *
 * Exit: 0 after printing; 2 when the rule file cannot be written.
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
    /* 5 ms outlasts the 1 ms check throttle; a raw system call so no rule can fault it. */
    (void)syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &delay, NULL);
    errno = 0;
    fd = open("/tmp/locale-data/file", O_RDONLY | O_CREAT, 0600);
    (void)puts(fd < 0 && errno == EIO ? "EIO" : "ok");
    return 0;
}
