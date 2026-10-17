/**
 * @file fuzz_io_config.c
 * @brief libFuzzer harness for chaos_io_config_parse_line(), the libchaos-io rule parser.
 *
 * @details Proves that no byte sequence fed to the parser as a rule-file line can crash it or
 * make it touch memory out of bounds (AddressSanitizer; UBSan is not enabled). The parser runs
 * inside every process that loads the library, on each reload, so a parser fault takes down
 * the application.
 *
 * Contract exercised: 0 for a blank or comment line, -1 for an invalid line, 1 for a valid
 * rule written to `*rule`. The harness ignores the return value; the finding is any crash,
 * AddressSanitizer report or libFuzzer timeout/OOM.
 *
 * The production translation unit is #included so its static helpers are compiled with
 * sanitizer instrumentation; CHAOS_IO_DEFINE_TEST_GLOBALS() supplies the globals
 * the library normally defines, so no real function is resolved and no wrapper is linked.
 *
 * Input shaping: inputs of 0 bytes or >= 4096 bytes are skipped; the rest are copied into a
 * NUL-terminated stack buffer because the parser tokenises its argument in place. An embedded
 * NUL byte ends the line early, exactly as it would in a C-string read from the rule file.
 *
 * Prerequisites: clang with -fsanitize=fuzzer,address (`FUZZ_CC`, default clang).
 * Build:  make fuzz           (binaries in build-fuzz/)
 * Run:    ./build-fuzz/fuzz_io_config -runs=60 -max_len=512 [corpus_dir]
 * Exit:   0 when the run completes without a finding; non-zero with a crash artefact
 *         (crash-<sha1>) written to the working directory otherwise.
 */

#include "../support/test_support.h"

CHAOS_IO_DEFINE_TEST_GLOBALS();

#include "../../src/config/chaos_io_config.c"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char buf[4096];
    chaos_io_rule_t rule;

    if (size == 0 || size >= sizeof(buf))
        return 0;

    memcpy(buf, data, size);
    buf[size] = '\0';

    (void)chaos_io_config_parse_line(buf, &rule);
    return 0;
}
