/**
 * @file fuzz_io_config.c
 * @brief libFuzzer harness for chaos_io_config_parse_line().
 *
 * Build:
 *   make fuzz          (uses clang -fsanitize=fuzzer,address)
 *
 * Run:
 *   ./build-fuzz/fuzz_io_config -runs=60 -max_len=512
 *   ./build-fuzz/fuzz_io_config corpus/io/         # with seed corpus
 *
 * Any crash, ASAN report, or UBSAN report indicates a bug in parse_line.
 * Blank/comment lines return 0; syntactically invalid lines return -1;
 * valid lines return 1 and populate the rule struct.  None of these paths
 * should ever abort or access out-of-bounds memory.
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
