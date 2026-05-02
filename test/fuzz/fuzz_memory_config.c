/**
 * @file fuzz_memory_config.c
 * @brief libFuzzer harness for chaos_memory_config_parse_line().
 *
 * Build:  make fuzz
 * Run:    ./build-fuzz/fuzz_memory_config -runs=60 -max_len=512
 */

#include "../support/test_memory_support.h"

CHAOS_MEMORY_DEFINE_TEST_GLOBALS();

#include "../../src/memory/chaos_memory_config.c"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char buf[4096];
    chaos_memory_rule_t rule;

    if (size == 0 || size >= sizeof(buf))
        return 0;

    memcpy(buf, data, size);
    buf[size] = '\0';

    (void)chaos_memory_config_parse_line(buf, &rule);
    return 0;
}
