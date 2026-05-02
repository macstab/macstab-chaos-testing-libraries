/**
 * @file fuzz_process_config.c
 * @brief libFuzzer harness for chaos_process_config_parse_line().
 *
 * Build:  make fuzz
 * Run:    ./build-fuzz/fuzz_process_config -runs=60 -max_len=512
 */

#include "../support/test_process_support.h"

CHAOS_PROCESS_DEFINE_TEST_GLOBALS();

#include "../../src/process/chaos_process_config.c"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char buf[4096];
    chaos_process_rule_t rule;

    if (size == 0 || size >= sizeof(buf))
        return 0;

    memcpy(buf, data, size);
    buf[size] = '\0';

    (void)chaos_process_config_parse_line(buf, &rule);
    return 0;
}
