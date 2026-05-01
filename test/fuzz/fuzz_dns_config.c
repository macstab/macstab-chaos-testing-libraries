/**
 * @file fuzz_dns_config.c
 * @brief libFuzzer harness for chaos_dns_config_parse_line().
 *
 * Build:  make fuzz
 * Run:    ./build-fuzz/fuzz_dns_config -runs=60 -max_len=512
 */

#include "../support/test_dns_support.h"

CHAOS_DNS_DEFINE_TEST_GLOBALS();

#include "../../src/dns/chaos_dns_config.c"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char buf[4096];
    chaos_dns_rule_t rule;

    if (size == 0 || size >= sizeof(buf))
        return 0;

    memcpy(buf, data, size);
    buf[size] = '\0';

    (void)chaos_dns_config_parse_line(buf, &rule);
    return 0;
}
