#ifndef CHAOS_IO_WRAPPERS_H
#define CHAOS_IO_WRAPPERS_H

/*
 * Internal helper declarations shared between wrapper compilation units.
 *
 * The library keeps exported interposers split across several `.c` files, but
 * fd-backed wrappers still need one common rule-selection entry point so they
 * all interpret config and fd-cache state the same way.
 */

#include "chaos_io_config.h"

int chaos_io_match_fd_rule(int fd, chaos_io_operation_t operation, chaos_io_rule_t *rule);
int chaos_io_resolve_at_path(
    int dirfd, const char *path, char *resolved_path, size_t resolved_path_size
);

#endif
