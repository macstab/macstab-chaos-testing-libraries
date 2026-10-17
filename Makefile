# Build, test and release entry point for the six libchaos-<lib> LD_PRELOAD libraries and the
# static chaos-init supervisor (SECCOMP mode).
#
# Outputs:
#   build/libchaos-<lib>.so            native shared library (Linux hosts only)
#   build/chaos-init                   native static supervisor
#   build/test_*                       unit-test executables, one translation unit each
#   dist/libchaos-<lib>-<libc>-<arch>.so   release variants (glibc|musl x amd64|arm64)
#   dist/chaos-init-<arch>             release supervisor, one per architecture
#
# Every toolchain variable below is `?=`: CI and the sanitizer/coverage jobs override CC, CFLAGS,
# LDFLAGS and BUILD_DIR on the command line instead of editing this file.
# Unit tests build and run on macOS too; shared libraries and chaos-init need a Linux host.
UNAME_S := $(shell uname -s)
HOST_ARCH := $(shell uname -m)

# Per-variant compilers. The defaults are the Debian cross-compiler names; docker/Dockerfile.build
# and the matrix workflow override them with the native `gcc`/`musl-gcc` of the build image.
CC ?= cc
GLIBC_AMD64_CC ?= x86_64-linux-gnu-gcc
GLIBC_ARM64_CC ?= aarch64-linux-gnu-gcc
MUSL_AMD64_CC ?= musl-gcc
MUSL_ARM64_CC ?= aarch64-linux-musl-gcc

# Strict C99 with -Werror on every build, including tests. -Os optimises for size: the objects are
# mapped into every process they are preloaded into. -ldl provides dlsym(RTLD_NEXT) on glibc
# before 2.34, where it is not yet part of libc.so.6.
CPPFLAGS ?= -D_GNU_SOURCE -Isrc -Isrc/common -Isrc/core -Isrc/config -Isrc/effects -Isrc/wrappers -Isrc/net -Isrc/dns -Isrc/time -Isrc/process -Isrc/memory
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic -Os
LDFLAGS ?=
LDLIBS ?= -ldl

# Flags for the injected shared objects only (tests use plain CFLAGS):
#   -fvisibility=hidden     only symbols marked for export (the wrappers) enter the dynamic
#                           symbol table, so internal helpers never interpose on the host process
#   -ffunction-sections, -fdata-sections + --gc-sections   drop unreferenced code and data
#   -fno-unwind-tables, -fno-asynchronous-unwind-tables, -fomit-frame-pointer, -fno-ident
#                           no .eh_frame or .comment payload; smaller object
#   -fno-stack-protector    no canary checks, so no __stack_chk_fail import
#   --build-id=none, --strip-all   no build-id note, no symbol table beyond .dynsym
#   max-page-size=4096, common-page-size=4096   4 KiB segment alignment instead of the 64 KiB
#                           aarch64 default, which pads the file; segments then assume 4 KiB pages
SHARED_CFLAGS := $(CPPFLAGS) $(CFLAGS) -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -fomit-frame-pointer -fno-ident -fno-stack-protector
SHARED_LDFLAGS := $(LDFLAGS) -Wl,--gc-sections -Wl,--build-id=none -Wl,--strip-all -Wl,-z,max-page-size=4096 -Wl,-z,common-page-size=4096

BUILD_DIR := build
DIST_DIR := dist
SRC_DIR := src
TEST_DIR := test
SRC_COMMON_DIR := $(SRC_DIR)/common
# src/common headers are included by every library, chaos-init and every test, so each of those
# targets depends on all of them: touching one rebuilds everything.
COMMON_HDRS := $(wildcard $(SRC_COMMON_DIR)/*.h)
SRC_CORE_DIR := $(SRC_DIR)/core
SRC_CONFIG_DIR := $(SRC_DIR)/config
SRC_EFFECTS_DIR := $(SRC_DIR)/effects
SRC_WRAPPERS_DIR := $(SRC_DIR)/wrappers
SRC_NET_DIR := $(SRC_DIR)/net
SRC_DNS_DIR := $(SRC_DIR)/dns
SRC_TIME_DIR := $(SRC_DIR)/time
SRC_PROCESS_DIR := $(SRC_DIR)/process
SRC_MEMORY_DIR := $(SRC_DIR)/memory
SRC_INIT_DIR := $(SRC_DIR)/init
TEST_UNIT_DIR := $(TEST_DIR)/unit
TEST_SUPPORT_DIR := $(TEST_DIR)/support
TEST_RUNTIME_DIR := $(TEST_DIR)/runtime
DOCKER_DIR := docker
TEST_SUPPORT_HDRS := \
	$(TEST_SUPPORT_DIR)/test_support.h \
	$(TEST_SUPPORT_DIR)/test_chaos_io_harness.h \
	$(TEST_SUPPORT_DIR)/test_net_support.h \
	$(TEST_SUPPORT_DIR)/test_dns_support.h \
	$(TEST_SUPPORT_DIR)/test_time_support.h \
	$(TEST_SUPPORT_DIR)/test_memory_support.h \
	$(TEST_SUPPORT_DIR)/test_process_support.h

# LIB_NAMES drives define_lib_rules below: adding a library means adding its name here plus
# LIB_SRCS_<lib>, LIB_HDRS_<lib>, NATIVE_<lib>_LIB and the four DIST_<variant>_<lib>_LIB names.
LIB_NAMES := io net dns time process memory
DIST_VARIANTS := glibc-amd64 glibc-arm64 musl-amd64 musl-arm64

# Per-library sources and private headers. Each library links into its own .so from only its own
# sources; the headers are listed so that editing one rebuilds that library.
LIB_SRCS_io := \
	$(SRC_CORE_DIR)/chaos_io.c \
	$(SRC_WRAPPERS_DIR)/chaos_io_open.c \
	$(SRC_WRAPPERS_DIR)/chaos_io_rw.c \
	$(SRC_WRAPPERS_DIR)/chaos_io_fsops.c \
	$(SRC_WRAPPERS_DIR)/chaos_io_sync.c \
	$(SRC_WRAPPERS_DIR)/chaos_io_stdio.c \
	$(SRC_EFFECTS_DIR)/chaos_io_actions.c \
	$(SRC_CONFIG_DIR)/chaos_io_config.c \
	$(SRC_CONFIG_DIR)/chaos_io_fdcache.c

LIB_HDRS_io := \
	$(SRC_EFFECTS_DIR)/chaos_io_actions.h \
	$(SRC_CONFIG_DIR)/chaos_io_config.h \
	$(SRC_CONFIG_DIR)/chaos_io_fdcache.h \
	$(SRC_CORE_DIR)/chaos_io_internal.h \
	$(SRC_CORE_DIR)/chaos_io_wrappers.h

LIB_SRCS_net := \
	$(SRC_NET_DIR)/chaos_net.c \
	$(SRC_NET_DIR)/chaos_net_actions.c \
	$(SRC_NET_DIR)/chaos_net_config.c \
	$(SRC_NET_DIR)/chaos_net_endpoint.c \
	$(SRC_NET_DIR)/chaos_net_extra.c \
	$(SRC_NET_DIR)/chaos_net_socket.c \
	$(SRC_NET_DIR)/chaos_net_wait.c

LIB_SRCS_dns := \
	$(SRC_DNS_DIR)/chaos_dns.c \
	$(SRC_DNS_DIR)/chaos_dns_actions.c \
	$(SRC_DNS_DIR)/chaos_dns_config.c \
	$(SRC_DNS_DIR)/chaos_dns_lookup.c \
	$(SRC_DNS_DIR)/chaos_dns_owned.c

LIB_SRCS_time := \
	$(SRC_TIME_DIR)/chaos_time.c \
	$(SRC_TIME_DIR)/chaos_time_actions.c \
	$(SRC_TIME_DIR)/chaos_time_config.c \
	$(SRC_TIME_DIR)/chaos_time_hooks.c

LIB_SRCS_process := \
	$(SRC_PROCESS_DIR)/chaos_process.c \
	$(SRC_PROCESS_DIR)/chaos_process_actions.c \
	$(SRC_PROCESS_DIR)/chaos_process_config.c \
	$(SRC_PROCESS_DIR)/chaos_process_hooks.c

LIB_SRCS_memory := \
	$(SRC_MEMORY_DIR)/chaos_memory.c \
	$(SRC_MEMORY_DIR)/chaos_memory_actions.c \
	$(SRC_MEMORY_DIR)/chaos_memory_config.c \
	$(SRC_MEMORY_DIR)/chaos_memory_hooks.c

LIB_HDRS_net := \
	$(SRC_NET_DIR)/chaos_net_internal.h \
	$(SRC_NET_DIR)/chaos_net_config.h \
	$(SRC_NET_DIR)/chaos_net_actions.h \
	$(SRC_NET_DIR)/chaos_net_endpoint.h
LIB_HDRS_dns := \
	$(SRC_DNS_DIR)/chaos_dns_internal.h \
	$(SRC_DNS_DIR)/chaos_dns_config.h \
	$(SRC_DNS_DIR)/chaos_dns_actions.h \
	$(SRC_DNS_DIR)/chaos_dns_owned.h
LIB_HDRS_time := \
	$(SRC_TIME_DIR)/chaos_time_internal.h \
	$(SRC_TIME_DIR)/chaos_time_config.h \
	$(SRC_TIME_DIR)/chaos_time_actions.h
LIB_HDRS_process := \
	$(SRC_PROCESS_DIR)/chaos_process_internal.h \
	$(SRC_PROCESS_DIR)/chaos_process_config.h \
	$(SRC_PROCESS_DIR)/chaos_process_actions.h
LIB_HDRS_memory := \
	$(SRC_MEMORY_DIR)/chaos_memory_internal.h \
	$(SRC_MEMORY_DIR)/chaos_memory_config.h \
	$(SRC_MEMORY_DIR)/chaos_memory_actions.h

# chaos-init: the static seccomp-user-notify supervisor of SECCOMP mode. Linked with -static, so
# one binary per architecture runs in glibc images, musl images and images without any libc.
# It has no copy of the rule engine: chaos_init_<lib>.c #include the libraries' config and action
# sources directly (as the unit tests do), so LD_PRELOAD mode and SECCOMP mode parse and apply
# rules from one source. That is why INIT_HDRS lists those .c files as prerequisites.
# Only io, net, memory and process are wired in; dns and time have no SECCOMP-mode backend.
INIT_SRCS := \
	$(SRC_INIT_DIR)/chaos_init.c \
	$(SRC_INIT_DIR)/chaos_init_core.c \
	$(SRC_INIT_DIR)/chaos_init_delay.c \
	$(SRC_INIT_DIR)/chaos_init_proc.c \
	$(SRC_INIT_DIR)/chaos_init_tracee.c \
	$(SRC_INIT_DIR)/chaos_init_io.c \
	$(SRC_INIT_DIR)/chaos_init_net.c \
	$(SRC_INIT_DIR)/chaos_init_memory.c \
	$(SRC_INIT_DIR)/chaos_init_process.c
INIT_HDRS := \
	$(SRC_INIT_DIR)/chaos_init_core.h \
	$(SRC_INIT_DIR)/chaos_init_call.h \
	$(SRC_INIT_DIR)/chaos_init_delay.h \
	$(SRC_INIT_DIR)/chaos_init_proc.h \
	$(SRC_INIT_DIR)/chaos_init_tracee.h \
	$(SRC_INIT_DIR)/chaos_init_io.h \
	$(SRC_INIT_DIR)/chaos_init_net.h \
	$(SRC_INIT_DIR)/chaos_init_memory.h \
	$(SRC_INIT_DIR)/chaos_init_process.h \
	$(SRC_COMMON_DIR)/chaos_status.h \
	$(SRC_COMMON_DIR)/chaos_hits.h \
	$(SRC_CONFIG_DIR)/chaos_io_config.c \
	$(SRC_EFFECTS_DIR)/chaos_io_actions.c \
	$(SRC_NET_DIR)/chaos_net_config.c \
	$(SRC_NET_DIR)/chaos_net_endpoint.c \
	$(SRC_NET_DIR)/chaos_net_actions.c \
	$(SRC_MEMORY_DIR)/chaos_memory_config.c \
	$(SRC_MEMORY_DIR)/chaos_memory_actions.c \
	$(SRC_PROCESS_DIR)/chaos_process_config.c \
	$(SRC_PROCESS_DIR)/chaos_process_actions.c \
	$(LIB_HDRS_io) \
	$(LIB_HDRS_net) \
	$(LIB_HDRS_memory) \
	$(LIB_HDRS_process)
INIT_CC ?= $(CC)
INIT_CFLAGS := $(CPPFLAGS) -I$(SRC_INIT_DIR) $(CFLAGS) -static
INIT_LDFLAGS := $(LDFLAGS) -Wl,--strip-all
NATIVE_INIT := $(BUILD_DIR)/chaos-init

# Output names. Native builds are unsuffixed in build/; release variants carry <libc>-<arch> so
# all 24 objects can live side by side in dist/ and in the GitHub release.
NATIVE_io_LIB := $(BUILD_DIR)/libchaos-io.so
NATIVE_net_LIB := $(BUILD_DIR)/libchaos-net.so
NATIVE_dns_LIB := $(BUILD_DIR)/libchaos-dns.so
NATIVE_time_LIB := $(BUILD_DIR)/libchaos-time.so
NATIVE_process_LIB := $(BUILD_DIR)/libchaos-process.so
NATIVE_memory_LIB := $(BUILD_DIR)/libchaos-memory.so

DIST_glibc-amd64_io_LIB := $(DIST_DIR)/libchaos-io-glibc-amd64.so
DIST_glibc-amd64_net_LIB := $(DIST_DIR)/libchaos-net-glibc-amd64.so
DIST_glibc-amd64_dns_LIB := $(DIST_DIR)/libchaos-dns-glibc-amd64.so
DIST_glibc-amd64_time_LIB := $(DIST_DIR)/libchaos-time-glibc-amd64.so
DIST_glibc-amd64_process_LIB := $(DIST_DIR)/libchaos-process-glibc-amd64.so
DIST_glibc-amd64_memory_LIB := $(DIST_DIR)/libchaos-memory-glibc-amd64.so

DIST_glibc-arm64_io_LIB := $(DIST_DIR)/libchaos-io-glibc-arm64.so
DIST_glibc-arm64_net_LIB := $(DIST_DIR)/libchaos-net-glibc-arm64.so
DIST_glibc-arm64_dns_LIB := $(DIST_DIR)/libchaos-dns-glibc-arm64.so
DIST_glibc-arm64_time_LIB := $(DIST_DIR)/libchaos-time-glibc-arm64.so
DIST_glibc-arm64_process_LIB := $(DIST_DIR)/libchaos-process-glibc-arm64.so
DIST_glibc-arm64_memory_LIB := $(DIST_DIR)/libchaos-memory-glibc-arm64.so

DIST_musl-amd64_io_LIB := $(DIST_DIR)/libchaos-io-musl-amd64.so
DIST_musl-amd64_net_LIB := $(DIST_DIR)/libchaos-net-musl-amd64.so
DIST_musl-amd64_dns_LIB := $(DIST_DIR)/libchaos-dns-musl-amd64.so
DIST_musl-amd64_time_LIB := $(DIST_DIR)/libchaos-time-musl-amd64.so
DIST_musl-amd64_process_LIB := $(DIST_DIR)/libchaos-process-musl-amd64.so
DIST_musl-amd64_memory_LIB := $(DIST_DIR)/libchaos-memory-musl-amd64.so

DIST_musl-arm64_io_LIB := $(DIST_DIR)/libchaos-io-musl-arm64.so
DIST_musl-arm64_net_LIB := $(DIST_DIR)/libchaos-net-musl-arm64.so
DIST_musl-arm64_dns_LIB := $(DIST_DIR)/libchaos-dns-musl-arm64.so
DIST_musl-arm64_time_LIB := $(DIST_DIR)/libchaos-time-musl-arm64.so
DIST_musl-arm64_process_LIB := $(DIST_DIR)/libchaos-process-musl-arm64.so
DIST_musl-arm64_memory_LIB := $(DIST_DIR)/libchaos-memory-musl-arm64.so

NATIVE_LIBS := $(foreach lib,$(LIB_NAMES),$(NATIVE_$(lib)_LIB))
GLIBC_AMD64_DISTS := $(foreach lib,$(LIB_NAMES),$(DIST_glibc-amd64_$(lib)_LIB))
GLIBC_ARM64_DISTS := $(foreach lib,$(LIB_NAMES),$(DIST_glibc-arm64_$(lib)_LIB))
MUSL_AMD64_DISTS := $(foreach lib,$(LIB_NAMES),$(DIST_musl-amd64_$(lib)_LIB))
MUSL_ARM64_DISTS := $(foreach lib,$(LIB_NAMES),$(DIST_musl-arm64_$(lib)_LIB))

# Unit-test executables. Each is built from one file, test/unit/test_<name>.c, which #includes
# the sources under test; see the $(BUILD_DIR)/test_% rule.
CONFIG_TEST := $(BUILD_DIR)/test_config_parse
ACTIONS_TEST := $(BUILD_DIR)/test_actions
FDCACHE_TEST := $(BUILD_DIR)/test_fdcache
CHAOS_IO_TEST := $(BUILD_DIR)/test_chaos_io
NET_ACTIONS_TEST := $(BUILD_DIR)/test_net_actions
NET_ENDPOINT_TEST := $(BUILD_DIR)/test_net_endpoint
NET_CONFIG_TEST := $(BUILD_DIR)/test_net_config
NET_RUNTIME_TEST := $(BUILD_DIR)/test_net_runtime
CHAOS_NET_TEST := $(BUILD_DIR)/test_chaos_net
DNS_ACTIONS_TEST := $(BUILD_DIR)/test_dns_actions
DNS_CONFIG_TEST := $(BUILD_DIR)/test_dns_config
DNS_RUNTIME_TEST := $(BUILD_DIR)/test_dns_runtime
DNS_OWNED_TEST := $(BUILD_DIR)/test_dns_owned
CHAOS_DNS_TEST := $(BUILD_DIR)/test_chaos_dns
TIME_ACTIONS_TEST := $(BUILD_DIR)/test_time_actions
TIME_CONFIG_TEST := $(BUILD_DIR)/test_time_config
TIME_RUNTIME_TEST := $(BUILD_DIR)/test_time_runtime
CHAOS_TIME_TEST := $(BUILD_DIR)/test_chaos_time
MEMORY_ACTIONS_TEST := $(BUILD_DIR)/test_memory_actions
MEMORY_CONFIG_TEST := $(BUILD_DIR)/test_memory_config
MEMORY_RUNTIME_TEST := $(BUILD_DIR)/test_memory_runtime
CHAOS_MEMORY_TEST := $(BUILD_DIR)/test_chaos_memory
PROCESS_ACTIONS_TEST := $(BUILD_DIR)/test_process_actions
PROCESS_CONFIG_TEST := $(BUILD_DIR)/test_process_config
PROCESS_RUNTIME_TEST := $(BUILD_DIR)/test_process_runtime
CHAOS_PROCESS_TEST := $(BUILD_DIR)/test_chaos_process
PROPTEST_TEST := $(BUILD_DIR)/test_config_proptest
CHAOS_INIT_TEST := $(BUILD_DIR)/test_chaos_init
CHAOS_INIT_IO_TEST := $(BUILD_DIR)/test_chaos_init_io
CHAOS_INIT_NET_TEST := $(BUILD_DIR)/test_chaos_init_net
CHAOS_INIT_MEMORY_TEST := $(BUILD_DIR)/test_chaos_init_memory
CHAOS_INIT_PROCESS_TEST := $(BUILD_DIR)/test_chaos_init_process
COMMON_TEST := $(BUILD_DIR)/test_common
UNIT_TESTS := $(CONFIG_TEST) $(ACTIONS_TEST) $(FDCACHE_TEST) $(CHAOS_IO_TEST) \
	$(NET_ACTIONS_TEST) $(NET_ENDPOINT_TEST) $(NET_CONFIG_TEST) $(NET_RUNTIME_TEST) $(CHAOS_NET_TEST) \
	$(DNS_ACTIONS_TEST) $(DNS_CONFIG_TEST) $(DNS_RUNTIME_TEST) $(DNS_OWNED_TEST) $(CHAOS_DNS_TEST) \
	$(TIME_ACTIONS_TEST) $(TIME_CONFIG_TEST) $(TIME_RUNTIME_TEST) $(CHAOS_TIME_TEST) \
	$(MEMORY_ACTIONS_TEST) $(MEMORY_CONFIG_TEST) $(MEMORY_RUNTIME_TEST) $(CHAOS_MEMORY_TEST) \
	$(PROCESS_ACTIONS_TEST) $(PROCESS_CONFIG_TEST) $(PROCESS_RUNTIME_TEST) $(CHAOS_PROCESS_TEST) \
	$(PROPTEST_TEST) $(CHAOS_INIT_TEST) $(CHAOS_INIT_IO_TEST) \
	$(CHAOS_INIT_NET_TEST) $(CHAOS_INIT_MEMORY_TEST) $(CHAOS_INIT_PROCESS_TEST) $(COMMON_TEST)
# Runtime suites run by `make test` against the native build on the host. Several start Docker
# containers; a suite that cannot run exits with ${CHAOS_SKIP_EXIT:-0}, i.e. it passes as
# skipped unless the caller sets CHAOS_SKIP_EXIT=1 (as CI does). ci.yml keeps its own copy of
# this list.
HOST_RUNTIME_TESTS := \
	$(TEST_RUNTIME_DIR)/test_integration.sh \
	$(TEST_RUNTIME_DIR)/test_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_alpine.sh \
	$(TEST_RUNTIME_DIR)/test_net_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_net_alpine.sh \
	$(TEST_RUNTIME_DIR)/test_dns_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_dns_alpine.sh \
	$(TEST_RUNTIME_DIR)/test_time_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_time_alpine.sh \
	$(TEST_RUNTIME_DIR)/test_memory_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_memory_alpine.sh \
	$(TEST_RUNTIME_DIR)/test_process_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_process_alpine.sh \
	$(TEST_RUNTIME_DIR)/test_errno_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_variants_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_sharing_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_baseline_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_isolation_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_path_forms.sh \
	$(TEST_RUNTIME_DIR)/test_status.sh \
	$(TEST_RUNTIME_DIR)/test_hits.sh \
	$(TEST_RUNTIME_DIR)/test_reload.sh \
	$(TEST_RUNTIME_DIR)/test_fork.sh \
	$(TEST_RUNTIME_DIR)/test_init.sh \
	$(TEST_RUNTIME_DIR)/test_mptcp.sh \
	$(TEST_RUNTIME_DIR)/test_seccomp.sh \
	$(TEST_RUNTIME_DIR)/test_stdio.sh
# The per-libc container suites, run by `make test-matrix` once per platform argument
# (linux/amd64, linux/arm64; the foreign one runs under emulation).
MATRIX_RUNTIME_TESTS := \
	$(TEST_RUNTIME_DIR)/test_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_alpine.sh \
	$(TEST_RUNTIME_DIR)/test_net_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_net_alpine.sh \
	$(TEST_RUNTIME_DIR)/test_dns_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_dns_alpine.sh \
	$(TEST_RUNTIME_DIR)/test_time_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_time_alpine.sh \
	$(TEST_RUNTIME_DIR)/test_memory_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_memory_alpine.sh \
	$(TEST_RUNTIME_DIR)/test_process_glibc.sh \
	$(TEST_RUNTIME_DIR)/test_process_alpine.sh

.PHONY: all check clean coverage native test unit docker-build-all fmt fmt-check qa test-matrix \
	fuzz fuzz-clean verify-docs \
	cross-glibc-amd64 cross-glibc-arm64 cross-musl-amd64 cross-musl-arm64 \
	native-init cross-init-amd64 cross-init-arm64 \
	$(foreach lib,$(LIB_NAMES),native-$(lib)) \
	$(foreach lib,$(LIB_NAMES),cross-glibc-amd64-$(lib)) \
	$(foreach lib,$(LIB_NAMES),cross-glibc-arm64-$(lib)) \
	$(foreach lib,$(LIB_NAMES),cross-musl-amd64-$(lib)) \
	$(foreach lib,$(LIB_NAMES),cross-musl-arm64-$(lib))

# Default goal: build and run the unit tests; on Linux also build the six native libraries.
all: unit
ifeq ($(UNAME_S),Linux)
all: native
endif

# The six libraries for the host toolchain, in build/. Fails with a message on non-Linux hosts.
native: $(NATIVE_LIBS)

# Builds every unit test, then runs them in a fixed order; make stops at the first failing test.
unit: $(UNIT_TESTS)
	./$(CONFIG_TEST)
	./$(ACTIONS_TEST)
	./$(FDCACHE_TEST)
	./$(CHAOS_IO_TEST)
	./$(NET_ACTIONS_TEST)
	./$(NET_ENDPOINT_TEST)
	./$(NET_CONFIG_TEST)
	./$(NET_RUNTIME_TEST)
	./$(CHAOS_NET_TEST)
	./$(DNS_ACTIONS_TEST)
	./$(DNS_CONFIG_TEST)
	./$(DNS_RUNTIME_TEST)
	./$(DNS_OWNED_TEST)
	./$(CHAOS_DNS_TEST)
	./$(TIME_ACTIONS_TEST)
	./$(TIME_CONFIG_TEST)
	./$(TIME_RUNTIME_TEST)
	./$(CHAOS_TIME_TEST)
	./$(MEMORY_ACTIONS_TEST)
	./$(MEMORY_CONFIG_TEST)
	./$(MEMORY_RUNTIME_TEST)
	./$(CHAOS_MEMORY_TEST)
	./$(PROCESS_ACTIONS_TEST)
	./$(PROCESS_CONFIG_TEST)
	./$(PROCESS_RUNTIME_TEST)
	./$(CHAOS_PROCESS_TEST)
	./$(PROPTEST_TEST)
	./$(CHAOS_INIT_TEST)
	./$(CHAOS_INIT_IO_TEST)
	./$(CHAOS_INIT_NET_TEST)
	./$(CHAOS_INIT_MEMORY_TEST)
	./$(CHAOS_INIT_PROCESS_TEST)
	./$(COMMON_TEST)

# Coverage gate: check_coverage.sh rebuilds the unit tests with --coverage -O0 in
# $(BUILD_DIR)-coverage, runs them and fails if any listed source file falls below its per-file
# line-coverage threshold (100.00 % for most files).
coverage:
	BUILD_DIR=$(BUILD_DIR)-coverage CC="$(CC)" CPPFLAGS='$(CPPFLAGS)' CFLAGS='$(CFLAGS)' ./$(TEST_RUNTIME_DIR)/check_coverage.sh

# clang-format every .c/.h under src/ and test/ in place (fmt) or fail on any deviation
# (fmt-check). The style is .clang-format at the repository root.
fmt:
	sh ./$(TEST_RUNTIME_DIR)/check_format.sh --write

fmt-check:
	sh ./$(TEST_RUNTIME_DIR)/check_format.sh --check

# Full local gate: formatting, coverage, unit tests, native build and the host runtime suites.
check: fmt-check coverage test

qa: check

# Unit tests, the native libraries (Linux) and every HOST_RUNTIME_TESTS suite.
# The loop does not stop at a failing suite: the recipe's exit status is the last suite's, so
# read the output (CI runs the same list under `set -eu`).
test: unit
ifeq ($(UNAME_S),Linux)
test: native
endif
	@for script in $(HOST_RUNTIME_TESTS); do \
		sh $$script; \
	done

# Every MATRIX_RUNTIME_TESTS suite on linux/amd64 and linux/arm64. Same exit-status caveat as
# `test`: only the last suite's result reaches make.
test-matrix:
	@for platform in linux/amd64 linux/arm64; do \
		for script in $(MATRIX_RUNTIME_TESTS); do \
			sh $$script $$platform; \
		done; \
	done

# ---- ci-local ---------------------------------------------------------------
# The correctness jobs of .github/workflows/ci.yml, run inside a local Ubuntu 24.04 container
# (docker/Dockerfile.ci) so that a macOS or Windows host without clang-format or a Linux toolchain
# can gate a change before pushing. The repository is bind-mounted at /work and the container runs
# as the caller's uid:gid, so build outputs stay owned by the caller.
#
# Covered: fmt-check, unit, coverage, ASan, UBSan, scan-build. Not covered: the runtime suites
# (they need Docker inside the container) and CodeQL.
# Each job writes to its own BUILD_DIR (build-ci, build-asan, build-ubsan, build-scan) so that
# differently instrumented objects never mix.
#
# Benchmarks do not belong here: a Linux VM on a non-Linux host (HVF/qemu) exposes a virtual
# TSC, which invalidates cycle-based timing. Use .github/workflows/bench.yml on a Linux runner.

CI_LOCAL_IMAGE     := chaos-ci-local:latest
CI_LOCAL_DOCKERFILE := $(DOCKER_DIR)/Dockerfile.ci
CI_LOCAL_RUN := docker run --rm \
	--user $(shell id -u):$(shell id -g) \
	-v $(CURDIR):/work \
	-w /work \
	$(CI_LOCAL_IMAGE)

# Sanitizer builds use -O1 -g -fno-omit-frame-pointer for usable stack traces, identical to the
# sanitizers job in ci.yml.
CI_LOCAL_SAN_CFLAGS := -std=c99 -Wall -Wextra -Werror -pedantic -O1 -g -fno-omit-frame-pointer

.PHONY: ci-local ci-local-image ci-local-shell ci-local-fmt ci-local-unit \
	ci-local-coverage ci-local-asan ci-local-ubsan ci-local-scan ci-local-clean

# Every ci-local-* job depends on this; docker's layer cache makes repeat builds cheap.
ci-local-image:
	docker build -t $(CI_LOCAL_IMAGE) -f $(CI_LOCAL_DOCKERFILE) $(DOCKER_DIR)

ci-local-fmt: ci-local-image
	@echo ">>> [ci-local] fmt-check"
	@$(CI_LOCAL_RUN) make fmt-check

ci-local-unit: ci-local-image
	@echo ">>> [ci-local] unit tests (BUILD_DIR=build-ci)"
	@$(CI_LOCAL_RUN) make unit BUILD_DIR=build-ci

ci-local-coverage: ci-local-image
	@echo ">>> [ci-local] coverage gate"
	@$(CI_LOCAL_RUN) make coverage

# ASan with leak detection; abort_on_error turns the first report into a non-zero exit.
ci-local-asan: ci-local-image
	@echo ">>> [ci-local] ASAN unit tests"
	@$(CI_LOCAL_RUN) env \
		ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:strict_string_checks=1 \
		make unit \
			BUILD_DIR=build-asan \
			CFLAGS="$(CI_LOCAL_SAN_CFLAGS) -fsanitize=address" \
			LDFLAGS="-fsanitize=address"

# UBSan recovers and continues by default; halt_on_error makes undefined behaviour fail the run.
ci-local-ubsan: ci-local-image
	@echo ">>> [ci-local] UBSAN unit tests"
	@$(CI_LOCAL_RUN) env \
		UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
		make unit \
			BUILD_DIR=build-ubsan \
			CFLAGS="$(CI_LOCAL_SAN_CFLAGS) -fsanitize=undefined" \
			LDFLAGS="-fsanitize=undefined"

# Clang static analyzer over the native library build; --status-bugs fails on any finding.
ci-local-scan: ci-local-image
	@echo ">>> [ci-local] clang scan-build static analysis"
	@$(CI_LOCAL_RUN) scan-build --status-bugs make native BUILD_DIR=build-scan

# Interactive bash in the ci-local image, for reproducing a failing job by hand.
ci-local-shell: ci-local-image
	docker run --rm -it \
		--user $(shell id -u):$(shell id -g) \
		-v $(CURDIR):/work \
		-w /work \
		$(CI_LOCAL_IMAGE) bash

# All ci-local jobs; listed as prerequisites, so `make -j` may run them concurrently.
ci-local: ci-local-fmt ci-local-unit ci-local-coverage ci-local-asan ci-local-ubsan ci-local-scan
	@echo ">>> [ci-local] ALL PASSED"

ci-local-clean:
	rm -rf build-ci build-asan build-ubsan build-scan

# ---- release variants -------------------------------------------------------
# cross-<libc>-<arch> builds the six libraries for one variant into dist/ with
# <LIBC>_<ARCH>_CC. Despite the name, release builds do not cross-compile: docker-build-all and
# the matrix workflow run each target on a native or emulated machine of the target architecture
# and pass the local compiler (for example GLIBC_ARM64_CC=gcc).
cross-glibc-amd64: $(GLIBC_AMD64_DISTS)

cross-glibc-arm64: $(GLIBC_ARM64_DISTS)

cross-musl-amd64: $(MUSL_AMD64_DISTS)

native-init: $(NATIVE_INIT)

# Build chaos-init inside an image of the target architecture (docker/Dockerfile.build,
# MAKE_TARGET=cross-init-<arch>, INIT_CC=gcc). It must be compiled for the target, not merely
# linked for it: the system call numbers in its seccomp filter come from that architecture's
# kernel headers. The % in the pattern rule below is only the output name; the architecture is
# whatever INIT_CC targets.
cross-init-amd64: $(DIST_DIR)/chaos-init-amd64

cross-init-arm64: $(DIST_DIR)/chaos-init-arm64

$(NATIVE_INIT): $(INIT_SRCS) $(INIT_HDRS) $(COMMON_HDRS) | $(BUILD_DIR)
	$(INIT_CC) $(INIT_CFLAGS) -o $@ $(INIT_SRCS) $(INIT_LDFLAGS)

$(DIST_DIR)/chaos-init-%: $(INIT_SRCS) $(INIT_HDRS) $(COMMON_HDRS) | $(DIST_DIR)
	$(INIT_CC) $(INIT_CFLAGS) -o $@ $(INIT_SRCS) $(INIT_LDFLAGS)

cross-musl-arm64: $(MUSL_ARM64_DISTS)

# All four library variants via docker buildx, one Dockerfile.build run per variant; arm64 runs
# under QEMU on an amd64 host (release.yml installs it). Each run exports its dist/ into
# build/docker-<variant>/, from which the .so files are copied to dist/. chaos-init is not built.
# The glibc variants use gcc:10 on purpose: the toolchain's glibc sets the minimum glibc the
# libraries require, and test/runtime/check_glibc_baseline.sh rejects anything above
# GLIBC_2.17. Do not bump this image without running that check.
docker-build-all: | $(BUILD_DIR) $(DIST_DIR)
	docker buildx build --platform linux/amd64 --build-arg BASE_IMAGE=gcc:10 --build-arg MAKE_TARGET=cross-glibc-amd64 --output type=local,dest=$(BUILD_DIR)/docker-glibc-amd64 -f $(DOCKER_DIR)/Dockerfile.build .
	cp $(BUILD_DIR)/docker-glibc-amd64/*.so $(DIST_DIR)/
	docker buildx build --platform linux/arm64 --build-arg BASE_IMAGE=gcc:10 --build-arg MAKE_TARGET=cross-glibc-arm64 --output type=local,dest=$(BUILD_DIR)/docker-glibc-arm64 -f $(DOCKER_DIR)/Dockerfile.build .
	cp $(BUILD_DIR)/docker-glibc-arm64/*.so $(DIST_DIR)/
	docker buildx build --platform linux/amd64 --build-arg BASE_IMAGE=alpine:3.20 --build-arg MAKE_TARGET=cross-musl-amd64 --output type=local,dest=$(BUILD_DIR)/docker-musl-amd64 -f $(DOCKER_DIR)/Dockerfile.build .
	cp $(BUILD_DIR)/docker-musl-amd64/*.so $(DIST_DIR)/
	docker buildx build --platform linux/arm64 --build-arg BASE_IMAGE=alpine:3.20 --build-arg MAKE_TARGET=cross-musl-arm64 --output type=local,dest=$(BUILD_DIR)/docker-musl-arm64 -f $(DOCKER_DIR)/Dockerfile.build .
	cp $(BUILD_DIR)/docker-musl-arm64/*.so $(DIST_DIR)/

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

# One unit test = one translation unit: test_<name>.c #includes the sources under test, so it
# can reach static functions and replace real functions with test seams, and no library object
# is linked. The cost is coarse dependencies: every test depends on every library source and
# header, so any source edit rebuilds all tests.
$(BUILD_DIR)/test_%: $(TEST_UNIT_DIR)/test_%.c $(LIB_SRCS_io) $(LIB_HDRS_io) $(LIB_SRCS_net) $(LIB_HDRS_net) $(LIB_SRCS_dns) $(LIB_HDRS_dns) $(LIB_SRCS_time) $(LIB_HDRS_time) $(LIB_SRCS_process) $(LIB_HDRS_process) $(LIB_SRCS_memory) $(LIB_HDRS_memory) $(INIT_SRCS) $(INIT_HDRS) $(COMMON_HDRS) $(TEST_SUPPORT_HDRS) | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

# define_lib_rules(<lib>) expands to the native rule, the four release-variant rules and the
# per-library convenience targets (native-<lib>, cross-<libc>-<arch>-<lib>) for one library.
# All five object rules compile every source of the library in one compiler invocation, with no
# intermediate .o files; the libraries are small enough that incremental compilation buys nothing.
# Comments must stay outside the define: a # line inside would become part of the expansion.
define define_lib_rules
$$(NATIVE_$(1)_LIB): $$(LIB_SRCS_$(1)) $$(LIB_HDRS_$(1)) $$(COMMON_HDRS) | $$(BUILD_DIR)
ifeq ($$(UNAME_S),Linux)
	$$(CC) $$(SHARED_CFLAGS) -shared -o $$@ $$(LIB_SRCS_$(1)) $$(SHARED_LDFLAGS) $$(LDLIBS)
else
	@echo "native shared library build requires Linux (host is $$(UNAME_S))" >&2
	@exit 1
endif

$$(DIST_glibc-amd64_$(1)_LIB): $$(LIB_SRCS_$(1)) $$(LIB_HDRS_$(1)) $$(COMMON_HDRS) | $$(DIST_DIR)
	$$(GLIBC_AMD64_CC) $$(SHARED_CFLAGS) -shared -o $$@ $$(LIB_SRCS_$(1)) $$(SHARED_LDFLAGS) $$(LDLIBS)

$$(DIST_glibc-arm64_$(1)_LIB): $$(LIB_SRCS_$(1)) $$(LIB_HDRS_$(1)) $$(COMMON_HDRS) | $$(DIST_DIR)
	$$(GLIBC_ARM64_CC) $$(SHARED_CFLAGS) -shared -o $$@ $$(LIB_SRCS_$(1)) $$(SHARED_LDFLAGS) $$(LDLIBS)

$$(DIST_musl-amd64_$(1)_LIB): $$(LIB_SRCS_$(1)) $$(LIB_HDRS_$(1)) $$(COMMON_HDRS) | $$(DIST_DIR)
	$$(MUSL_AMD64_CC) $$(SHARED_CFLAGS) -shared -o $$@ $$(LIB_SRCS_$(1)) $$(SHARED_LDFLAGS) $$(LDLIBS)

$$(DIST_musl-arm64_$(1)_LIB): $$(LIB_SRCS_$(1)) $$(LIB_HDRS_$(1)) $$(COMMON_HDRS) | $$(DIST_DIR)
	$$(MUSL_ARM64_CC) $$(SHARED_CFLAGS) -shared -o $$@ $$(LIB_SRCS_$(1)) $$(SHARED_LDFLAGS) $$(LDLIBS)

native-$(1): $$(NATIVE_$(1)_LIB)
cross-glibc-amd64-$(1): $$(DIST_glibc-amd64_$(1)_LIB)
cross-glibc-arm64-$(1): $$(DIST_glibc-arm64_$(1)_LIB)
cross-musl-amd64-$(1): $$(DIST_musl-amd64_$(1)_LIB)
cross-musl-arm64-$(1): $$(DIST_musl-arm64_$(1)_LIB)
endef

$(foreach lib,$(LIB_NAMES),$(eval $(call define_lib_rules,$(lib))))

# Removes build/, build-coverage/ and dist/. The ci-local and fuzz directories have their own
# clean targets (ci-local-clean, fuzz-clean).
clean:
	rm -rf $(BUILD_DIR) $(BUILD_DIR)-coverage $(DIST_DIR)

# ---- libFuzzer harnesses ---------------------------------------------------
# One libFuzzer binary per rule-file parser (test/fuzz/fuzz_<lib>_config.c), built with
# ASan so that out-of-bounds reads and writes in the parsers abort the run.
# Requires clang with libFuzzer (-fsanitize=fuzzer); GCC cannot build these.
# Build:  make fuzz
# Run:    ./build-fuzz/fuzz_<name> -runs=60 -max_len=512 [corpus_dir]
# Corpus: optional; seed inputs in a directory passed as corpus_dir make libFuzzer reach deep
#         parser states sooner than random bytes do.

FUZZ_CC        ?= clang
FUZZ_BUILD_DIR  := build-fuzz
FUZZ_CFLAGS     := $(CPPFLAGS) -std=c99 -Wall -Wextra -O1 -g \
                   -fsanitize=fuzzer,address -fno-omit-frame-pointer
FUZZ_HARNESSES  := fuzz_io_config fuzz_net_config fuzz_dns_config \
                   fuzz_time_config fuzz_memory_config fuzz_process_config
FUZZ_BINS       := $(patsubst %,$(FUZZ_BUILD_DIR)/%,$(FUZZ_HARNESSES))

fuzz: $(FUZZ_BINS)
	@echo "Fuzz harnesses built in $(FUZZ_BUILD_DIR)/."
	@echo "Run one with: ./$(FUZZ_BUILD_DIR)/fuzz_io_config -runs=60 -max_len=512"

$(FUZZ_BUILD_DIR):
	@mkdir -p $@

$(FUZZ_BUILD_DIR)/fuzz_%: test/fuzz/fuzz_%.c | $(FUZZ_BUILD_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $<

fuzz-clean:
	rm -rf $(FUZZ_BUILD_DIR)

# Runs every fenced ```sh verified``` (or bash/shell) block in docs/*.md and fails if any block
# fails; see scripts/run_verified_examples.sh.
verify-docs:
	@bash scripts/run_verified_examples.sh
