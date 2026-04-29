UNAME_S := $(shell uname -s)
HOST_ARCH := $(shell uname -m)

CC ?= cc
GLIBC_AMD64_CC ?= x86_64-linux-gnu-gcc
GLIBC_ARM64_CC ?= aarch64-linux-gnu-gcc
MUSL_AMD64_CC ?= musl-gcc
MUSL_ARM64_CC ?= aarch64-linux-musl-gcc

CPPFLAGS ?= -D_GNU_SOURCE -Isrc -Isrc/common -Isrc/core -Isrc/config -Isrc/effects -Isrc/wrappers -Isrc/net -Isrc/dns -Isrc/time -Isrc/process -Isrc/memory
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic -Os
LDFLAGS ?=
LDLIBS ?= -ldl

SHARED_CFLAGS := $(CPPFLAGS) $(CFLAGS) -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -fomit-frame-pointer -fno-ident -fno-stack-protector
SHARED_LDFLAGS := $(LDFLAGS) -Wl,--gc-sections -Wl,--build-id=none -Wl,--strip-all -Wl,-z,max-page-size=4096 -Wl,-z,common-page-size=4096

BUILD_DIR := build
DIST_DIR := dist
SRC_DIR := src
TEST_DIR := test
SRC_COMMON_DIR := $(SRC_DIR)/common
SRC_CORE_DIR := $(SRC_DIR)/core
SRC_CONFIG_DIR := $(SRC_DIR)/config
SRC_EFFECTS_DIR := $(SRC_DIR)/effects
SRC_WRAPPERS_DIR := $(SRC_DIR)/wrappers
SRC_NET_DIR := $(SRC_DIR)/net
SRC_DNS_DIR := $(SRC_DIR)/dns
SRC_TIME_DIR := $(SRC_DIR)/time
SRC_PROCESS_DIR := $(SRC_DIR)/process
SRC_MEMORY_DIR := $(SRC_DIR)/memory
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

LIB_NAMES := io net dns time process memory
DIST_VARIANTS := glibc-amd64 glibc-arm64 musl-amd64 musl-arm64

LIB_SRCS_io := \
	$(SRC_CORE_DIR)/chaos_io.c \
	$(SRC_WRAPPERS_DIR)/chaos_io_open.c \
	$(SRC_WRAPPERS_DIR)/chaos_io_rw.c \
	$(SRC_WRAPPERS_DIR)/chaos_io_fsops.c \
	$(SRC_WRAPPERS_DIR)/chaos_io_sync.c \
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
	$(SRC_DNS_DIR)/chaos_dns_lookup.c

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
	$(SRC_DNS_DIR)/chaos_dns_actions.h
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
UNIT_TESTS := $(CONFIG_TEST) $(ACTIONS_TEST) $(FDCACHE_TEST) $(CHAOS_IO_TEST) \
	$(NET_ACTIONS_TEST) $(NET_ENDPOINT_TEST) $(NET_CONFIG_TEST) $(NET_RUNTIME_TEST) $(CHAOS_NET_TEST) \
	$(DNS_ACTIONS_TEST) $(DNS_CONFIG_TEST) $(DNS_RUNTIME_TEST) $(CHAOS_DNS_TEST) \
	$(TIME_ACTIONS_TEST) $(TIME_CONFIG_TEST) $(TIME_RUNTIME_TEST) $(CHAOS_TIME_TEST) \
	$(MEMORY_ACTIONS_TEST) $(MEMORY_CONFIG_TEST) $(MEMORY_RUNTIME_TEST) $(CHAOS_MEMORY_TEST) \
	$(PROCESS_ACTIONS_TEST) $(PROCESS_CONFIG_TEST) $(PROCESS_RUNTIME_TEST) $(CHAOS_PROCESS_TEST)
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
	$(TEST_RUNTIME_DIR)/test_process_alpine.sh
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
	cross-glibc-amd64 cross-glibc-arm64 cross-musl-amd64 cross-musl-arm64 \
	$(foreach lib,$(LIB_NAMES),native-$(lib)) \
	$(foreach lib,$(LIB_NAMES),cross-glibc-amd64-$(lib)) \
	$(foreach lib,$(LIB_NAMES),cross-glibc-arm64-$(lib)) \
	$(foreach lib,$(LIB_NAMES),cross-musl-amd64-$(lib)) \
	$(foreach lib,$(LIB_NAMES),cross-musl-arm64-$(lib))

all: unit
ifeq ($(UNAME_S),Linux)
all: native
endif

native: $(NATIVE_LIBS)

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

coverage:
	BUILD_DIR=$(BUILD_DIR)-coverage CC="$(CC)" CPPFLAGS='$(CPPFLAGS)' CFLAGS='$(CFLAGS)' ./$(TEST_RUNTIME_DIR)/check_coverage.sh

fmt:
	sh ./$(TEST_RUNTIME_DIR)/check_format.sh --write

fmt-check:
	sh ./$(TEST_RUNTIME_DIR)/check_format.sh --check

check: fmt-check coverage test

qa: check

test: unit
ifeq ($(UNAME_S),Linux)
test: native
endif
	@for script in $(HOST_RUNTIME_TESTS); do \
		sh $$script; \
	done

test-matrix:
	@for platform in linux/amd64 linux/arm64; do \
		for script in $(MATRIX_RUNTIME_TESTS); do \
			sh $$script $$platform; \
		done; \
	done

cross-glibc-amd64: $(GLIBC_AMD64_DISTS)

cross-glibc-arm64: $(GLIBC_ARM64_DISTS)

cross-musl-amd64: $(MUSL_AMD64_DISTS)

cross-musl-arm64: $(MUSL_ARM64_DISTS)

docker-build-all: | $(BUILD_DIR) $(DIST_DIR)
	docker buildx build --platform linux/amd64 --build-arg BASE_IMAGE=gcc:bookworm --build-arg MAKE_TARGET=cross-glibc-amd64 --output type=local,dest=$(BUILD_DIR)/docker-glibc-amd64 -f $(DOCKER_DIR)/Dockerfile.build .
	cp $(BUILD_DIR)/docker-glibc-amd64/*.so $(DIST_DIR)/
	docker buildx build --platform linux/arm64 --build-arg BASE_IMAGE=gcc:bookworm --build-arg MAKE_TARGET=cross-glibc-arm64 --output type=local,dest=$(BUILD_DIR)/docker-glibc-arm64 -f $(DOCKER_DIR)/Dockerfile.build .
	cp $(BUILD_DIR)/docker-glibc-arm64/*.so $(DIST_DIR)/
	docker buildx build --platform linux/amd64 --build-arg BASE_IMAGE=alpine:3.20 --build-arg MAKE_TARGET=cross-musl-amd64 --output type=local,dest=$(BUILD_DIR)/docker-musl-amd64 -f $(DOCKER_DIR)/Dockerfile.build .
	cp $(BUILD_DIR)/docker-musl-amd64/*.so $(DIST_DIR)/
	docker buildx build --platform linux/arm64 --build-arg BASE_IMAGE=alpine:3.20 --build-arg MAKE_TARGET=cross-musl-arm64 --output type=local,dest=$(BUILD_DIR)/docker-musl-arm64 -f $(DOCKER_DIR)/Dockerfile.build .
	cp $(BUILD_DIR)/docker-musl-arm64/*.so $(DIST_DIR)/

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

$(BUILD_DIR)/test_%: $(TEST_UNIT_DIR)/test_%.c $(LIB_SRCS_io) $(LIB_HDRS_io) $(LIB_SRCS_net) $(LIB_HDRS_net) $(LIB_SRCS_dns) $(LIB_HDRS_dns) $(LIB_SRCS_time) $(LIB_HDRS_time) $(LIB_SRCS_process) $(LIB_HDRS_process) $(LIB_SRCS_memory) $(LIB_HDRS_memory) $(TEST_SUPPORT_HDRS) | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

define define_lib_rules
$$(NATIVE_$(1)_LIB): $$(LIB_SRCS_$(1)) $$(LIB_HDRS_$(1)) | $$(BUILD_DIR)
ifeq ($$(UNAME_S),Linux)
	$$(CC) $$(SHARED_CFLAGS) -shared -o $$@ $$(LIB_SRCS_$(1)) $$(SHARED_LDFLAGS) $$(LDLIBS)
else
	@echo "native shared library build requires Linux (host is $$(UNAME_S))" >&2
	@exit 1
endif

$$(DIST_glibc-amd64_$(1)_LIB): $$(LIB_SRCS_$(1)) $$(LIB_HDRS_$(1)) | $$(DIST_DIR)
	$$(GLIBC_AMD64_CC) $$(SHARED_CFLAGS) -shared -o $$@ $$(LIB_SRCS_$(1)) $$(SHARED_LDFLAGS) $$(LDLIBS)

$$(DIST_glibc-arm64_$(1)_LIB): $$(LIB_SRCS_$(1)) $$(LIB_HDRS_$(1)) | $$(DIST_DIR)
	$$(GLIBC_ARM64_CC) $$(SHARED_CFLAGS) -shared -o $$@ $$(LIB_SRCS_$(1)) $$(SHARED_LDFLAGS) $$(LDLIBS)

$$(DIST_musl-amd64_$(1)_LIB): $$(LIB_SRCS_$(1)) $$(LIB_HDRS_$(1)) | $$(DIST_DIR)
	$$(MUSL_AMD64_CC) $$(SHARED_CFLAGS) -shared -o $$@ $$(LIB_SRCS_$(1)) $$(SHARED_LDFLAGS) $$(LDLIBS)

$$(DIST_musl-arm64_$(1)_LIB): $$(LIB_SRCS_$(1)) $$(LIB_HDRS_$(1)) | $$(DIST_DIR)
	$$(MUSL_ARM64_CC) $$(SHARED_CFLAGS) -shared -o $$@ $$(LIB_SRCS_$(1)) $$(SHARED_LDFLAGS) $$(LDLIBS)

native-$(1): $$(NATIVE_$(1)_LIB)
cross-glibc-amd64-$(1): $$(DIST_glibc-amd64_$(1)_LIB)
cross-glibc-arm64-$(1): $$(DIST_glibc-arm64_$(1)_LIB)
cross-musl-amd64-$(1): $$(DIST_musl-amd64_$(1)_LIB)
cross-musl-arm64-$(1): $$(DIST_musl-arm64_$(1)_LIB)
endef

$(foreach lib,$(LIB_NAMES),$(eval $(call define_lib_rules,$(lib))))

clean:
	rm -rf $(BUILD_DIR) $(BUILD_DIR)-coverage $(DIST_DIR)
