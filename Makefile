UNAME_S := $(shell uname -s)
HOST_ARCH := $(shell uname -m)

CC ?= cc
GLIBC_AMD64_CC ?= x86_64-linux-gnu-gcc
GLIBC_ARM64_CC ?= aarch64-linux-gnu-gcc
MUSL_AMD64_CC ?= musl-gcc
MUSL_ARM64_CC ?= aarch64-linux-musl-gcc

CPPFLAGS ?= -D_GNU_SOURCE -Isrc
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic -Os
LDFLAGS ?=
LDLIBS ?= -ldl

SHARED_CFLAGS := $(CPPFLAGS) $(CFLAGS) -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -fomit-frame-pointer -fno-ident -fno-stack-protector
SHARED_LDFLAGS := $(LDFLAGS) -Wl,--gc-sections -Wl,--build-id=none -Wl,--strip-all -Wl,-z,max-page-size=4096 -Wl,-z,common-page-size=4096

BUILD_DIR := build
DIST_DIR := dist
SRC_DIR := src
TEST_DIR := test
TEST_SUPPORT_HDRS := $(TEST_DIR)/test_support.h $(TEST_DIR)/test_chaos_io_harness.h

LIB_SRCS := \
	$(SRC_DIR)/chaos_io.c \
	$(SRC_DIR)/chaos_io_open.c \
	$(SRC_DIR)/chaos_io_rw.c \
	$(SRC_DIR)/chaos_io_sync.c \
	$(SRC_DIR)/chaos_io_actions.c \
	$(SRC_DIR)/chaos_io_config.c \
	$(SRC_DIR)/chaos_io_fdcache.c

LIB_HDRS := \
	$(SRC_DIR)/chaos_io_actions.h \
	$(SRC_DIR)/chaos_io_config.h \
	$(SRC_DIR)/chaos_io_fdcache.h \
	$(SRC_DIR)/chaos_io_internal.h \
	$(SRC_DIR)/chaos_io_wrappers.h

NATIVE_LIB := $(BUILD_DIR)/libchaos-io.so
CONFIG_TEST := $(BUILD_DIR)/test_config_parse
ACTIONS_TEST := $(BUILD_DIR)/test_actions
FDCACHE_TEST := $(BUILD_DIR)/test_fdcache
CHAOS_IO_TEST := $(BUILD_DIR)/test_chaos_io
UNIT_TESTS := $(CONFIG_TEST) $(ACTIONS_TEST) $(FDCACHE_TEST) $(CHAOS_IO_TEST)

GLIBC_AMD64_DIST := $(DIST_DIR)/libchaos-io-glibc-amd64.so
GLIBC_ARM64_DIST := $(DIST_DIR)/libchaos-io-glibc-arm64.so
MUSL_AMD64_DIST := $(DIST_DIR)/libchaos-io-musl-amd64.so
MUSL_ARM64_DIST := $(DIST_DIR)/libchaos-io-musl-arm64.so

.PHONY: all check clean coverage native test unit cross-glibc-amd64 cross-glibc-arm64 cross-musl-amd64 cross-musl-arm64 docker-build-all

all: unit
ifeq ($(UNAME_S),Linux)
all: native
endif

native: $(NATIVE_LIB)

unit: $(UNIT_TESTS)
	./$(CONFIG_TEST)
	./$(ACTIONS_TEST)
	./$(FDCACHE_TEST)
	./$(CHAOS_IO_TEST)

coverage:
	BUILD_DIR=$(BUILD_DIR)-coverage CC="$(CC)" CPPFLAGS='$(CPPFLAGS)' CFLAGS='$(CFLAGS)' ./$(TEST_DIR)/check_coverage.sh

check: coverage test

test: unit
ifeq ($(UNAME_S),Linux)
test: native
endif
		./$(TEST_DIR)/test_integration.sh
		./$(TEST_DIR)/test_glibc.sh
		./$(TEST_DIR)/test_alpine.sh

cross-glibc-amd64: $(GLIBC_AMD64_DIST)

cross-glibc-arm64: $(GLIBC_ARM64_DIST)

cross-musl-amd64: $(MUSL_AMD64_DIST)

cross-musl-arm64: $(MUSL_ARM64_DIST)

docker-build-all: | $(BUILD_DIR) $(DIST_DIR)
	docker buildx build --platform linux/amd64 --build-arg BASE_IMAGE=gcc:bookworm --build-arg MAKE_TARGET=cross-glibc-amd64 --output type=local,dest=$(BUILD_DIR)/docker-glibc-amd64 -f Dockerfile.build .
	cp $(BUILD_DIR)/docker-glibc-amd64/libchaos-io-glibc-amd64.so $(DIST_DIR)/
	docker buildx build --platform linux/arm64 --build-arg BASE_IMAGE=gcc:bookworm --build-arg MAKE_TARGET=cross-glibc-arm64 --output type=local,dest=$(BUILD_DIR)/docker-glibc-arm64 -f Dockerfile.build .
	cp $(BUILD_DIR)/docker-glibc-arm64/libchaos-io-glibc-arm64.so $(DIST_DIR)/
	docker buildx build --platform linux/amd64 --build-arg BASE_IMAGE=alpine:3.20 --build-arg MAKE_TARGET=cross-musl-amd64 --output type=local,dest=$(BUILD_DIR)/docker-musl-amd64 -f Dockerfile.build .
	cp $(BUILD_DIR)/docker-musl-amd64/libchaos-io-musl-amd64.so $(DIST_DIR)/
	docker buildx build --platform linux/arm64 --build-arg BASE_IMAGE=alpine:3.20 --build-arg MAKE_TARGET=cross-musl-arm64 --output type=local,dest=$(BUILD_DIR)/docker-musl-arm64 -f Dockerfile.build .
	cp $(BUILD_DIR)/docker-musl-arm64/libchaos-io-musl-arm64.so $(DIST_DIR)/

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

$(BUILD_DIR)/test_%: $(TEST_DIR)/test_%.c $(LIB_SRCS) $(LIB_HDRS) $(TEST_SUPPORT_HDRS) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

$(NATIVE_LIB): $(LIB_SRCS) $(LIB_HDRS) | $(BUILD_DIR)
ifeq ($(UNAME_S),Linux)
	$(CC) $(SHARED_CFLAGS) -shared -o $@ $(LIB_SRCS) $(SHARED_LDFLAGS) $(LDLIBS)
else
	@echo "native shared library build requires Linux (host is $(UNAME_S))" >&2
	@exit 1
endif

$(GLIBC_AMD64_DIST): $(LIB_SRCS) $(LIB_HDRS) | $(DIST_DIR)
	$(GLIBC_AMD64_CC) $(SHARED_CFLAGS) -shared -o $@ $(LIB_SRCS) $(SHARED_LDFLAGS) $(LDLIBS)

$(GLIBC_ARM64_DIST): $(LIB_SRCS) $(LIB_HDRS) | $(DIST_DIR)
	$(GLIBC_ARM64_CC) $(SHARED_CFLAGS) -shared -o $@ $(LIB_SRCS) $(SHARED_LDFLAGS) $(LDLIBS)

$(MUSL_AMD64_DIST): $(LIB_SRCS) $(LIB_HDRS) | $(DIST_DIR)
	$(MUSL_AMD64_CC) $(SHARED_CFLAGS) -shared -o $@ $(LIB_SRCS) $(SHARED_LDFLAGS) $(LDLIBS)

$(MUSL_ARM64_DIST): $(LIB_SRCS) $(LIB_HDRS) | $(DIST_DIR)
	$(MUSL_ARM64_CC) $(SHARED_CFLAGS) -shared -o $@ $(LIB_SRCS) $(SHARED_LDFLAGS) $(LDLIBS)

clean:
	rm -rf $(BUILD_DIR) $(BUILD_DIR)-coverage $(DIST_DIR)
