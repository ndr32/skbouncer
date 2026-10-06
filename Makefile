# skbouncer build
#
# src/bpf/vmlinux.h is committed and is not regenerated here. Fragmentation
# results depend on the kernel, so the BTF snapshot stays pinned to the
# kernel recorded in CLAUDE.md.

CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := x86

BUILD   := build
BIN     := skbouncer

BPF_SRC  := src/bpf/skbouncer.bpf.c
BPF_OBJ  := $(BUILD)/skbouncer.bpf.o
SKEL     := $(BUILD)/skbouncer.skel.h

USER_SRCS := $(wildcard src/user/*.c)
USER_OBJS := $(patsubst src/user/%.c,$(BUILD)/%.o,$(USER_SRCS))

INCLUDES := -Iinclude -Isrc/user -I$(BUILD)

# Recorded with every result set, so it names the exact commit.
VERSION := $(shell git describe --always --dirty 2>/dev/null || echo unknown)

# -MMD -MP: each object also depends on the headers it includes.
CFLAGS  := -g -O2 -Wall -Wextra -Wno-unused-parameter -MMD -MP
LDLIBS  := -lbpf -lelf -lz -lcurl -ljansson

# vmlinux.h emits bare forward declarations for anonymous types.
# -Wno-missing-declarations keeps them from burying real warnings.
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH) -g -O2 -Wall \
              -Wno-missing-declarations \
              -Iinclude -Isrc/bpf

all: $(BIN)

$(BUILD):
	@mkdir -p $(BUILD)

$(BPF_OBJ): $(BPF_SRC) src/bpf/vmlinux.h include/skbouncer.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Checked on every build and rewritten only when the version changes. A new
# commit rebuilds main.o, and an unchanged tree rebuilds nothing.
$(BUILD)/version.h: FORCE | $(BUILD)
	@v='#define SKB_VERSION "$(VERSION)"'; \
	[ "$$(cat $@ 2>/dev/null)" = "$$v" ] || echo "$$v" >$@

$(BUILD)/main.o: $(BUILD)/version.h

$(BUILD)/%.o: src/user/%.c $(SKEL) | $(BUILD)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BIN): $(USER_OBJS)
	$(CLANG) $(CFLAGS) $^ $(LDLIBS) -o $@

clean:
	rm -rf $(BUILD) $(BIN)

-include $(USER_OBJS:.o=.d)

.PHONY: all clean FORCE
FORCE:
.DELETE_ON_ERROR:
