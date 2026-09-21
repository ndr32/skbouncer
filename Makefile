# skbouncer - build
#
# src/bpf/vmlinux.h is committed and is NOT regenerated here. The
# fragmentation results are kernel-sensitive, so the BTF snapshot stays
# pinned to the kernel recorded in CLAUDE.md.

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

# jansson backs the JSON policy parser (M5). The build stays green without
# it so earlier milestones are not blocked; policy.c compiles to a stub.
JANSSON_CFLAGS := $(shell pkg-config --cflags jansson 2>/dev/null)
JANSSON_LIBS   := $(shell pkg-config --libs jansson 2>/dev/null)
ifeq ($(strip $(JANSSON_LIBS)),)
$(warning jansson not found: policy support disabled.)
$(warning   fix with: sudo apt install libjansson-dev)
else
INCLUDES += $(JANSSON_CFLAGS) -DHAVE_JANSSON
endif

CFLAGS  := -g -O2 -Wall -Wextra -Wno-unused-parameter
LDLIBS  := -lbpf -lelf -lz $(JANSSON_LIBS)

# -Wno-missing-declarations: vmlinux.h emits bare forward declarations for
# anonymous types, which would otherwise bury real warnings.
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

$(BUILD)/%.o: src/user/%.c $(SKEL) | $(BUILD)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BIN): $(USER_OBJS)
	$(CLANG) $(CFLAGS) $^ $(LDLIBS) -o $@

clean:
	rm -rf $(BUILD) $(BIN)

# Loads the program and shows it, then unloads. Needs root.
verify: $(BIN)
	@echo "run in one window:   sudo ./$(BIN)"
	@echo "then in another:     sudo bpftool prog show name skb_egress"

.PHONY: all clean verify
.DELETE_ON_ERROR:
