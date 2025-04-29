# Makefile for building eBPF program for multiple architectures

# Default architecture is x86_64
ARCH ?= x86_64

# Compiler settings
CLANG = clang
CFLAGS = -O2 -g -Wall -D__TARGET_ARCH_x86_64 -I.

# Define architecture-specific flags
ifeq ($(ARCH),x86_64)
    TARGET_ARCH = x86_64
    CFLAGS += -target bpf -D__TARGET_ARCH_x86_64
    OUT_FILE = xdp_ssh_filterx86.bpf.o
else ifeq ($(ARCH),arm64)
    TARGET_ARCH = arm64
    CFLAGS += -target bpf -D__TARGET_ARCH_arm64
    OUT_FILE = xdp_ssh_filterarm64.bpf.o
else
    $(error Unsupported architecture $(ARCH))
endif

# Source files
SRC = ssh_defense.bpf.c

# Default target
all: $(OUT_FILE)

# Rule to compile for the selected architecture
$(OUT_FILE): $(SRC)
	$(CLANG) $(CFLAGS) -c $(SRC) -o $(OUT_FILE)

# Clean up build files
clean:
	rm -f $(OUT_FILE)

.PHONY: all clean
